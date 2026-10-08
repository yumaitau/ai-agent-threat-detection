"""PB3: enrich attacking IPs (GreyNoise, AbuseIPDB, ThreatFox) and block them with a Cloud Armor deny rule that expires.

Status: SKELETON - compiles offline; not deployed.
Modes (JSON body {"mode": ...}, sent by Cloud Scheduler):
  "enrich_block" - read new G13 hits from detection_hits, enrich each IP, block the ones that score high enough.
  "cleanup"      - remove PB3 rules whose description says they have expired.

TI APIs:
  GreyNoise Community  GET https://api.greynoise.io/v3/community/{ip}   header "key" (optional)
      fields: noise, riot, classification, name   https://docs.greynoise.io/ (Community API)
  AbuseIPDB            GET https://api.abuseipdb.com/api/v2/check?ipAddress=..&maxAgeInDays=90  header "Key"
      field data.abuseConfidenceScore              https://docs.abuseipdb.com/#check-endpoint
  ThreatFox            POST https://threatfox-api.abuse.ch/api/v1/ {"query":"search_ioc","search_term":ip} header "Auth-Key"
                                                    https://threatfox.abuse.ch/api/
Cloud Armor: compute v1 securityPolicies.addRule / removeRule / get. versionedExpr SRC_IPS_V1, max 10 srcIpRanges per rule.
  https://docs.cloud.google.com/armor/docs/configure-security-policies
Blocking an IP at the WAF for a few hours is low-impact and reversible, so it runs without a human click; every block is
logged, expires, and never touches allowlisted ranges or GreyNoise RIOT (known business services).
"""
import datetime as dt
import ipaddress
import json
import os
import re

import functions_framework
import google.auth
import requests
from google.auth.transport import requests as ga_requests
from google.cloud import bigquery

PROJECT = os.environ["POLICY_PROJECT"]
POLICY = os.environ["SECURITY_POLICY"]
REGISTER_DATASET = os.environ["REGISTER_DATASET"]  # project.dataset
PRIORITY_MIN, PRIORITY_MAX = int(os.environ.get("PRIORITY_MIN", "1000")), int(os.environ.get("PRIORITY_MAX", "1999"))
TTL_HOURS = int(os.environ.get("BLOCK_TTL_HOURS", "24"))
ALLOW = [ipaddress.ip_network(c.strip()) for c in os.environ.get("ALLOWLIST_CIDRS", "").split(",") if c.strip()]
ABUSE_MIN = int(os.environ.get("ABUSEIPDB_MIN_SCORE", "75"))
TAG = "yuma-gai-pb3"
COMPUTE = f"https://compute.googleapis.com/compute/v1/projects/{PROJECT}/global/securityPolicies/{POLICY}"


def _greynoise(ip):
    h = {"key": os.environ["GREYNOISE_KEY"]} if os.environ.get("GREYNOISE_KEY") else {}
    r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers=h, timeout=10)
    return r.json() if r.status_code in (200, 404) else {"error": r.status_code}


def _abuseipdb(ip):
    r = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                     headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "application/json"}, timeout=10)
    return r.json().get("data", {}) if r.ok else {"error": r.status_code}


def _threatfox(ip):
    r = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": ip},
                      headers={"Auth-Key": os.environ["THREATFOX_KEY"]}, timeout=10)
    return r.json() if r.ok else {"error": r.status_code}


def verdict(ip, gn, ab, tf):
    addr = ipaddress.ip_address(ip)
    if addr.is_private or any(addr in n for n in ALLOW):
        return "allowlisted"
    if gn.get("riot") or gn.get("classification") == "benign":
        return "benign"
    if (ab.get("abuseConfidenceScore") or 0) >= ABUSE_MIN or tf.get("query_status") == "ok" \
            or gn.get("classification") == "malicious":
        return "block"
    return "watch"  # G13 behaviour alone is not enough to block; analyst decides


def _session():
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    return ga_requests.AuthorizedSession(creds)


def _free_priority(s):
    used = {r["priority"] for r in s.get(COMPUTE, timeout=20).json().get("rules", [])}
    for p in range(PRIORITY_MIN, PRIORITY_MAX + 1):
        if p not in used:
            return p
    raise RuntimeError("PB3 priority band full; run cleanup")


def block(ips):
    s = _session()
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=TTL_HOURS)).strftime("%Y-%m-%dT%H:%MZ")
    out = []
    for i in range(0, len(ips), 10):  # Cloud Armor: max 10 ranges per SRC_IPS_V1 rule
        chunk = [f"{ip}/32" if ":" not in ip else f"{ip}/128" for ip in ips[i:i + 10]]
        prio = _free_priority(s)
        rule = {"priority": prio, "action": "deny(403)", "description": f"{TAG} expires={expires}",
                "match": {"versionedExpr": "SRC_IPS_V1", "config": {"srcIpRanges": chunk}}}
        r = s.post(f"{COMPUTE}/addRule", json=rule, timeout=30)
        out.append({"priority": prio, "ips": chunk, "status": r.status_code})
    return out


def cleanup():
    s = _session()
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    removed = []
    for r in s.get(COMPUTE, timeout=20).json().get("rules", []):
        m = re.search(TAG + r" expires=(\S+)", r.get("description", ""))
        if m and m.group(1) <= now:
            s.post(f"{COMPUTE}/removeRule", params={"priority": r["priority"]}, timeout=30)
            removed.append(r["priority"])
    return removed


@functions_framework.http
def handler(request):
    mode = (request.get_json(silent=True) or {}).get("mode", "enrich_block")
    if mode == "cleanup":
        return {"removed": cleanup()}
    bq = bigquery.Client()
    rows = bq.query(
        f"SELECT DISTINCT entity FROM `{REGISTER_DATASET}.detection_hits` "
        "WHERE detection_id = 'G13' AND hit_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 15 MINUTE) AND case_ref IS NULL"
    ).result()
    decisions, to_block = [], []
    for row in rows:
        ip = row.entity
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        gn, ab, tf = _greynoise(ip), _abuseipdb(ip), _threatfox(ip)
        v = verdict(ip, gn, ab, tf)
        decisions.append({"ip": ip, "verdict": v, "abuse": ab.get("abuseConfidenceScore"),
                          "greynoise": gn.get("classification"), "threatfox": tf.get("query_status")})
        if v == "block":
            to_block.append(ip)
    blocks = block(to_block) if to_block else []
    print(json.dumps({"pb3": decisions, "blocks": blocks}))  # structured log = evidence trail
    return {"decisions": decisions, "blocks": blocks}
