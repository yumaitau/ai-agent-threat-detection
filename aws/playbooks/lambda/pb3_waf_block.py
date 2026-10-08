"""PB3: find AI-speed exploitation bursts (A14), enrich the IPs with free threat intel, and block them in a WAF IP set.

Schedule: EventBridge Scheduler every 15 minutes. Block entries expire after BLOCK_HOURS (default 24) and are removed.
Threat intel:
  GreyNoise Community  GET https://api.greynoise.io/v3/community/{ip}  (works without a key; rate limited)
  AbuseIPDB            GET https://api.abuseipdb.com/api/v2/check       (header Key; optional)
  ThreatFox            POST https://threatfox-api.abuse.ch/api/v1/      (header Auth-Key; optional)
Keys are read from one Secrets Manager secret (JSON: {"abuseipdb": "...", "threatfox": "..."}) if THREAT_INTEL_SECRET_ID is set.
"""
import ipaddress
import json
import os
import time
import urllib.parse
import urllib.request

import boto3

from yuma_common import now_iso, table_name

logs = boto3.client("logs")
waf = boto3.client("wafv2")
ddb = boto3.client("dynamodb")
secrets = boto3.client("secretsmanager")

QUERY_FILE = os.path.join(os.path.dirname(__file__), "A14-ai-speed-waf-burst.logsinsights")


def _query_string():
    with open(QUERY_FILE) as f:
        return "\n".join(line for line in f.read().splitlines() if not line.lstrip().startswith("#"))


def run_logs_insights(query, minutes=15):
    end = int(time.time())
    qid = logs.start_query(logGroupNames=[os.environ["WAF_LOG_GROUP"]], startTime=end - minutes * 60,
                           endTime=end, queryString=query)["queryId"]
    for _ in range(60):
        res = logs.get_query_results(queryId=qid)
        if res["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        time.sleep(2)
    if res["status"] != "Complete":
        raise RuntimeError(f"Logs Insights query {qid} ended {res['status']}")
    return [{c["field"]: c["value"] for c in row} for row in res["results"]]


def _http_json(url, headers=None, data=None):
    req = urllib.request.Request(url, headers=headers or {}, data=data, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:  # noqa: S310 (fixed vendor URLs)
            return json.loads(r.read())
    except Exception as exc:  # enrichment is best effort
        return {"error": str(exc)}


def enrich(ip, keys):
    intel = {"greynoise": _http_json(f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ip)}")}
    if keys.get("abuseipdb"):
        intel["abuseipdb"] = _http_json("https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
            {"ipAddress": ip, "maxAgeInDays": 30}), headers={"Key": keys["abuseipdb"], "Accept": "application/json"})
    if keys.get("threatfox"):
        intel["threatfox"] = _http_json("https://threatfox-api.abuse.ch/api/v1/", headers={"Auth-Key": keys["threatfox"]},
                                        data=json.dumps({"query": "search_ioc", "search_term": ip}).encode())
    return intel


def score(row, intel):
    s = 50 if int(row.get("rulesHit", 0) or 0) >= 5 else 30
    gn = intel.get("greynoise", {})
    if gn.get("riot"):
        s -= 40  # known benign business service (RIOT)
    if gn.get("classification") == "malicious":
        s += 30
    abuse = (intel.get("abuseipdb", {}).get("data") or {}).get("abuseConfidenceScore")
    if isinstance(abuse, int):
        s += abuse // 4
    if intel.get("threatfox", {}).get("query_status") == "ok":
        s += 30
    return s


def update_ip_set(add, remove):
    name, scope, set_id = os.environ["IPSET_NAME"], os.environ.get("IPSET_SCOPE", "REGIONAL"), os.environ["IPSET_ID"]
    for _ in range(5):  # optimistic locking: retry on WAFOptimisticLockException
        cur = waf.get_ip_set(Name=name, Scope=scope, Id=set_id)
        addrs = (set(cur["IPSet"]["Addresses"]) | set(add)) - set(remove)
        try:
            waf.update_ip_set(Name=name, Scope=scope, Id=set_id, Addresses=sorted(addrs), LockToken=cur["LockToken"])
            return sorted(addrs)
        except waf.exceptions.WAFOptimisticLockException:
            time.sleep(1)
    raise RuntimeError("Could not update IP set after 5 attempts")


def expired_blocks():
    now = now_iso()
    resp = ddb.query(TableName=table_name(), KeyConditionExpression="pk = :p",
                     FilterExpression="expires_at < :n",
                     ExpressionAttributeValues={":p": {"S": "WAFBLOCK"}, ":n": {"S": now}})
    return [i["sk"]["S"] for i in resp.get("Items", [])]


def handler(event, _ctx):
    allow = [ipaddress.ip_network(c) for c in os.environ.get("ALLOW_CIDRS", "").split(",") if c]
    threshold = int(os.environ.get("BLOCK_SCORE", "60"))
    keys = {}
    if os.environ.get("THREAT_INTEL_SECRET_ID"):
        keys = json.loads(secrets.get_secret_value(SecretId=os.environ["THREAT_INTEL_SECRET_ID"])["SecretString"])
    rows = event.get("rows") or run_logs_insights(_query_string())
    to_block, decisions = [], []
    for row in rows:
        ip = row.get("ip")
        if not ip or any(ipaddress.ip_address(ip) in n for n in allow):
            continue
        intel = enrich(ip, keys)
        sc = score(row, intel)
        decisions.append({"ip": ip, "score": sc, "rulesHit": row.get("rulesHit"), "requests": row.get("requests")})
        if sc >= threshold:
            cidr = f"{ip}/32" if ipaddress.ip_address(ip).version == 4 else f"{ip}/128"
            to_block.append(cidr)
            expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600 * int(os.environ.get("BLOCK_HOURS", "24"))))
            ddb.put_item(TableName=table_name(), Item={
                "pk": {"S": "WAFBLOCK"}, "sk": {"S": cidr}, "score": {"N": str(sc)}, "blocked_at": {"S": now_iso()},
                "expires_at": {"S": expires}, "intel": {"S": json.dumps(intel)[:30000]}})
    expired = expired_blocks()
    if os.environ.get("AUTO_BLOCK", "false").lower() == "true" and (to_block or expired):
        update_ip_set(to_block, expired)
        for cidr in expired:
            ddb.delete_item(TableName=table_name(), Key={"pk": {"S": "WAFBLOCK"}, "sk": {"S": cidr}})
    return {"evaluated": len(decisions), "blocked": to_block if os.environ.get("AUTO_BLOCK") == "true" else [],
            "proposed": to_block, "expired": expired, "decisions": decisions}
