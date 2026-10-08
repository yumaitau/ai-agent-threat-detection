"""PB5: monthly ISM evidence export to S3 (bucket with S3 Object Lock default retention, compliance mode).

Writes evidence/YYYY-MM-DD/ with:
  agent-register.csv   current register with ISM-2135 field gaps and review status
  ism-controls.csv     one row per ISM control (ISM-2133 to 2140, 2156 to 2159): status, metric, evidence, method
  summary.md           plain-English summary for an assessor
  manifest.json        SHA-256 of each file, generation time, account, Region, pack version
Status values: Evidence present / Gap / No data / Attestation required.
The export supports an assessment. It is not a compliance determination.
"""
import csv
import hashlib
import io
import json
import os

import boto3

from yuma_common import from_ddb, now_iso, table_name, today

s3 = boto3.client("s3")
ddb = boto3.client("dynamodb")
bedrock = boto3.client("bedrock")
cloudtrail = boto3.client("cloudtrail")
guardduty = boto3.client("guardduty")

PACK_VERSION = "0.1.0-draft"
_HERE = os.path.dirname(os.path.abspath(__file__))
# Bundled next to the handler by tools/package_lambdas.py; falls back to the repo copy for local tests.
CONTROL_MAP = next(p for p in (os.path.join(_HERE, "ism-control-map.csv"),
                               os.path.join(_HERE, "..", "..", "register", "ism-control-map.csv")) if os.path.exists(p))


def register():
    out, kw = [], {"TableName": table_name(), "FilterExpression": "sk = :c", "ExpressionAttributeValues": {":c": {"S": "CURRENT"}}}
    while True:
        page = ddb.scan(**kw)
        out += [from_ddb(i) for i in page.get("Items", [])]
        if "LastEvaluatedKey" not in page:
            return [r for r in out if r.get("status") != "Retired"]
        kw["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def logging_posture():
    p = {"model_invocation_logging": False, "gateway_data_events": False, "agent_data_events": False,
         "guardrail_data_events": False, "guardduty_ai_protection": False}
    cfg = bedrock.get_model_invocation_logging_configuration().get("loggingConfig") or {}
    p["model_invocation_logging"] = bool(cfg.get("cloudWatchConfig") or cfg.get("s3Config"))
    trail = os.environ.get("TRAIL_NAME")
    if trail:
        sel = cloudtrail.get_event_selectors(TrailName=trail).get("AdvancedEventSelectors") or []
        types = {v for s in sel for f in s["FieldSelectors"] if f["Field"] == "resources.type" for v in f.get("Equals", [])}
        p["gateway_data_events"] = "AWS::BedrockAgentCore::Gateway" in types
        p["agent_data_events"] = "AWS::Bedrock::AgentAlias" in types
        p["guardrail_data_events"] = "AWS::Bedrock::Guardrail" in types
    for det in guardduty.list_detectors().get("DetectorIds", []):
        feats = guardduty.get_detector(DetectorId=det).get("Features") or []
        p["guardduty_ai_protection"] |= any(f["Name"] == "AI_PROTECTION" and f["Status"] == "ENABLED" for f in feats)
    return p


def control_status(reg, posture):
    d = today().isoformat()
    n = len(reg)
    no_owner = sum(1 for r in reg if not (r.get("owner") and r.get("business_purpose")))
    no_ident = sum(1 for r in reg if not r.get("identities"))
    no_tools = sum(1 for r in reg if not (r.get("tools") and r.get("permissions")))
    pending = sum(1 for r in reg if r.get("status") == "PendingReview")
    overdue = sum(1 for r in reg if r.get("status") == "Approved" and (r.get("next_review_due") or "0000") < d)
    never = sum(1 for r in reg if r.get("status") == "Approved" and not r.get("last_review"))
    idents = [i for r in reg for i in (r.get("identities") or [])]
    shared = len(idents) - len(set(idents))
    s = {}
    s["ISM-2133"] = ("No data" if n == 0 else "Gap" if (no_ident or shared) else "Evidence present",
                     f"{no_ident} agents without an identity; {shared} identities shared between agents")
    s["ISM-2134"] = ("No data" if n == 0 else "Gap" if pending else "Evidence present",
                     f"{n} agents in register; {pending} discovered but not yet reviewed")
    s["ISM-2135"] = ("No data" if n == 0 else "Gap" if (no_owner or no_ident or no_tools) else "Evidence present",
                     f"{no_owner} missing owner/purpose; {no_ident} missing identities; {no_tools} missing tools/permissions")
    s["ISM-2136"] = ("Attestation required", "A07 alerts are evidence of monitoring; enforcement is attested")
    s["ISM-2137"] = ("Attestation required", "A05 alerts list Identity Center application grants; who may grant is attested")
    s["ISM-2138"] = ("No data" if n == 0 else "Gap" if (overdue or never) else "Evidence present",
                     f"{overdue} reviews overdue; {never} approved agents never reviewed")
    s["ISM-2139"] = ("Attestation required", "CloudTrail management events cover Identity Center; confirm trail scope")
    s["ISM-2140"] = ("Attestation required", "No AWS setting found to disable device authorisation; attest the control")
    s["ISM-2156"] = ("Attestation required" if n else "No data", "A04 alerts and Access Analyzer unused-permission findings support this")
    s["ISM-2157"] = ("Attestation required", "A08 and A11 monitor tool use; task-scoped authorisation is attested")
    s["ISM-2158"] = ("Evidence present" if posture["guardrail_data_events"] and posture["guardduty_ai_protection"] else "Gap",
                     f"guardrail data events={posture['guardrail_data_events']}; GuardDuty AI Protection={posture['guardduty_ai_protection']}")
    full = posture["model_invocation_logging"] and posture["gateway_data_events"] and posture["agent_data_events"]
    s["ISM-2159"] = ("Evidence present" if full else "Gap",
                     f"model invocation logging={posture['model_invocation_logging']}; gateway data events={posture['gateway_data_events']}; agent data events={posture['agent_data_events']}")
    return s


def handler(event, _ctx):
    reg = register()
    posture = logging_posture()
    status = control_status(reg, posture)
    with open(CONTROL_MAP) as fh:
        controls = list(csv.DictReader(fh))
    files = {}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["agent_id", "agent_name", "platform", "owner", "business_purpose", "identities", "credentials", "tools",
                "permissions", "data_repositories", "status", "decided_by", "last_review", "next_review_due"])
    for r in sorted(reg, key=lambda x: x.get("agent_name") or x["agent_id"]):
        j = lambda k: ";".join(sorted(r.get(k) or []))  # noqa: E731
        w.writerow([r["agent_id"], r.get("agent_name"), r.get("platform"), r.get("owner"), r.get("business_purpose"),
                    j("identities"), j("credentials"), j("tools"), j("permissions"), j("data_repositories"),
                    r.get("status"), r.get("decided_by"), r.get("last_review"), r.get("next_review_due")])
    files["agent-register.csv"] = buf.getvalue()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ControlId", "Status", "Metric", "PackEvidence", "EvidenceMethod", "Control"])
    for c in controls:
        st, metric = status[c["ControlId"]]
        w.writerow([c["ControlId"], st, metric, c["PackEvidence"], c["EvidenceMethod"], c["Control"]])
    files["ism-controls.csv"] = buf.getvalue()
    counts = {}
    for st, _m in status.values():
        counts[st] = counts.get(st, 0) + 1
    lines = [f"# AI agent register and ISM evidence, {today().isoformat()}", "",
             f"Agents in register: {len(reg)}. Control status: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())), "",
             "| Control | Status | Metric |", "|---|---|---|"]
    lines += [f"| {k} | {v[0]} | {v[1]} |" for k, v in sorted(status.items())]
    lines += ["", "This pack supports an assessment. Controls marked 'Attestation required' need a written statement from the control owner."]
    files["summary.md"] = "\n".join(lines) + "\n"
    prefix = f"evidence/{today().isoformat()}/"
    manifest = {"generated_at": now_iso(), "pack_version": PACK_VERSION, "region": os.environ.get("AWS_REGION"),
                "logging_posture": posture, "files": {}}
    for name, body in files.items():
        data = body.encode()
        manifest["files"][name] = hashlib.sha256(data).hexdigest()
        s3.put_object(Bucket=os.environ["EVIDENCE_BUCKET"], Key=prefix + name, Body=data,
                      ChecksumAlgorithm="SHA256")
    s3.put_object(Bucket=os.environ["EVIDENCE_BUCKET"], Key=prefix + "manifest.json",
                  Body=json.dumps(manifest, indent=2).encode(), ChecksumAlgorithm="SHA256")
    return {"prefix": prefix, "status_counts": counts}
