"""PB4: daily AI agent inventory and register sync.

Lists what exists in AWS (Bedrock Agents, AgentCore runtimes, gateways, workload identities, credential providers,
AWS Agent Registry records, IAM roles trusted by bedrock/bedrock-agentcore), then:
  1. writes inventory.jsonl and register.jsonl snapshots to S3 for Athena (register/athena-register.sql)
  2. adds anything unregistered to the register as PendingReview (RegisterSnapshot history record)
  3. refreshes the CloudWatch Logs lookup table used by A02 (UpdateLookupTable)
  4. publishes CloudWatch metrics for the dashboard (namespace Yuma/AIA)
Run in each account and Region that hosts agents (or from a delegated account with an assumed role per account).
The Lambda needs a boto3 recent enough to include bedrock-agentcore-control and agent-registry-control: bundle it.
"""
import csv
import io
import json
import os

import boto3

from yuma_common import from_ddb, put_history, table_name, to_ddb, today, trusts_ai_service

s3 = boto3.client("s3")
ddb = boto3.client("dynamodb")
cw = boto3.client("cloudwatch")
logs = boto3.client("logs")
iam = boto3.client("iam")
REGION = os.environ.get("AWS_REGION", "ap-southeast-2")


def _pages(client, op, key, **kw):
    """Generic nextToken pagination (these APIs use nextToken / maxResults)."""
    while True:
        resp = getattr(client, op)(**kw)
        yield from resp.get(key, [])
        tok = resp.get("nextToken")
        if not tok:
            return
        kw["nextToken"] = tok


def inventory(account_id):
    items = []
    ba = boto3.client("bedrock-agent")
    for s in _pages(ba, "list_agents", "agentSummaries"):
        a = ba.get_agent(agentId=s["agentId"])["agent"]
        items.append({"resource_arn": a["agentArn"], "platform": "BedrockAgent", "name": a["agentName"],
                      "role_arn": a.get("agentResourceRoleArn"), "details": {"model": a.get("foundationModel"),
                      "guardrail": a.get("guardrailConfiguration")}})
    ac = boto3.client("bedrock-agentcore-control")
    for r in _pages(ac, "list_agent_runtimes", "agentRuntimes"):
        d = ac.get_agent_runtime(agentRuntimeId=r["agentRuntimeId"])
        items.append({"resource_arn": d["agentRuntimeArn"], "platform": "AgentCoreRuntime", "name": d["agentRuntimeName"],
                      "role_arn": d.get("roleArn"), "details": {"workloadIdentity": (d.get("workloadIdentityDetails") or {}).get("workloadIdentityArn"),
                      "authorizer": list((d.get("authorizerConfiguration") or {}).keys())}})
    for g in _pages(ac, "list_gateways", "items"):
        d = ac.get_gateway(gatewayIdentifier=g["gatewayId"])
        items.append({"resource_arn": d["gatewayArn"], "platform": "AgentCoreGateway", "name": d["name"],
                      "role_arn": d.get("roleArn"), "details": {"authorizerType": d.get("authorizerType"),
                      "protocolType": d.get("protocolType"), "webAclArn": d.get("webAclArn")}})
    for w in _pages(ac, "list_workload_identities", "workloadIdentities"):
        items.append({"resource_arn": w["workloadIdentityArn"], "platform": "AgentCoreWorkloadIdentity", "name": w["name"]})
    for c in _pages(ac, "list_oauth2_credential_providers", "credentialProviders"):
        items.append({"resource_arn": c["credentialProviderArn"], "platform": "Credential", "name": c["name"],
                      "details": {"vendor": c.get("credentialProviderVendor"), "kind": "OAuth2"}})
    for c in _pages(ac, "list_api_key_credential_providers", "credentialProviders"):
        items.append({"resource_arn": c["credentialProviderArn"], "platform": "Credential", "name": c["name"],
                      "details": {"kind": "ApiKey"}})
    if os.environ.get("INCLUDE_AGENT_REGISTRY", "true") == "true":
        ar = boto3.client("agent-registry-control")
        for reg in _pages(ar, "list_registries", "registries"):
            for rec in _pages(ar, "list_registry_records", "registryRecords", registryId=reg["registryId"]):
                items.append({"resource_arn": rec["recordArn"], "platform": "AgentRegistryRecord", "name": rec["name"],
                              "details": {"recordType": rec.get("recordType"), "status": rec.get("status")}})
    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            if trusts_ai_service(role["AssumeRolePolicyDocument"]):
                items.append({"resource_arn": role["Arn"], "platform": "IAMRole", "name": role["RoleName"],
                              "role_arn": role["Arn"]})
    for i in items:
        i.update({"account_id": account_id, "region": REGION})
        i["details"] = json.dumps(i.get("details") or {}, default=str)
    return items


def register_items():
    out, kw = [], {"TableName": table_name(), "FilterExpression": "sk = :c", "ExpressionAttributeValues": {":c": {"S": "CURRENT"}}}
    while True:
        page = ddb.scan(**kw)
        out += [from_ddb(i) for i in page.get("Items", [])]
        if "LastEvaluatedKey" not in page:
            return out
        kw["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def _jsonl(rows):
    def norm(v):
        return sorted(v) if isinstance(v, set) else v
    return "\n".join(json.dumps({k: norm(v) for k, v in r.items()}, default=str) for r in rows) + "\n"


def handler(event, _ctx):
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    inv = inventory(account_id)
    reg = register_items()
    reg_ids = {r["agent_id"] for r in reg}
    identity_in_register = {i for r in reg for i in (r.get("identities") or [])}
    new = [i for i in inv if i["resource_arn"] not in reg_ids and i["resource_arn"] not in identity_in_register]
    for i in new:
        rec = {"agent_name": i["name"], "platform": i["platform"], "account_id": account_id, "region": REGION,
               "identities": {i["role_arn"]} if i.get("role_arn") else None, "status": "PendingReview"}
        put_history(ddb, i["resource_arn"], "RegisterSnapshot", rec)
        cur = dict(rec, pk=f"AGENT#{i['resource_arn']}", sk="CURRENT", agent_id=i["resource_arn"], record_type="RegisterSnapshot")
        try:
            ddb.put_item(TableName=table_name(), Item=to_ddb(cur), ConditionExpression="attribute_not_exists(pk)")
        except ddb.exceptions.ConditionalCheckFailedException:
            pass  # written by PB2 in the meantime; keep the existing record
        if i.get("role_arn"):
            ddb.put_item(TableName=table_name(), Item=to_ddb({"pk": f"IDENTITY#{i['role_arn']}", "sk": "MAP", "agent_id": i["resource_arn"]}))
    reg = register_items()
    d = today().isoformat()
    bucket = os.environ["EVIDENCE_BUCKET"]
    s3.put_object(Bucket=bucket, Key=f"inventory/snapshot_date={d}/inventory.jsonl", Body=_jsonl(inv).encode())
    s3.put_object(Bucket=bucket, Key=f"register/snapshot_date={d}/register.jsonl", Body=_jsonl(reg).encode())
    # Lookup table for Logs Insights (A02): role_name, agent_id, agent_name, owner, approved_models
    if os.environ.get("LOOKUP_TABLE_ARN"):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["role_name", "agent_id", "agent_name", "owner", "approved_models"])
        for r in reg:
            for ident in r.get("identities") or []:
                if ":role/" in ident:
                    w.writerow([ident.rsplit("/", 1)[-1], r["agent_id"], r.get("agent_name", ""), r.get("owner", ""),
                                "|".join(sorted(r.get("approved_models") or []))])
        logs.update_lookup_table(lookupTableArn=os.environ["LOOKUP_TABLE_ARN"], tableBody=buf.getvalue())
    overdue = sum(1 for r in reg if r.get("status") == "Approved" and (r.get("next_review_due") or "0000") < d)
    incomplete = sum(1 for r in reg if r.get("status") != "Retired" and not (r.get("owner") and r.get("business_purpose") and r.get("identities")))
    pending = sum(1 for r in reg if r.get("status") == "PendingReview")
    cw.put_metric_data(Namespace="Yuma/AIA", MetricData=[
        {"MetricName": "InventoryItems", "Value": len(inv), "Unit": "Count"},
        {"MetricName": "NewlyDiscovered", "Value": len(new), "Unit": "Count"},
        {"MetricName": "PendingReview", "Value": pending, "Unit": "Count"},
        {"MetricName": "ReviewsOverdue", "Value": overdue, "Unit": "Count"},
        {"MetricName": "RegisterIncomplete", "Value": incomplete, "Unit": "Count"},
    ])
    return {"inventory": len(inv), "new": len(new), "pending": pending, "overdue": overdue, "incomplete": incomplete}
