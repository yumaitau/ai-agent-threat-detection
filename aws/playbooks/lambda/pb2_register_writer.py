"""PB2: write new or changed AI agents, tools and credentials to the register, and run the six-monthly review sweep.

Triggers:
  - EventBridge rule with pattern detections/A03-agent-or-tool-change.eventbridge.json (CloudTrail API call)
  - EventBridge Scheduler, weekly, input {"action": "review-sweep"}
Human decisions are recorded with tools/register_decide.py (writes an ApprovalDecision or ReviewCompleted record).
"""
import datetime as dt
import os

import boto3

from yuma_common import REVIEW_DAYS, from_ddb, now_iso, put_history, table_name, to_ddb, today

ddb = boto3.client("dynamodb")
sns = boto3.client("sns")

# Response fields that carry the new resource's ARN, by event (from the API output shapes)
ARN_KEYS = ["agentArn", "agentRuntimeArn", "gatewayArn", "targetArn", "workloadIdentityArn", "credentialProviderArn",
            "knowledgeBaseArn", "flowArn", "memoryArn", "browserArn", "codeInterpreterArn", "recordArn", "agentAliasArn"]
PLATFORM = {"CreateAgent": "BedrockAgent", "UpdateAgent": "BedrockAgent", "CreateAgentRuntime": "AgentCoreRuntime",
            "UpdateAgentRuntime": "AgentCoreRuntime", "CreateGateway": "AgentCoreGateway", "UpdateGateway": "AgentCoreGateway",
            "CreateWorkloadIdentity": "AgentCoreWorkloadIdentity", "CreateRegistryRecord": "AgentRegistryRecord"}


def _find_arn(detail):
    resp = detail.get("responseElements") or {}
    for key in ARN_KEYS:
        val = resp.get(key) or (resp.get("agent") or {}).get(key)
        if val:
            return val
    for r in detail.get("resources") or []:
        if r.get("ARN"):
            return r["ARN"]
    return None


def on_change(event):
    d = event["detail"]
    req = d.get("requestParameters") or {}
    agent_id = _find_arn(d) or f"unresolved:{d.get('eventID')}"
    role = req.get("roleArn") or req.get("agentResourceRoleArn")
    change = {
        "agent_name": req.get("name") or req.get("agentName") or req.get("actionGroupName"),
        "platform": PLATFORM.get(d["eventName"], "Other"),
        "account_id": d.get("recipientAccountId"), "region": d.get("awsRegion"),
        "identities": {role} if role else None,
        "decision": f"{d['eventName']} by {d.get('userIdentity', {}).get('arn')}",
        "source_event_id": d.get("eventID"), "status": "PendingReview",
    }
    put_history(ddb, agent_id, "ChangeObserved", change)
    # Upsert CURRENT without overwriting a human decision: status only set if the record is new.
    names, values, sets = {"#s": "status"}, {":pr": {"S": "PendingReview"}, ":u": {"S": now_iso()},
                                              ":a": {"S": agent_id}, ":p": {"S": change["platform"]}}, []
    sets.append("#s = if_not_exists(#s, :pr)")
    sets.append("updated_at = :u, agent_id = :a, platform = if_not_exists(platform, :p)")
    if change["agent_name"]:
        values[":n"] = {"S": change["agent_name"]}
        sets.append("agent_name = :n")
    expr = "SET " + ", ".join(sets)
    if role:
        values[":r"] = {"SS": [role]}
        expr += " ADD identities :r"  # identities is a DynamoDB string set; ADD merges without duplicates
    ddb.update_item(TableName=table_name(), Key={"pk": {"S": f"AGENT#{agent_id}"}, "sk": {"S": "CURRENT"}},
                    UpdateExpression=expr, ExpressionAttributeNames=names, ExpressionAttributeValues=values)
    if role:
        ddb.put_item(TableName=table_name(), Item=to_ddb({"pk": f"IDENTITY#{role}", "sk": "MAP", "agent_id": agent_id}))
    sns.publish(TopicArn=os.environ["REGISTER_TOPIC_ARN"], Subject="AI agent register: decision needed",
                Message=(f"{change['decision']}\nAgent: {agent_id}\nPlatform: {change['platform']}\nRole: {role}\n\n"
                         "Record a decision (owner, purpose, approve or reject):\n"
                         f"python tools/register_decide.py --agent-id '{agent_id}' --decision approve --owner <name> --purpose <text>"))
    return {"agent_id": agent_id, "status": "PendingReview"}


def review_sweep():
    horizon = (today() + dt.timedelta(days=30)).isoformat()
    due = []
    kwargs = {"TableName": table_name(), "IndexName": "by-status-review",
              "KeyConditionExpression": "#s = :a AND next_review_due <= :h",
              "ExpressionAttributeNames": {"#s": "status"},
              "ExpressionAttributeValues": {":a": {"S": "Approved"}, ":h": {"S": horizon}}}
    while True:
        page = ddb.query(**kwargs)
        due += [from_ddb(i) for i in page.get("Items", [])]
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    if due:
        lines = [f"- {a.get('agent_name') or a['agent_id']} (owner {a.get('owner')}): review due {a.get('next_review_due')}" for a in due]
        sns.publish(TopicArn=os.environ["REGISTER_TOPIC_ARN"], Subject=f"AI agent reviews due: {len(due)}",
                    Message=f"Six-monthly reviews (every {REVIEW_DAYS} days) due within 30 days:\n" + "\n".join(lines))
    return {"due": len(due)}


def handler(event, _ctx):
    if event.get("action") == "review-sweep":
        return review_sweep()
    return on_change(event)
