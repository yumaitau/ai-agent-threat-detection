"""PB1 step 1: work out which principal the alert is about, whether it is an AI agent identity, and who owns it.

Input: the EventBridge event that triggered the state machine (CloudTrail API call from A04/A12, GuardDuty AI
Protection finding, or a scheduled-detection result posted as {"source":"yuma.aia", "detail": {...}}).
"""
import os

import boto3

from yuma_common import find_agent_by_identity, role_name_from_arn, trusts_ai_service

iam = boto3.client("iam")
ddb = boto3.client("dynamodb")


def _principal_from_event(event):
    detail = event.get("detail", {})
    src = event.get("source")
    if src == "aws.guardduty":
        # AI Protection findings use resource type AccessKey (resource.accessKeyDetails).
        akd = detail.get("resource", {}).get("accessKeyDetails", {})
        return {"kind": akd.get("userType"), "name": akd.get("userName"), "access_key_id": akd.get("accessKeyId"),
                "account": detail.get("accountId"), "finding_type": detail.get("type"),
                "severity": detail.get("severity")}
    if detail.get("eventSource") == "iam.amazonaws.com":
        role = (detail.get("requestParameters") or {}).get("roleName")
        return {"kind": "Role", "name": role, "account": detail.get("recipientAccountId"),
                "finding_type": f"Yuma AIA-A04 {detail.get('eventName')}"}
    if src == "yuma.aia":
        return {"kind": detail.get("principalKind", "Role"), "name": role_name_from_arn(detail.get("principalArn")) or detail.get("principalName"),
                "account": detail.get("accountId"), "finding_type": detail.get("detection")}
    ui = detail.get("userIdentity", {})
    issuer = (ui.get("sessionContext") or {}).get("sessionIssuer", {})
    return {"kind": issuer.get("type") or ui.get("type"), "name": issuer.get("userName") or ui.get("userName"),
            "account": detail.get("recipientAccountId"), "finding_type": detail.get("eventName")}


def handler(event, _ctx):
    p = _principal_from_event(event)
    out = dict(p)
    out["is_agent_identity"] = False
    out["agent"] = None
    if p.get("kind") in ("Role", "AssumedRole") and p.get("name"):
        role = iam.get_role(RoleName=p["name"])["Role"]
        out["role_arn"] = role["Arn"]
        out["trusts_ai_service"] = trusts_ai_service(role["AssumeRolePolicyDocument"])
        agent = find_agent_by_identity(ddb, role["Arn"])
        out["agent"] = agent
        out["is_agent_identity"] = bool(agent) or out["trusts_ai_service"]
    elif p.get("kind") == "IAMUser" and p.get("name"):
        arn = f"arn:aws:iam::{p['account']}:user/{p['name']}"
        out["user_arn"] = arn
        agent = find_agent_by_identity(ddb, arn)
        out["agent"] = agent
        out["is_agent_identity"] = bool(agent)
    out["owner"] = (out["agent"] or {}).get("owner") or os.environ.get("DEFAULT_OWNER", "security-team")
    out["summary"] = (f"{p.get('finding_type')} on {p.get('kind')} {p.get('name')} in {p.get('account')}; "
                      f"agent={((out['agent'] or {}).get('agent_name')) or 'not in register'}")
    return out
