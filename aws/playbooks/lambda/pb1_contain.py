"""PB1 step 3 (only after approval): contain the agent identity.

Role: put an inline deny policy. mode "deny-all" blocks everything; mode "revoke-sessions" denies only sessions
issued before now (AWS's documented pattern using aws:TokenIssueTime):
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
IAM user: set its access keys Inactive (reversible).
"""
import datetime as dt
import json
import os

import boto3

iam = boto3.client("iam")

POLICY_NAME = os.environ.get("CONTAINMENT_POLICY_NAME", "YumaAIAContainment")


def handler(event, _ctx):
    ctx = event["context"]
    decision = event["decision"]
    mode = os.environ.get("CONTAINMENT_MODE", "deny-all")
    done = []
    if ctx.get("role_arn"):
        role_name = ctx["role_arn"].rsplit("/", 1)[-1]
        stmt = {"Effect": "Deny", "Action": "*", "Resource": "*"}
        if mode == "revoke-sessions":
            now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            stmt["Condition"] = {"DateLessThan": {"aws:TokenIssueTime": now}}
        iam.put_role_policy(RoleName=role_name, PolicyName=POLICY_NAME,
                            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [stmt]}))
        iam.tag_role(RoleName=role_name, Tags=[{"Key": "yuma-aia-contained", "Value": "true"},
                                                {"Key": "yuma-aia-approver", "Value": str(decision.get("approver"))[:256]}])
        done.append(f"put_role_policy {POLICY_NAME} ({mode}) on {role_name}")
    elif ctx.get("user_arn"):
        user = ctx["user_arn"].rsplit("/", 1)[-1]
        for key in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
            iam.update_access_key(UserName=user, AccessKeyId=key["AccessKeyId"], Status="Inactive")
            done.append(f"deactivated {key['AccessKeyId']}")
    return {"actions": done, "agent_id": (ctx.get("agent") or {}).get("agent_id") or ctx.get("role_arn") or ctx.get("user_arn")}
