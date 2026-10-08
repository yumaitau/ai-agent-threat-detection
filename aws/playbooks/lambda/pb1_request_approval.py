"""PB1 step 2 (invoked with .waitForTaskToken): ask a named human to approve containment.

No public callback endpoint. The approver runs one AWS CLI command with their own Identity Center session, so
CloudTrail records exactly who approved (states:SendTaskSuccess), which is the ISM-2113 evidence.
Posts to an SNS topic (email) and, if configured, a Slack or Teams incoming webhook whose URL is in Secrets Manager.
"""
import json
import os
import urllib.request

import boto3

sns = boto3.client("sns")
secrets = boto3.client("secretsmanager")


def _cli(token, decision):
    payload = json.dumps({"decision": decision, "approver": "<your name>", "reason": "<why>"})
    return f"aws stepfunctions send-task-success --task-output '{payload}' --task-token '{token}'"


def handler(event, _ctx):
    token = event["taskToken"]
    ctx = event["context"]
    text = (
        "Yuma AI agent containment request\n\n"
        f"What: {ctx.get('summary')}\n"
        f"Role: {ctx.get('role_arn') or ctx.get('user_arn')}\n"
        f"Owner: {ctx.get('owner')}\n"
        f"Proposed action: attach inline deny policy '{os.environ.get('CONTAINMENT_POLICY_NAME', 'YumaAIAContainment')}' "
        "(reversible: delete the inline policy)\n\n"
        "To APPROVE, run with your own AWS session:\n" + _cli(token, "approve") + "\n\n"
        "To REJECT:\n" + _cli(token, "reject") + "\n\n"
        f"This request times out after {os.environ.get('APPROVAL_TIMEOUT_HOURS', '4')} hours and is then treated as rejected."
    )
    sns.publish(TopicArn=os.environ["APPROVAL_TOPIC_ARN"], Subject="Approve AI agent containment?", Message=text)
    secret_id = os.environ.get("CHAT_WEBHOOK_SECRET_ID")
    if secret_id:
        url = secrets.get_secret_value(SecretId=secret_id)["SecretString"].strip()
        body = json.dumps({"text": text}).encode()  # Slack and Teams incoming webhooks both accept a "text" field
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 (URL comes from the customer's secret)
            r.read()
    return {"posted": True}
