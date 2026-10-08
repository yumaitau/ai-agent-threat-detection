#!/usr/bin/env python3
"""Record a human decision in the AI agent register (run with your own AWS session, so CloudTrail shows who decided).
Examples:
  register_decide.py --agent-id <arn> --decision approve --owner "Kim Lee" --purpose "HR FAQ agent" \
      --tools "action-group:faq" --permissions "role/HRAgentRole" --data "kb/KB123" --models anthropic.claude-3-haiku
  register_decide.py --agent-id <arn> --decision review    # six-monthly review completed, no change
  register_decide.py --agent-id <arn> --decision reject --reason "not approved by data owner"
  register_decide.py --agent-id <arn> --decision retire"""
import argparse
import datetime as dt
import os
import sys

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "playbooks", "lambda"))
from yuma_common import REVIEW_DAYS, now_iso, put_history  # noqa: E402

p = argparse.ArgumentParser()
p.add_argument("--table", default=os.environ.get("REGISTER_TABLE"))
p.add_argument("--agent-id", required=True)
p.add_argument("--decision", required=True, choices=["approve", "reject", "review", "retire"])
p.add_argument("--owner")
p.add_argument("--purpose")
p.add_argument("--tools", nargs="*", default=[])
p.add_argument("--permissions", nargs="*", default=[])
p.add_argument("--data", nargs="*", default=[])
p.add_argument("--credentials", nargs="*", default=[])
p.add_argument("--models", nargs="*", default=[])
p.add_argument("--reason", default="")
a = p.parse_args()
os.environ["REGISTER_TABLE"] = a.table
ddb = boto3.client("dynamodb")
who = boto3.client("sts").get_caller_identity()["Arn"]
today = dt.date.today()
status = {"approve": "Approved", "reject": "Rejected", "review": "Approved", "retire": "Retired"}[a.decision]
record_type = {"approve": "ApprovalDecision", "reject": "ApprovalDecision", "review": "ReviewCompleted", "retire": "Retired"}[a.decision]
fields = {"status": status, "decided_by": who, "decided_at": now_iso(), "decision": f"{a.decision}: {a.reason}".strip(": ")}
if a.decision in ("approve", "review"):
    fields["last_review"] = today.isoformat()
    fields["next_review_due"] = (today + dt.timedelta(days=REVIEW_DAYS)).isoformat()
for k, v in (("owner", a.owner), ("business_purpose", a.purpose)):
    if v:
        fields[k] = v
sets = {k: v for k, v in (("tools", a.tools), ("permissions", a.permissions), ("data_repositories", a.data),
                          ("credentials", a.credentials), ("approved_models", a.models)) if v}
put_history(ddb, a.agent_id, record_type, dict(fields, **{k: set(v) for k, v in sets.items()}))
names, values, parts = {}, {}, []
for i, (k, v) in enumerate(list(fields.items()) + [(k, set(v)) for k, v in sets.items()] + [("updated_at", now_iso())]):
    names[f"#f{i}"] = k
    values[f":v{i}"] = {"SS": sorted(v)} if isinstance(v, set) else {"S": v}
    parts.append(f"#f{i} = :v{i}")
ddb.update_item(TableName=a.table, Key={"pk": {"S": f"AGENT#{a.agent_id}"}, "sk": {"S": "CURRENT"}},
                UpdateExpression="SET " + ", ".join(parts), ExpressionAttributeNames=names, ExpressionAttributeValues=values)
print(f"{record_type} recorded for {a.agent_id} by {who}: status {status}")
