"""Shared helpers for the Yuma AI agent pack Lambdas (bundled into each function zip by tools/package_lambdas.py)."""
import datetime as _dt
import json
import os

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

_ser = TypeSerializer()
_des = TypeDeserializer()

REVIEW_DAYS = 182  # six-monthly review (ISM-2138 cadence, applied to agents)


def now_iso():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today():
    return _dt.datetime.now(_dt.timezone.utc).date()


def to_ddb(item):
    """Plain dict -> DynamoDB attribute map. Empty lists and None are dropped (DynamoDB rejects empty sets)."""
    return {k: _ser.serialize(v) for k, v in item.items() if v is not None and v != []}


def from_ddb(item):
    return {k: _des.deserialize(v) for k, v in item.items()}


def table_name():
    return os.environ["REGISTER_TABLE"]


def find_agent_by_identity(ddb, identity_arn):
    """Identity map items: pk = IDENTITY#<arn>, sk = MAP, agent_id."""
    resp = ddb.get_item(TableName=table_name(), Key={"pk": {"S": f"IDENTITY#{identity_arn}"}, "sk": {"S": "MAP"}})
    if "Item" not in resp:
        return None
    agent_id = resp["Item"]["agent_id"]["S"]
    cur = ddb.get_item(TableName=table_name(), Key={"pk": {"S": f"AGENT#{agent_id}"}, "sk": {"S": "CURRENT"}})
    return from_ddb(cur["Item"]) if "Item" in cur else {"agent_id": agent_id}


def put_history(ddb, agent_id, record_type, body):
    item = dict(body)
    item.update({"pk": f"AGENT#{agent_id}", "sk": f"HIST#{now_iso()}#{record_type}", "agent_id": agent_id,
                 "record_type": record_type, "updated_at": now_iso()})
    ddb.put_item(TableName=table_name(), Item=to_ddb(item))


def role_name_from_arn(arn):
    """arn:aws:iam::123:role/path/Name -> Name ; arn:aws:sts::123:assumed-role/Name/session -> Name"""
    if not arn:
        return None
    if ":assumed-role/" in arn:
        return arn.split(":assumed-role/", 1)[1].split("/")[0]
    if ":role/" in arn:
        return arn.rsplit("/", 1)[-1]
    return None


def role_arn_from_any(arn, account_id=None):
    """Session ARN or role ARN -> role ARN (path is lost for assumed-role ARNs; resolve with iam:GetRole)."""
    if not arn:
        return None
    if ":role/" in arn:
        return arn
    name = role_name_from_arn(arn)
    acct = account_id or arn.split(":")[4]
    return f"arn:aws:iam::{acct}:role/{name}" if name else None


def trusts_ai_service(assume_role_policy):
    """True if the trust policy lets Bedrock or AgentCore assume the role."""
    doc = assume_role_policy
    if isinstance(doc, str):
        from urllib.parse import unquote
        doc = json.loads(unquote(doc))
    for st in doc.get("Statement", []):
        svc = (st.get("Principal") or {}).get("Service", [])
        svc = [svc] if isinstance(svc, str) else svc
        if any(s in ("bedrock.amazonaws.com", "bedrock-agentcore.amazonaws.com") for s in svc):
            return True
    return False
