#!/usr/bin/env python3
"""Checks that names used in the pack exist in AWS's own service models (botocore) or in cited AWS docs:
  1. CloudTrail eventName values in EventBridge patterns and in SQL "eventName IN (...)"/"api.operation IN (...)" lists
  2. boto3 client methods called by the Lambdas (AST scan; each must map to a real API operation)
  3. IAM actions in the CloudFormation template (heuristic: action name == API operation name)
Exceptions are listed with the doc that verifies them."""
import ast
import json
import pathlib
import re
import sys

import boto3
import botocore.session
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
S = botocore.session.get_session()
SOURCE_TO_SERVICES = {
    "bedrock.amazonaws.com": ["bedrock", "bedrock-runtime", "bedrock-agent", "bedrock-agent-runtime"],
    "bedrock-agentcore.amazonaws.com": ["bedrock-agentcore-control", "bedrock-agentcore"],
    "agent-registry.amazonaws.com": ["agent-registry-control", "agent-registry"],
    "iam.amazonaws.com": ["iam"], "sso.amazonaws.com": ["sso-admin", "sso-oidc", "sso"],
    "cloudtrail.amazonaws.com": ["cloudtrail"], "guardduty.amazonaws.com": ["guardduty"],
    "s3.amazonaws.com": ["s3"], "secretsmanager.amazonaws.com": ["secretsmanager"], "ssm.amazonaws.com": ["ssm"],
}
IAM_PREFIX_TO_SERVICES = {
    "bedrock": ["bedrock", "bedrock-runtime", "bedrock-agent", "bedrock-agent-runtime"],
    "bedrock-agentcore": ["bedrock-agentcore-control", "bedrock-agentcore"],
    "agent-registry": ["agent-registry-control", "agent-registry"], "states": ["stepfunctions"],
    "events": ["events"], "scheduler": ["scheduler"], "logs": ["logs"], "cloudwatch": ["cloudwatch"],
}
DOC_VERIFIED = {
    ("bedrock-agentcore.amazonaws.com", "InvokeGateway"): "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/understanding-gateway-cloudtrail-log-entries.html",
}
PERMISSION_ONLY = {"iam:PassRole"}
# IAM action names that differ from the API operation name, with the Service Authorization Reference page
IAM_ALIASES = {"lambda:InvokeFunction": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_lambda.html (API: Invoke)"}


def ops(services):
    out = set()
    for s in services:
        out |= set(S.get_service_model(s).operation_names)
    return out


def check_event_names():
    errs, n = [], 0
    for p in sorted((ROOT / "detections").glob("*.eventbridge.json")):
        pat = json.loads(p.read_text())
        d = pat.get("detail", {})
        sources = [s for s in d.get("eventSource", []) if isinstance(s, str)]
        if not sources:
            continue
        allowed = ops([svc for s in sources for svc in SOURCE_TO_SERVICES[s]])
        for name in d.get("eventName", []):
            n += 1
            if name not in allowed and not any((s, name) in DOC_VERIFIED for s in sources):
                errs.append(f"{p.name}: eventName {name} not an operation of {sources}")
    for p in sorted((ROOT / "detections").glob("*.sql")):
        txt = p.read_text()
        srcs = set(re.findall(r"'([a-z0-9-]+\.amazonaws\.com)'", txt))
        allowed = ops([svc for s in srcs if s in SOURCE_TO_SERVICES for svc in SOURCE_TO_SERVICES[s]])
        for block in re.findall(r"(?:eventName|api\.operation)\s*(?:IN\s*\(([^)]*)\)|=\s*'([A-Za-z0-9]+)')", txt):
            for name in re.findall(r"'([A-Za-z0-9]+)'", block[0]) + ([block[1]] if block[1] else []):
                n += 1
                if name not in allowed and not any((s, name) in DOC_VERIFIED for s in srcs):
                    errs.append(f"{p.name}: {name} not an operation of {sorted(srcs)}")
    return n, errs


def check_lambda_calls():
    errs, n = [], 0
    for p in sorted((ROOT / "playbooks" / "lambda").glob("*.py")):
        tree = ast.parse(p.read_text())
        clients = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                f = node.value.func
                if isinstance(f, ast.Attribute) and f.attr == "client" and node.value.args and isinstance(node.value.args[0], ast.Constant):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            clients[tgt.id] = node.value.args[0].value
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                obj = node.func.value
                svc = None
                if isinstance(obj, ast.Name) and obj.id in clients:
                    svc = clients[obj.id]
                elif isinstance(obj, ast.Call) and isinstance(obj.func, ast.Attribute) and obj.func.attr == "client" and obj.args:
                    svc = obj.args[0].value
                if not svc:
                    continue
                meth = node.func.attr
                if meth in ("get_paginator", "exceptions"):
                    continue
                c = boto3.client(svc, region_name="ap-southeast-2", aws_access_key_id="x", aws_secret_access_key="x")
                n += 1
                if meth not in c.meta.method_to_api_mapping:
                    errs.append(f"{p.name}: {svc}.{meth} is not a boto3 method")
            # generic paginator helper calls: _pages(client, "op", ...)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_pages":
                a0, a1 = node.args[0], node.args[1]
                svc = clients.get(a0.id) if isinstance(a0, ast.Name) else None
                if svc is None:
                    continue
                c = boto3.client(svc, region_name="ap-southeast-2", aws_access_key_id="x", aws_secret_access_key="x")
                n += 1
                if a1.value not in c.meta.method_to_api_mapping:
                    errs.append(f"{p.name}: {svc}.{a1.value} is not a boto3 method")
    return n, errs


def local_clients_fix():
    """pb4_inventory creates some clients inside functions (ba, ac, ar); the AST scan above picks those up too
    because they are plain assignments."""


def check_iam_actions():
    errs, n = [], 0
    t = yaml.safe_load((ROOT / "deploy" / "cfn" / "yuma-aia-core.yaml").read_text())
    acts = set()

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "Action":
                    for a in (v if isinstance(v, list) else [v]):
                        acts.add(a)
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(t)
    for a in sorted(acts):
        if a in ("*", "s3:*") or a in PERMISSION_ONLY or a in IAM_ALIASES:
            continue
        prefix, name = a.split(":", 1)
        svcs = IAM_PREFIX_TO_SERVICES.get(prefix, [prefix])
        try:
            allowed = ops(svcs)
        except Exception:
            errs.append(f"{a}: no botocore model for prefix {prefix}")
            continue
        n += 1
        if name not in allowed:
            errs.append(f"{a}: not an API operation (may still be a valid permission-only action; check the Service Authorization Reference)")
    return n, errs


def main():
    total_err = 0
    for label, fn in (("CloudTrail event names", check_event_names), ("Lambda boto3 calls", check_lambda_calls), ("IAM actions in CFN", check_iam_actions)):
        n, errs = fn()
        total_err += len(errs)
        print(f"{label}: {n} checked, {len(errs)} problem(s)")
        for e in errs:
            print(f"    {e}")
    print("Doc-verified exceptions: " + "; ".join(f"{k[1]} ({v})" for k, v in DOC_VERIFIED.items()))
    return total_err


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
