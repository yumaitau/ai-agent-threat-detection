#!/usr/bin/env python3
"""Offline structural check for Google Workflows YAML (not the Workflows API validator).

Checks: YAML parses; 'main' exists; every step is a single-key mapping; each step body uses known step keys;
'call' targets are either subworkflows in the file or in the allow-list below (connectors/std-lib functions that
appear in Google's Workflows reference: https://docs.cloud.google.com/workflows/docs/reference/googleapis and
https://docs.cloud.google.com/workflows/docs/reference/stdlib/overview); '${' expressions have balanced braces.
"""
import sys

import yaml

STEP_KEYS = {"assign", "call", "args", "result", "switch", "next", "return", "raise", "steps", "for", "parallel", "try",
             "except", "retry"}
CALLS = {"http.get", "http.post", "events.create_callback_endpoint", "events.await_callback", "sys.log", "sys.sleep",
         "googleapis.bigquery.v2.jobs.query", "googleapis.bigquery.v2.jobs.insert", "googleapis.bigquery.v2.tabledata.insertAll",
         "googleapis.secretmanager.v1.projects.secrets.versions.accessString", "googleapis.storage.v1.objects.insert"}


def walk_steps(steps, subs, errs, where):
    if not isinstance(steps, list):
        errs.append(f"{where}: steps must be a list")
        return
    for s in steps:
        if not isinstance(s, dict) or len(s) != 1:
            errs.append(f"{where}: each step must be a single-key mapping")
            continue
        name, body = next(iter(s.items()))
        if not isinstance(body, dict):
            errs.append(f"{where}/{name}: step body must be a mapping")
            continue
        bad = set(body) - STEP_KEYS
        if bad:
            errs.append(f"{where}/{name}: unknown keys {sorted(bad)}")
        if "call" in body and body["call"] not in CALLS and body["call"] not in subs:
            errs.append(f"{where}/{name}: call target {body['call']} not in allow-list")
        if "steps" in body:
            walk_steps(body["steps"], subs, errs, f"{where}/{name}")
        if "for" in body:
            walk_steps(body["for"].get("steps"), subs, errs, f"{where}/{name}/for")
        if "try" in body and isinstance(body["try"], dict) and "steps" in body["try"]:
            walk_steps(body["try"]["steps"], subs, errs, f"{where}/{name}/try")
        if "except" in body and "steps" in body["except"]:
            walk_steps(body["except"]["steps"], subs, errs, f"{where}/{name}/except")
        for c in body.get("switch", []) or []:
            if "steps" in c:
                walk_steps(c["steps"], subs, errs, f"{where}/{name}/switch")


def expr_check(node, errs, path="$"):
    if isinstance(node, dict):
        for k, v in node.items():
            expr_check(v, errs, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            expr_check(v, errs, f"{path}[{i}]")
    elif isinstance(node, str) and node.startswith("${"):
        depth = 0
        for ch in node:
            depth += (ch == "{") - (ch == "}")
        if depth != 0 or not node.endswith("}"):
            errs.append(f"{path}: unbalanced expression")


def check(path):
    errs = []
    doc = yaml.safe_load(open(path))
    if "main" not in doc:
        return ["no main workflow"]
    subs = set(doc)
    for name, wf in doc.items():
        walk_steps(wf.get("steps"), subs, errs, name)
    expr_check(doc, errs)
    return errs


if __name__ == "__main__":
    bad = 0
    for f in sys.argv[1:]:
        e = check(f)
        print(("FAIL " if e else "OK   ") + f.split("/")[-1])
        for x in e:
            print("     - " + x)
        bad += bool(e)
    sys.exit(1 if bad else 0)
