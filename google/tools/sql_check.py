#!/usr/bin/env python3
"""Offline check of the BigQuery SQL in this pack.

1. Substitutes the Terraform templatefile placeholders (${logs_table}, ${workspace_activity_table}, ${register_dataset}).
2. Parses with sqlglot (BigQuery dialect), standalone AND wrapped exactly as deploy/terraform/detections.tf wraps it.
3. Checks column paths on the two external sources against allow-lists taken from Google docs / Google's own queries:
   Log Analytics _AllLogs (CSA queries) and the Workspace BigQuery export (support.google.com/a/answer/9079965).
   Paths marked UNVALIDATED in a file header are reported as warnings, not failures.
sqlglot parsing is NOT a BigQuery dry run: it does not resolve tables, types or functions.
"""
import glob
import os
import re
import sys

import sqlglot

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
SUBS = {"${logs_table}": "proj.logs_linked._AllLogs", "${workspace_activity_table}": "proj.workspace.activity",
        "${register_dataset}": "proj.yuma_ai_register"}

# _AllLogs top-level columns and audit paths used by Google's CSA Log Analytics queries / LogEntry schema
LOGS_TOP = {"timestamp", "log_id", "log_name", "resource", "proto_payload", "json_payload", "http_request", "labels", "severity"}
AUDIT_PATHS = {"service_name", "method_name", "resource_name", "authentication_info", "request_metadata", "response",
               "request", "metadata", "service_data", "status"}
WS_TOP = {"time_usec", "email", "ip_address", "event_name", "event_type", "record_type", "token", "admin", "drive", "login",
          "_PARTITIONTIME"}
WS_TOKEN_VERIFIED = {"client_id", "app_name", "scope"}


def render(text):
    for k, v in SUBS.items():
        text = text.replace(k, v)
    if "${" in text or "%{" in text:
        raise ValueError("unresolved template marker")
    return text


def wrap(sql, det_id):
    return (f"INSERT INTO `proj.yuma_ai_register.detection_hits` (hit_time, detection_id, severity, entity, summary, details)\n"
            f"SELECT CURRENT_TIMESTAMP(), '{det_id}', t.severity, t.entity, t.summary, TO_JSON(t) FROM (\n{sql}\n) AS t\n"
            f"WHERE NOT EXISTS (SELECT 1 FROM `proj.yuma_ai_register.detection_hits` AS h WHERE h.detection_id = '{det_id}' "
            f"AND h.entity = t.entity AND h.hit_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR))")


def field_checks(text):
    errs, warns = [], []
    header = "\n".join(l for l in text.splitlines() if l.startswith("--"))
    body = "\n".join(l.split("--")[0] for l in text.splitlines())
    if "${logs_table}" in text:
        for col in set(re.findall(r"\bl\.([a-z_]+)", body)):
            if col not in LOGS_TOP:
                errs.append(f"_AllLogs column l.{col} not in allow-list")
        for p in set(re.findall(r"audit_log\.([a-z_]+)", body)):
            if p not in AUDIT_PATHS:
                errs.append(f"audit_log.{p} not in allow-list")
    if "${workspace_activity_table}" in text:
        for col in set(re.findall(r"\ba\.([A-Za-z_]+)\b(?!\()", body)):
            if col not in WS_TOP:
                errs.append(f"Workspace export column a.{col} not in allow-list")
        for col in set(re.findall(r"\ba\.token\.([a-z_]+)", body)):
            if col not in WS_TOKEN_VERIFIED:
                (warns if "UNVALIDATED" in header and col in header else errs).append(f"token.{col} not verified in export docs")
    if "${" in body.replace("${logs_table}", "").replace("${workspace_activity_table}", "").replace("${register_dataset}", ""):
        errs.append("unknown template placeholder")
    return errs, warns


def check(path):
    text = open(path).read()
    errs, warns = field_checks(text)
    try:
        sql = render(text)
        sqlglot.parse(sql, read="bigquery", error_level=sqlglot.ErrorLevel.RAISE)
        m = re.match(r"(G\d\d)_", os.path.basename(path))
        if m and "/detections/" in path:
            sqlglot.parse_one(wrap(sql, m.group(1)), read="bigquery", error_level=sqlglot.ErrorLevel.RAISE)
    except Exception as exc:  # noqa: BLE001
        errs.append(f"parse: {str(exc).splitlines()[0][:200]}")
    return errs, warns


def main(paths):
    files = []
    for p in paths:
        files += sorted(glob.glob(p)) if any(c in p for c in "*?") else [p]
    bad = 0
    for f in files:
        e, w = check(f)
        print(("FAIL " if e else "OK   ") + os.path.relpath(f, PACK))
        for x in e:
            print("     - " + x)
        for x in w:
            print("     ~ warn: " + x)
        bad += bool(e)
    print(f"sqlglot {sqlglot.__version__}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or [os.path.join(PACK, "detections/bigquery/*.sql"), os.path.join(PACK, "register/sql/*.sql")]))
