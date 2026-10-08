#!/usr/bin/env python3
"""Offline SQL check for the pack:
  1. parse every .sql file with sqlglot (Trino dialect for CloudTrail Lake, Athena dialect otherwise)
  2. schema check: every dotted column path must be a documented field of a table the query reads
     (tools/schemas.json); bare names must be documented fields or names defined in the query (aliases, CTEs, UNNEST).
It does not execute anything and cannot prove a query returns rows.
Usage: sqlcheck.py <file.sql> [...]"""
import json
import pathlib
import re
import sys

import sqlglot
from sqlglot import exp

SCHEMAS = json.loads((pathlib.Path(__file__).parent / "schemas.json").read_text())
FUNCS_AS_COLS = {"current_timestamp", "current_date"}


def schema_keys(sql):
    keys = set()
    if "$EDS_ID" in sql:
        keys.add("cloudtrail_lake")
    if re.search(r"_cloud_trail_mgmt_2_0|_s3_data_2_0", sql):
        keys.add("sl_cloudtrail")
    if "_waf_2_0" in sql:
        keys.add("sl_waf")
    if "_route53_2_0" in sql:
        keys.add("sl_route53")
    if "yuma_aia." in sql:
        keys.add("yuma_aia")
    return keys


def check(path):
    raw = pathlib.Path(path).read_text()
    dialect = "trino" if "$EDS_ID" in raw else "athena"
    sql = raw.replace("$EDS_ID", "eds_placeholder")
    errors = []
    try:
        stmts = [s for s in sqlglot.parse(sql, read=dialect) if s is not None]
    except sqlglot.errors.ParseError as e:
        return [f"PARSE {e}"]
    keys = schema_keys(raw)
    allowed = set()
    for k in keys:
        allowed |= {f.lower() for f in SCHEMAS[k]}
    struct_fields = set(SCHEMAS["cloudtrail_lake_struct_fields"]) if "cloudtrail_lake" in keys else set()
    top = {a.split(".")[0] for a in allowed}
    for st in stmts:
        if isinstance(st, (exp.Create,)) and st.args.get("kind", "").upper() in ("DATABASE", "TABLE"):
            continue
        local = set()
        for a in st.find_all(exp.Alias):
            local.add(a.alias.lower())
        for c in st.find_all(exp.CTE):
            local.add(c.alias.lower())
        table_aliases = set()
        for ta in st.find_all(exp.TableAlias):
            if ta.name:
                table_aliases.add(ta.name.lower())
            for col in ta.columns:
                local.add(col.name.lower())
        for lam in st.find_all(exp.Lambda):
            for v in lam.expressions:
                local.add(v.name.lower())
        for col in st.find_all(exp.Column):
            if isinstance(col.this, exp.Star):
                continue
            parts = [p.name.lower() for p in col.parts]
            if parts and parts[0] in table_aliases and len(parts) > 1:
                parts = parts[1:]
            path_ = ".".join(parts)
            if not keys or path_ in FUNCS_AS_COLS:
                continue
            if len(parts) == 1:
                if parts[0] not in top and parts[0] not in local and parts[0] not in allowed:
                    errors.append(f"UNKNOWN column '{path_}'")
            else:
                if path_ in allowed or parts[0] in local:
                    continue
                if any(path_.startswith(a + ".") for a in allowed if a in ("api.request.data", "api.response.data")):
                    continue
                errors.append(f"UNKNOWN field '{path_}'")
        # element_at(resources, 1).arn style struct access (CloudTrail Lake)
        for dot in st.find_all(exp.Dot):
            if isinstance(dot.this, (exp.Anonymous, exp.Func, exp.Bracket)):
                name = dot.name.lower()
                if struct_fields and name not in struct_fields:
                    errors.append(f"UNKNOWN struct field '.{name}'")
    return errors


def main(files):
    bad = 0
    for f in files:
        errs = check(f)
        bad += bool(errs)
        print(f"{'PASS' if not errs else 'FAIL'}  {f}")
        for e in sorted(set(errs)):
            print(f"        {e}")
    print(f"sqlcheck: {bad} file(s) failed of {len(files)}")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main(sys.argv[1:]) else 0)
