#!/usr/bin/env python3
"""Offline structural + UDM-field linter for YARA-L 2.0 rules.

This is NOT the Google SecOps compiler. It catches: missing/out-of-order sections, unbalanced brackets/strings,
UDM paths that don't exist in the published UDM field list (tools/udm_schema.json, parsed from
https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list), enum values that don't exist for enum fields,
undefined placeholder variables in match/outcome/condition, and outcome variables used in condition but not defined.
Run: python3 tools/yaral_lint.py detections/secops/*.yaral
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = json.load(open(os.path.join(HERE, "udm_schema.json")))
ENUMS = json.load(open(os.path.join(HERE, "udm_enums.json")))
ROOT = SCHEMA["UDM Event data model"]
SECTIONS = ["meta", "events", "match", "outcome", "condition"]
REQUIRED_META = ["author", "description", "severity", "yuma_id", "ism"]
LEAF_OK = {"google.protobuf.Timestamp": {"seconds", "nanos"}}
MAP_TYPES = {"google.protobuf.Struct"}


def strip_strings(text):
    """Replace string, regex and backtick literals with placeholders so path scanning ignores them."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            i = j
            continue
        if c in "\"`":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise ValueError(f"unterminated {c} literal at offset {i}")
            out.append('"S"')
            i = j + 1
            continue
        if c == "/" and re.search(r"(=|!=|\(|,|or|and)\s*$", "".join(out[-12:])):
            j = i + 1
            while j < n and text[j] != "/":
                if text[j] == "\n":
                    raise ValueError(f"unterminated regex literal at offset {i}")
                j += 2 if text[j] == "\\" else 1
            out.append('"R"')
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def resolve(path):
    """Return (ok, type_or_error) for a UDM path like principal.user.email_addresses."""
    parts = path.split(".")
    cur = ROOT
    typ = None
    for idx, p in enumerate(parts):
        if typ in LEAF_OK:
            return (p in LEAF_OK[typ] and idx == len(parts) - 1), typ
        if typ in MAP_TYPES:
            return True, typ
        if not isinstance(cur, dict) or p not in cur:
            return False, f"'{p}' not a field of {typ or 'UDM event'}"
        typ = cur[p]
        base = typ.split("(")[0].strip()
        cur = SCHEMA.get(base)
        typ = base
    return True, typ


def enum_of(typ):
    base = typ.split("(")[0].strip()
    return ENUMS.get(base)


def lint(path):
    errs = []
    raw = open(path).read()
    try:
        body = strip_strings(raw)
    except ValueError as e:
        return [str(e)]
    for o, c in ("{}", "()", "[]"):
        if body.count(o) != body.count(c):
            errs.append(f"unbalanced {o}{c}: {body.count(o)} vs {body.count(c)}")
    m = re.search(r"\brule\s+([a-z0-9_]+)\s*\{", body)
    if not m:
        errs.append("no 'rule <snake_case_name> {' header")
    pos = {s: body.find(f"\n  {s}:") for s in SECTIONS}
    for s in ("meta", "events", "condition"):
        if pos[s] < 0:
            errs.append(f"missing section {s}")
    present = [s for s in SECTIONS if pos[s] >= 0]
    if [pos[s] for s in present] != sorted(pos[s] for s in present):
        errs.append("sections out of order (meta, events, match, outcome, condition)")

    def section(name):
        if pos[name] < 0:
            return ""
        nxt = [pos[s] for s in SECTIONS if pos[s] > pos[name]]
        return body[pos[name]: min(nxt) if nxt else body.rfind("}")]

    meta = section("meta")
    for k in REQUIRED_META:
        if not re.search(rf"\b{k}\s*=", meta):
            errs.append(f"meta missing {k}")

    events = section("events")
    event_vars = set(re.findall(r"\$(\w+)\.", events))
    placeholders = set(re.findall(r"=\s*\$(\w+)\s*$", events, flags=re.M)) | set(re.findall(r"^\s*\$(\w+)\s*=\s*\$\w+\.", events, flags=re.M))
    # UDM paths
    raw_events = raw[raw.find("\n  events:"):]
    for var, p in re.findall(r"\$(\w+)\.([a-z_][a-z0-9_.]*)", body):
        p = p.rstrip(".")
        ok, info = resolve(p)
        if not ok:
            errs.append(f"${var}.{p}: {info}")
    # enum literals:  $x.path = "VALUE"
    for var, p, val in re.findall(r"\$(\w+)\.([a-z_][a-z0-9_.]*)\s*!?=\s*\"([A-Z_]+)\"", raw_events):
        ok, typ = resolve(p)
        vals = enum_of(typ) if ok and typ else None
        if vals and val not in vals:
            errs.append(f"${var}.{p} = \"{val}\": not a value of {typ}")

    match = section("match")
    for v in re.findall(r"\$(\w+)", match):
        if v not in placeholders and v not in event_vars:
            errs.append(f"match variable ${v} not defined in events")
    outcome = section("outcome")
    outcome_vars = set(re.findall(r"^\s*\$(\w+)\s*=", outcome, flags=re.M))
    if match and outcome:
        for line in outcome.splitlines():
            mm = re.match(r"\s*\$(\w+)\s*=\s*(.*)", line)
            if mm and not re.match(r"(max|min|sum|count|count_distinct|array|array_distinct|avg|stddev|earliest|latest)\(", mm.group(2)):
                errs.append(f"outcome ${mm.group(1)} must be aggregated when the rule has a match section")
    cond = section("condition")
    for v in re.findall(r"\$(\w+)", cond):
        if v not in event_vars and v not in outcome_vars:
            errs.append(f"condition uses ${v}, not an event or outcome variable")
    for v in event_vars:
        if not re.search(rf"\${v}\b", cond):
            errs.append(f"event variable ${v} not referenced in condition")
    for ref in re.findall(r"%(\w+)", body):
        if not ref.startswith("yuma_"):
            errs.append(f"reference list %{ref} should use the yuma_ prefix")
    return errs


def main(files):
    bad = 0
    for f in files:
        e = lint(f)
        print(("FAIL " if e else "OK   ") + os.path.basename(f))
        for x in e:
            print("     - " + x)
        bad += bool(e)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
