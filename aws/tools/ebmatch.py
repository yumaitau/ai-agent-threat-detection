#!/usr/bin/env python3
"""Offline EventBridge pattern tester (subset of the documented matching rules):
exact values, prefix, suffix, anything-but, exists, numeric, wildcard, equals-ignore-case; arrays in the event
match when any element matches. AWS evaluates array-of-object paths leaf by leaf over the flattened event, which is
looser than this checker when one pattern spans two leaves inside the same array; noted in the README.
Rules: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html
Usage: ebmatch.py <detections dir>  (reads samples/expectations.json)"""
import fnmatch
import json
import operator
import pathlib
import sys

MISSING = object()


def leaf_ok(cond, val):
    if isinstance(cond, dict):
        (k, arg), = cond.items()
        if k == "exists":
            return (val is not MISSING) == arg
        if val is MISSING:
            return False
        if k == "prefix":
            return isinstance(val, str) and val.startswith(arg if isinstance(arg, str) else arg.get("equals-ignore-case", ""))
        if k == "suffix":
            return isinstance(val, str) and val.endswith(arg)
        if k == "equals-ignore-case":
            return isinstance(val, str) and val.lower() == arg.lower()
        if k == "wildcard":
            return isinstance(val, str) and fnmatch.fnmatchcase(val, arg)
        if k == "anything-but":
            args = arg if isinstance(arg, list) else [arg]
            if isinstance(arg, dict):
                return not leaf_ok(arg, val)
            return val not in args
        if k == "numeric":
            ops = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge, "=": operator.eq}
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                return False
            return all(ops[arg[i]](val, arg[i + 1]) for i in range(0, len(arg), 2))
        raise ValueError(f"unsupported filter {k}")
    if val is MISSING:
        return False
    return cond == val


def values_ok(conds, val):
    vals = val if isinstance(val, list) else [val]
    if val is MISSING:
        vals = [MISSING]
    return any(leaf_ok(c, v) for c in conds for v in vals)


def match(pattern, event):
    if isinstance(event, list):
        return any(match(pattern, e) for e in event)
    for key, sub in pattern.items():
        if key in ("$or",):
            if not any(match(p, event) for p in sub):
                return False
            continue
        val = event.get(key, MISSING) if isinstance(event, dict) else MISSING
        if isinstance(sub, dict):
            if val is MISSING or not match(sub, val):
                return False
        elif isinstance(sub, list):
            if not values_ok(sub, val):
                return False
        else:
            raise ValueError(f"pattern values must be arrays or objects at {key}")
    return True


def main(det_dir):
    det = pathlib.Path(det_dir)
    exp = json.loads((det / "samples" / "expectations.json").read_text())
    fails = 0
    for pat_file, cases in exp.items():
        pat = json.loads((det / pat_file).read_text())
        for want, files in (("match", cases.get("match", [])), ("nomatch", cases.get("nomatch", []))):
            for f in files:
                ev = json.loads((det / "samples" / f).read_text())
                got = match(pat, ev)
                ok = got == (want == "match")
                fails += not ok
                print(f"{'PASS' if ok else 'FAIL'}  {pat_file:55s} {f:40s} expected {want}")
    # every *.eventbridge.json must be valid JSON with array/object leaves
    for p in sorted(det.glob("*.eventbridge.json")):
        match(json.loads(p.read_text()), {})
    print(f"ebmatch: {fails} failure(s)")
    return fails


if __name__ == "__main__":
    sys.exit(1 if main(sys.argv[1] if len(sys.argv) > 1 else "detections") else 0)
