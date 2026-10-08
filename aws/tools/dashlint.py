#!/usr/bin/env python3
"""Lint the Logs Insights queries inside register/cloudwatch-dashboard.json with tools/lilint.py.
Dashboard log widgets use "SOURCE '<log group>' | ..." (CloudWatch dashboard body structure:
https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Dashboard-Body-Structure.html).
The log source for field checks is taken from the widget title prefix."""
import json, pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import lilint
ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = {"A01": "route53", "A02": "bedrock", "A11": "cloudtrail", "A13": "waf", "A14": "waf"}
d = json.loads((ROOT / "register/cloudwatch-dashboard.json").read_text())
bad = n = 0
for w in d["widgets"]:
    if w["type"] != "log":
        continue
    n += 1
    p = w["properties"]
    m = re.match(r"\s*SOURCE\s+'[^']+'\s*\|\s*(.*)$", p["query"], re.S)
    if not m:
        print(f"FAIL  {p['title']}: missing SOURCE '<log group>' | prefix"); bad += 1; continue
    q = re.sub(r"\s\|\s", "\n| ", m.group(1))
    src = SRC.get(p["title"].split()[0])
    errs = lilint.lint_query(q, src)
    for k in ("region", "view"):
        if k not in p:
            errs.append(f"missing property {k}")
    bad += bool(errs)
    print(f"{'PASS' if not errs else 'FAIL'}  {p['title']}  (source={src})")
    for e in errs:
        print("        " + e)
print(f"dashlint: {bad} widget(s) failed of {n} log widgets")
sys.exit(1 if bad else 0)
