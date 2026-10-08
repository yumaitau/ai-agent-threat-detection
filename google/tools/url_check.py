#!/usr/bin/env python3
"""Fetch every documentation URL cited in the pack and report the HTTP status (needs internet; optional)."""
import glob
import os
import re
import subprocess
import sys

SKIP = ["example", "{", "api.greynoise.io/v3", "api.abuseipdb.com/api", "threatfox-api", "workflowexecutions.googleapis.com/",
        "compute.googleapis.com/compute", "admin.googleapis.com/admin", "iam.googleapis.com/v1", "cloudresourcemanager.googleapis.com/v3",
        "cloudasset.googleapis.com/v1", "www.googleapis.com/auth", "oauth2.googleapis.com", "gstatic.com", ".invalid/",
        "-aiplatform.googleapis.com/v1/"]
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
urls = set()
for f in glob.glob(os.path.join(root, "**/*"), recursive=True):
    if os.path.isfile(f) and ".terraform" not in f and not f.endswith((".json", ".zip", "validation.txt", "url_check.py")):
        try:
            text = open(f).read()
        except UnicodeDecodeError:
            continue
        for u in re.findall(r"https://[^\s)`\"'<>|,]+", text):
            u = u.rstrip(".)")
            if not any(s in u for s in SKIP):
                urls.add(u)
bad = 0
for u in sorted(urls):
    code = subprocess.run(["curl", "-s", "-o", "/dev/null", "-L", "-A", "Mozilla/5.0", "--max-time", "20", "-w", "%{http_code}", u],
                          capture_output=True, text=True).stdout
    bad += code != "200"
    print(f"{code} {u}")
print(f"{len(urls)} URLs, {bad} not 200")
sys.exit(1 if bad else 0)
