#!/usr/bin/env python3
"""Check every https URL cited in the pack's markdown, SQL, JSON and Python files returns HTTP 200.
Needs network. Usage: python3 tools/urlcheck.py"""
import pathlib, re, sys, urllib.request, concurrent.futures as cf
ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_HOSTS = ("api.greynoise.io", "api.abuseipdb.com", "threatfox-api.abuse.ch", "hooks.slack.com", "example")
urls = set()
for f in ROOT.rglob("*"):
    if f.is_file() and f.suffix in {".md", ".sql", ".json", ".py", ".logsinsights", ".csv", ".yaml", ".tf"} and ".terraform" not in f.parts and f.name != "urlcheck.py":
        for u in re.findall(r"https://[^\s)\"'`>,|\]]+", f.read_text(errors="ignore")):
            u = u.rstrip(".;:")
            if not any(h in u for h in SKIP_HOSTS) and "{" not in u and "<" not in u:
                urls.add(u)
def check(u):
    try:
        req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            final = r.geturl().split("#")[0].rstrip("/")
            if r.status == 200 and final != u.split("#")[0].rstrip("/"):
                return u, "redirected to " + final
            return u, r.status
    except Exception as e:
        return u, getattr(e, "code", str(e)[:60])
bad = 0
with cf.ThreadPoolExecutor(8) as ex:
    for u, st in sorted(ex.map(check, sorted(urls))):
        ok = st == 200
        bad += not ok
        print(("OK  " if ok else "BAD ") + str(st) + " " + u)
print(f"{len(urls)} URLs, {bad} not 200")
sys.exit(1 if bad else 0)
