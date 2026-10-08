#!/usr/bin/env python3
"""Offline lint for CloudWatch Logs Insights queries (no official offline parser exists).
Checks per query: known commands, balanced brackets/quotes/regex, documented functions only, and every field is
either a documented field of the log source named in the file header, a Logs Insights system field (@...), or a
name the query defines (as, parse named groups, glob parse targets, lookup OUTPUT fields).
Files may hold several queries separated by lines starting with '# --- query'.
Docs: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html"""
import pathlib
import re
import sys

COMMANDS = {"fields", "filter", "stats", "sort", "limit", "parse", "display", "dedup", "unmask", "unnest", "lookup",
            "pattern", "diff", "filterindex", "source", "anomaly"}
FUNCTIONS = {"count", "countdistinct", "sum", "avg", "min", "max", "earliest", "latest", "pct", "stddev", "bin",
             "coalesce", "isempty", "isblank", "ispresent", "strcontains", "tolower", "toupper", "concat", "strlen",
             "substr", "replace", "trim", "ltrim", "rtrim", "abs", "ceil", "floor", "greatest", "least", "datefloor",
             "dateceil", "fromMillis".lower(), "toMillis".lower(), "jsonparse", "isvalidip", "isipv4insubnet"}
KEYWORDS = {"as", "by", "and", "or", "not", "like", "in", "desc", "asc", "output", "outputnew", "m", "h", "s", "d"}
SOURCES = {
    "route53": {"version", "account_id", "region", "vpc_id", "resource_id", "query_timestamp", "query_name", "query_type",
                "query_class", "rcode", "answer_type", "rdata", "answer_class", "answers", "srcaddr", "srcport", "transport",
                "srcids", "srcids.instance", "srcids.resolver_endpoint", "firewall_rule_group_id", "firewall_rule_action",
                "firewall_domain_list_id"},
    "bedrock": {"schematype", "schemaversion", "timestamp", "accountid", "region", "requestid", "operation", "modelid",
                "identity.arn", "requestmetadata", "input.inputcontenttype", "input.inputbodyjson", "input.inputtokencount",
                "output.outputcontenttype", "output.outputbodyjson", "output.outputtokencount"},
    "waf": {"timestamp", "action", "terminatingruleid", "terminatingruletype", "httpsourcename", "httpsourceid",
            "httprequest.clientip", "httprequest.country", "httprequest.uri", "httprequest.httpmethod", "httprequest.headers",
            "httprequest.args", "httprequest.httpversion", "httprequest.requestid", "labels", "ja3fingerprint", "ja4fingerprint",
            "rulegrouplist", "ratebasedrulelist", "nonterminatingmatchingrules", "webaclid", "responsecodesent", "requestid"},
    "cloudtrail": {"eventsource", "eventname", "eventtime", "sourceipaddress", "useragent", "errorcode", "awsregion",
                   "recipientaccountid", "eventcategory", "eventtype"},
}
PREFIXES = {"cloudtrail": ("requestparameters.", "responseelements.", "additionaleventdata.", "useridentity.", "resources.")}
DOCS = {"route53": "resolver-query-logs-format.html", "bedrock": "model-invocation-logging.html",
        "waf": "logging-fields.html", "cloudtrail": "understanding-gateway-cloudtrail-log-entries.html"}


def source_of(text):
    head = "\n".join(l for l in text.splitlines() if l.startswith("#"))
    for k, marker in DOCS.items():
        if marker in head:
            return k
    return None


def strip_literals(q):
    q = re.sub(r'"(?:[^"\\]|\\.)*"', ' "S" ', q)
    q = re.sub(r"'(?:[^'\\]|\\.)*'", " 'S' ", q)
    q = re.sub(r"(?<=[\s(,])/(?:[^/\\\n]|\\.)+/", " /R/ ", q)
    return q


def lint_query(q, src):
    errs = []
    orig = q
    defined = set()
    for m in re.finditer(r"\(\?<(\w+)>", orig):
        defined.add(m.group(1).lower())
    for m in re.finditer(r"\bas\s+([A-Za-z_@][\w.@]*)", orig):
        defined.add(m.group(1).lower())
    for m in re.finditer(r"\bOUTPUT(?:NEW)?\s+([\w\s,]+)", orig):
        defined |= {x.strip().lower() for x in m.group(1).split(",") if x.strip()}
    for m in re.finditer(r"^\s*\|?\s*parse\s+\S+\s+'[^']*'\s+as\s+([\w\s,]+)", orig, re.M):
        defined |= {x.strip().lower() for x in m.group(1).split(",")}
    for m in re.finditer(r"^\s*\|?\s*lookup\s+(\w+)\s+([\w\s,]+?)\s+OUTPUT", orig, re.M):
        defined.add(m.group(1).lower())
        defined |= {x.strip().lower() for x in m.group(2).split(",")}
    q = strip_literals(q)
    for opener, closer in ("()", "[]"):
        if q.count(opener) != q.count(closer):
            errs.append(f"unbalanced {opener}{closer}")
    if q.count('"') % 2 or q.count("'") % 2:
        errs.append("unbalanced quotes")
    stages = [s.strip() for s in re.split(r"\n\s*\|", "\n" + q.strip()) if s.strip()]
    for st in stages:
        cmd = st.split()[0].lower()
        if cmd not in COMMANDS:
            errs.append(f"unknown command '{cmd}'")
    for m in re.finditer(r"([A-Za-z_]\w*)\s*\(", q):
        fn = m.group(1).lower()
        if fn not in FUNCTIONS and fn not in COMMANDS and fn not in KEYWORDS:
            errs.append(f"undocumented function '{m.group(1)}'")
    if src:
        allowed = SOURCES[src]
        for st in stages:
            body = st.split(None, 1)[1] if len(st.split(None, 1)) > 1 else ""
            if st.split()[0].lower() in ("lookup",):
                continue
            for m in re.finditer(r"(?<![\w@.])([A-Za-z_][\w]*(?:\.[\w]+)*)", body):
                name = m.group(1)
                low = name.lower()
                if body[m.end():].lstrip().startswith("("):
                    continue  # function call
                if name in ("R", "S"):
                    continue  # placeholders for stripped literals
                if low in KEYWORDS or low in defined or re.fullmatch(r"\d+[mhsd]?", low):
                    continue
                if low in allowed or low.startswith(PREFIXES.get(src, ("\0",))):
                    continue
                if low.split(".")[0] in allowed and src == "bedrock" and low.startswith("requestmetadata."):
                    continue
                errs.append(f"field '{name}' is not documented for source '{src}'")
    return errs


def main(files):
    bad = 0
    for f in files:
        text = pathlib.Path(f).read_text()
        src = source_of(text)
        queries = re.split(r"^# --- query.*$", text, flags=re.M)
        errs = []
        n = 0
        for chunk in queries:
            q = "\n".join(l for l in chunk.splitlines() if not l.lstrip().startswith("#")).strip()
            if not q:
                continue
            n += 1
            errs += [f"q{n}: {e}" for e in lint_query(q, src)]
        bad += bool(errs)
        print(f"{'PASS' if not errs else 'FAIL'}  {f}  ({n} quer{'y' if n == 1 else 'ies'}, source={src})")
        for e in sorted(set(errs)):
            print(f"        {e}")
    print(f"lilint: {bad} file(s) failed of {len(files)}")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main(sys.argv[1:]) else 0)
