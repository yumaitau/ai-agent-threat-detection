#!/usr/bin/env python3
"""Build tools/prelude.generated.kql for kqlcheck.js: a stub for Sentinel's _GetWatchlist() plus every pack
function as a let-statement, so queries that call them can be bound offline. The stub's columns are the union of
the two pack watchlists' columns (real _GetWatchlist returns watchlist columns as strings plus SearchKey)."""
import pathlib, re
root = pathlib.Path(__file__).resolve().parent.parent
order = ["YumaAIRegister", "YumaISMControlStatus", "YumaEvidenceRegisterCsv", "YumaEvidenceControlsCsv", "YumaEvidenceMarkdown"]
cols = set()
for f in (root / "deploy/register").glob("watchlist-*.csv"):
    cols.update(f.read_text().splitlines()[0].split(","))
stub_cols = ", ".join(f"['{c}']:string" for c in ["SearchKey"] + sorted(cols))
parts = [f"let _GetWatchlist = (alias:string) {{ datatable({stub_cols})[] }};"]
for name in order:
    body = (root / "functions" / f"{name}.kql").read_text()
    body = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("//"))
    parts.append(f"let {name} = () {{\n{body.strip()}\n}};")
out = root / "tools/prelude.generated.kql"
out.write_text("\n".join(parts) + "\n")
print("wrote", out, "lines:", len(out.read_text().splitlines()))
