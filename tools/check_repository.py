#!/usr/bin/env python3
"""Check mapping completeness, JSON, local Markdown links and publishable text."""
import csv
import json
import os
from pathlib import Path
import re

from build_mappings import render

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE = {'.git', '.terraform', 'node_modules', '__pycache__', '.venv', '.build', 'build', 'dist', 'artifacts'}
files = [p for p in ROOT.rglob('*') if p.is_file() and not set(p.relative_to(ROOT).parts) & EXCLUDE]
errors = []
rows = list(csv.DictReader((ROOT/'mappings/detections.csv').open()))
expected = {(platform, f'{prefix}{i:02}') for platform, prefix in [('microsoft', 'D'), ('aws', 'A'), ('google', 'G')] for i in range(1, 16)}
actual = {(r['platform'], r['detection_id']) for r in rows}
if len(rows) != 45 or actual != expected:
    errors.append('Mappings must contain all 45 original catalogue IDs exactly once')
if (ROOT/'mappings/README.md').read_text() != render():
    errors.append('Run python3 tools/build_mappings.py to refresh the Markdown table')
for platform in ['microsoft', 'aws', 'google']:
    for p in (ROOT/platform/'detections').rglob('*'):
        match = re.match(r'([DAG]\d{2})', p.name)
        if p.is_file() and match and (platform, match[1]) not in actual:
            errors.append(f'Unmapped detection: {p.relative_to(ROOT)}')
    for row in (r for r in rows if r['platform'] == platform):
        found = list((ROOT/platform/'detections').rglob(row['detection_id']+'*'))
        if not found and 'S' not in row['source_status']:
            errors.append(f"Missing implementation: {platform}/{row['detection_id']}")
email = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
guard = os.environ.get('GUARD_PATTERN')
for path in files:
    rel = path.relative_to(ROOT)
    text = path.read_text()
    if path.suffix == '.json':
        json.loads(text)
    if chr(0x2014) in text:
        errors.append(f'{rel}: em dash')
    if path.name != 'SECURITY.md' and email.search(text):
        errors.append(f'{rel}: email address outside security contact')
    for value in re.findall(r'(?<![\d])\d{12}(?![\d])', text):
        if value != '0'*12 and path.name not in {'package-lock.json'}:
            errors.append(f'{rel}: non-placeholder account number')
    if guard and re.search(guard, text, re.I):
        errors.append(f'{rel}: content guard match')
    if path.suffix == '.md':
        for target in re.findall(r'\]\(([^\s)]+)\)', text):
            if re.match(r'^[a-z]+:', target) or target.startswith('#'):
                continue
            dest = (path.parent / target.split('#')[0]).resolve()
            if not dest.exists():
                errors.append(f'{rel}: missing local link {target}')
if errors:
    raise SystemExit('\n'.join(errors))
print(f'PASS: {len(files)} files; JSON, local links, text hygiene and 45 mapping rows')
