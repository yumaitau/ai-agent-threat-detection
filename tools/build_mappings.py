#!/usr/bin/env python3
"""Render the combined Markdown table from the source-preserving CSV."""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTRO = '''# Detection mappings

[Download the combined CSV](detections.csv). Each of the 45 original catalogue IDs has one row, including draft hunts and specifications. Multiple query formats share their original detection ID.

The agentic ISM column contains only ISM-2133 to ISM-2140 and ISM-2156 to ISM-2159 where the source pack supplied them. The next column preserves all source ISM mappings. `None supplied` means the source did not map that detection to that framework or range. No new control or technique IDs have been inferred. ATLAS IDs have the `AML.` prefix expanded consistently.

These are inherited mappings, not an independent assessment or proof that a control is met. Essential Eight entries describe supporting detective coverage. The source packs cite the September 2026 ISM catalogue, MITRE ATLAS v5.6.0, OWASP LLM Top 10 2025 and OWASP Agentic Top 10 2026. Confirm applicability for your assessment.

Source status is retained: Microsoft R means a rule candidate, H a hunt and S a specification; AWS R means an implemented query, R+ also marks a priority or fixture-tested detection, and S a specification; Google R means a rule candidate, H a hunt and S a specification. None of these labels means live validation.

'''
HEADERS = ['Platform', 'ID', 'Detection', 'Agentic ISM controls', 'All source ISM controls', 'Essential Eight', 'MITRE ATLAS', 'ATT&CK', 'OWASP LLM / Agentic', 'Source status']

def render():
    with (ROOT/'mappings/detections.csv').open() as stream:
        rows = list(csv.reader(stream))[1:]
    escape = lambda cell: cell.replace('|', r'\|').replace('\n', ' ')
    lines = ['| ' + ' | '.join(HEADERS) + ' |', '| ' + ' | '.join(['---']*len(HEADERS)) + ' |']
    lines += ['| ' + ' | '.join(map(escape, row)) + ' |' for row in rows]
    return INTRO + '\n'.join(lines) + '\n'

if __name__ == '__main__':
    (ROOT/'mappings/README.md').write_text(render())
