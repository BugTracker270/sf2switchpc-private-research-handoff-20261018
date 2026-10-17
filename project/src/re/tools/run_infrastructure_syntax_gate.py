"""Parse every original Python source in the three authorized source/test trees."""
import ast
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--report-label', default='v32')
args = parser.parse_args()
if not re.fullmatch('[a-z0-9-]+', args.report_label):
    parser.error('Only lowercase report labels are allowed')

inventory = subprocess.run(['rg', '--files', '--hidden', '--no-ignore', '-g', '*.py', 'src/tools', 'src/re/tools', 'tests'],
                          cwd=ROOT, check=True, capture_output=True, text=True, encoding='utf-8')
rows = []
for relative in sorted(set(inventory.stdout.splitlines())):
    path = destination(ROOT, ROOT / relative)
    raw = path.read_bytes()
    error = None
    try:
        ast.parse(raw, filename=relative)
    except (SyntaxError, UnicodeError) as problem:
        error = dict(kind=type(problem).__name__, message=str(problem))
    rows.append(dict(path=relative.replace('\\', '/'), sha256=hashlib.sha256(raw).hexdigest(), passed=error is None, error=error))
failures = sum(not row['passed'] for row in rows)
report = dict(status='PASS_ORIGINAL_PYTHON_SYNTAX' if failures == 0 else 'FAIL_ORIGINAL_PYTHON_SYNTAX',
              files=len(rows), failures=failures, scope=['src/tools', 'src/re/tools', 'tests'],
              source_execution=False, tests=rows)
destination(ROOT, ROOT / f'reports/{args.report_label}-infrastructure-python-syntax.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(f'Python AST syntax: {len(rows) - failures}/{len(rows)} files; {failures} errors')
if failures:
    raise SystemExit(1)
