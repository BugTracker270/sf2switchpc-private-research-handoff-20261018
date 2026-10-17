"""Keep scoped ILSpy type failures distinct from successful export exit codes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',default='nso-stack-headers-v11');args=parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+',args.run):raise ValueError('Invalid recovery run')
    folder=ROOT/('analysis/il2cpp/cpp2il-csharp-'+args.run);results=[];empty=[]
    for path in sorted(folder.rglob('*.cs')):
        text=path.read_text(encoding='utf-8-sig');warnings=[]
        if not text.strip():empty.append(str(path.relative_to(ROOT)));continue
        for i,line in enumerate(text.splitlines(),1):
            if '//IL_' in line and ('Expected ' in line or 'Unknown result type' in line):warnings.append(dict(line=i,message=line.strip()))
        results.append(dict(path=str(path.relative_to(ROOT)),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            type_warnings=len(warnings),warning_locations=warnings,recovery_diagnostic_calls=text.count('NoteDecompilerIssue('),
            suspicious_base_constructor_syntax=bool(re.search(r'\bbase\.\.ctor\(',text)),
            suspected_exception_as_array=bool(re.search(r'\(int\[\]\).*new OverflowException\(',text)),
            recovered_int_array_allocations=len(re.findall(r'new int\[',text))))
    if len(results)!=2:raise ValueError('Expected both preserved scoped VersionContainer/Triangle exports')
    report=dict(recovery_run=args.run,status='TYPE_OR_RECOVERY_LIMITATIONS_CONFIRMED' if any(r['type_warnings'] or r['recovery_diagnostic_calls'] for r in results) else 'SCOPED_SOURCE_REQUIRES_COMPILER_VALIDATION',
        files=results,empty_export_paths=empty,warning_total=sum(r['type_warnings'] for r in results),buildable_game_source=False,
        scope='ILSpy exit zero confirms an export attempt, not valid C# or verifiable CIL. Commented operand-type failures are recorded even in methods without injected helper calls. No compilation or whole-game source-correctness claim.')
    lock=json.loads((ROOT/'reports/cpp2il-corrections-lock.json').read_text(encoding='utf-8-sig'))
    if lock.get('recovery_run')==args.run:
        destination(ROOT,ROOT/'reports/scoped-csharp-type-audit.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    destination(ROOT,ROOT/('analysis/il2cpp/scoped-csharp-type-audit-'+args.run+'.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=report['status'],files=len(results),warnings=report['warning_total'])))
if __name__=='__main__':main()
