"""Report actual complete-source compiler outcomes without conflating export and correctness."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',required=True)
    parser.add_argument('--kind',choices=['source-build','source-project-build','source-profile-project-build','source-reference-check','source-legacy-reference-check','source-profile-legacy-reference-check'],default='source-build');args=parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+',args.run):raise ValueError('Invalid recovery run')
    folder=ROOT/f'analysis/il2cpp/{args.kind}-{args.run}'
    state=json.loads((folder/'result.json').read_text(encoding='utf-8-sig'));rows=[]
    if state['status']=='IN_PROGRESS' or len(state['assemblies'])!=2:raise ValueError('Source-build experiment has not completed')
    for row in state['assemblies']:
        name=row['assembly'];base=destination(ROOT,Path(row['folder']))
        sources=[dict(path=str(path.relative_to(ROOT)),bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(base.rglob('*.cs')) if 'obj' not in path.relative_to(base).parts]
        codes=collections.Counter();unique=set();occurrences=0
        log=destination(ROOT,ROOT/row.get('compiler_log',f'logs/source-build-{args.run}-{name}.log'))
        if log.exists():
            for line in log.read_text(encoding='utf-8-sig',errors='replace').splitlines():
                found=re.search(r': error (CS\d+|[A-Z]+\d+):',line)
                if found:
                    occurrences+=1
                    normalized=re.sub(r'^\d+>','',line.lstrip()).strip()
                    if normalized not in unique:unique.add(normalized);codes[found.group(1)]+=1
        rows.append(dict(**row,source_files=sources,unique_compiler_diagnostic_lines=len(unique),compiler_error_line_occurrences=occurrences,error_codes=dict(codes),build_log=str(log.relative_to(ROOT)) if log.exists() else None))
    report=dict(status=state['status'],recovery_run=args.run,experiment=args.kind,assemblies=rows,whole_game_source_ready=False,
        scope=state['scope']+' Compiler diagnostic lines are deduplicated across repeated build summaries; counts are not independent root causes or a completeness percentage. Successful compilation alone would not clear helper/placeholder/ABI/behavior gates.')
    destination(ROOT,ROOT/f'reports/recovered-{args.kind}-{args.run}.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=report['status'],assemblies=[dict(name=r['assembly'],build_exit_code=r['build_exit_code'],unique_errors=r['unique_compiler_diagnostic_lines'],error_codes=r['error_codes']) for r in rows]),indent=2))
if __name__=='__main__':main()
