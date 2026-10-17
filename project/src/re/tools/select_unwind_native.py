"""Select only independently validated, unattempted exception-frame entries."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--batch',type=int,required=True);parser.add_argument('--limit',type=int,default=1000);args=parser.parse_args()
    if not 1<=args.batch<=999 or not 1<=args.limit<=5000:raise ValueError('Invalid bounded batch/count')
    manifest=json.loads((ROOT/'reports/native-unwind-inventory.json').read_text())
    if manifest['status']!='PASS_FRAME_RANGE_INVENTORY' or manifest['errors']:raise ValueError('Validated unwind inventory required')
    frame_file=ROOT/'analysis/nso/unwind-inventory-v1/frames.jsonl'
    if manifest.get('frames_file_sha256'):
        with frame_file.open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=manifest['frames_file_sha256']:raise ValueError('Validated frame entry file changed')
    name=f'unwind-v1-{args.batch:03d}';target=destination(ROOT,ROOT/f'analysis/nso/{name}-targets.json')
    if target.exists():raise ValueError('Preserve prior target selection')
    db=sqlite3.connect((ROOT/'analysis/nso/corpus.sqlite').as_uri()+'?mode=ro',uri=True)
    indexed=dict(db.execute('SELECT rva,status FROM functions'));db.close()
    selected=[];total=successful=failed=pending=0
    for line in frame_file.open(encoding='utf-8'):
        row=json.loads(line);rva=row['rva'];total+=1
        if rva in indexed:
            if indexed[rva]=='PSEUDOCODE_EXPORTED':successful+=1
            else:failed+=1
            continue
        pending+=1
        if len(selected)<args.limit:selected.append(dict(rva=rva,end_rva=row['end_rva'],name=f'NativeUnwind_{rva:08X}',signature='',preserve_prototype=True,
            unwind_fde_rva=row['fde_rva'],selection_scope='Original exception search-table entry agrees with its independently decoded FDE/CIE start and bounded text extent. Existing Ghidra prototype retained; no parameter types or behavior inferred.'))
    result=dict(status='SELECTED' if selected else 'NO_UNATTEMPTED_RANGES',batch=args.batch,total_validated_ranges=total,successful_indexed_ranges=successful,
        failed_indexed_ranges=failed,unattempted_ranges=pending,selected=len(selected),target=str(target.relative_to(ROOT)))
    target.write_text(json.dumps(selected,indent=2)+'\n',encoding='utf-8')
    destination(ROOT,ROOT/f'analysis/nso/{name}-selection.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,indent=2))
    if not selected:sys.exit(3)
if __name__=='__main__':main()
