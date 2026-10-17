"""Refresh export coverage of validated unwind entries without a semantic claim."""
import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    inventory=json.loads((ROOT/'reports/native-unwind-inventory.json').read_text())
    if inventory['status']!='PASS_FRAME_RANGE_INVENTORY' or inventory['errors']:raise ValueError('Validated frame inventory required')
    source=ROOT/'analysis/nso/unwind-inventory-v1/frames.jsonl'
    with source.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    prior=inventory.get('frames_file_sha256')
    if prior and prior!=digest:raise ValueError('Preserved unwind entry file changed')
    if not prior:
        inventory['frames_file_sha256']=digest
        for path in (ROOT/'reports/native-unwind-inventory.json',ROOT/'analysis/nso/unwind-inventory-v1/summary.json'):
            destination(ROOT,path).write_text(json.dumps(inventory,indent=2)+'\n',encoding='utf-8')
    frames=[json.loads(line) for line in source.open(encoding='utf-8')]
    if len(frames)!=inventory['validated_records'] or len({row['rva'] for row in frames})!=inventory['unique_range_starts']:raise ValueError('Frame inventory cardinality changed')
    db=sqlite3.connect((ROOT/'analysis/nso/corpus.sqlite').as_uri()+'?mode=ro',uri=True)
    indexed=dict(db.execute('SELECT rva,status FROM functions'));db.close()
    passed=[row for row in frames if indexed.get(row['rva'])=='PSEUDOCODE_EXPORTED']
    failed=[row for row in frames if row['rva'] in indexed and indexed[row['rva']]!='PSEUDOCODE_EXPORTED']
    pending=[row for row in frames if row['rva'] not in indexed]
    report=dict(status='UNWIND_RANGE_EXPORT_COMPLETE' if not failed and not pending else 'IN_PROGRESS',utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        validated_ranges=len(frames),ranges_with_pseudocode=len(passed),failed_ranges=len(failed),unattempted_ranges=len(pending),
        exported_range_bytes=sum(row['end_rva']-row['rva'] for row in passed),validated_range_bytes=inventory['covered_text_bytes'],
        indexed_native_records=len(indexed),frame_file_sha256=digest,source_nso_sha256=inventory['source_sha256'],
        full_semantic_reverse_engineering='NOT_COMPLETE',
        scope='Exact-entry pseudocode export coverage of independently validated, nonoverlapping exception-frame code ranges. Extra native entries, residual text, actual CFI/LSDA behavior, operand types and all game/engine semantics remain separate. Exported range bytes are not verified source or behavior coverage.')
    destination(ROOT,ROOT/'reports/native-unwind-recovery.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
