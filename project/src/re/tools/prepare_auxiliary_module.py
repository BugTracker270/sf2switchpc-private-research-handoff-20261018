"""Prepare a bounded independent auxiliary-module corpus; never mix its RVAs with main."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--module',choices=['rtld','sdk','subsdk0'],required=True)
    parser.add_argument('--limit',type=int,default=500);args=parser.parse_args()
    if not 1<=args.limit<=5000:raise ValueError('Invalid bounded pilot size')
    manifest=json.loads((ROOT/'reports/native-module-inventory.json').read_text(encoding='utf-8-sig'))
    module=manifest['modules'][args.module]
    if manifest['status']!='PASS_SUPPLIED_MODULE_IMAGES_AND_SEGMENT_HASHES' or module['unwind']['errors']:raise ValueError('Verified module image/range inventory required')
    raw=ROOT/f'analysis/nso/{args.module}-uncompressed.nso'
    if hashlib.sha256(raw.read_bytes()).hexdigest()!=module['uncompressed_sha256']:raise ValueError('Original uncompressed module image changed')
    frames=ROOT/f'analysis/nso/module-inventory-v2/{args.module}-frames.jsonl'
    rows=list(map(json.loads,frames.open(encoding='utf-8')))
    if len(rows)!=module['unwind']['validated_ranges']:raise ValueError('Frame inventory cardinality changed')
    selected=rows
    folder=destination(ROOT,ROOT/f'analysis/nso/auxiliary-{args.module}-v1')
    if folder.exists():raise ValueError('Preserve prior auxiliary module experiment')
    folder.mkdir()
    targets=[dict(module=args.module,rva=row['rva'],end_rva=row['end_rva'],unwind_fde_rva=row['fde_rva'],
        name=f'Auxiliary_{args.module}_{row["rva"]:08X}',signature='',preserve_prototype=True,
        selection_scope='Independent supplied-module frame entry; no managed prototype or behavior inferred.') for row in selected]
    destination(ROOT,folder/'targets.json').write_text(json.dumps(targets,indent=2)+'\n',encoding='utf-8')
    report=dict(module=args.module,status='BOUNDED_AUXILIARY_TARGETS_PREPARED',total_validated_ranges=len(rows),selected=len(targets),
        original_source_sha256=module['source_sha256'],uncompressed_sha256=module['uncompressed_sha256'],
        frame_file_sha256=hashlib.sha256(frames.read_bytes()).hexdigest(),
        maximum_new_exports_per_pass=args.limit,
        scope='Separate module address space/corpus; full validated target inventory with bounded incremental export passes. This is not complete clean module source. Do not ingest auxiliary RVAs into the main-only index.')
    destination(ROOT,folder/'selection.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
