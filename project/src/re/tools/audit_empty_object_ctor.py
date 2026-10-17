"""Validate removal of a witnessed native no-op without claiming general constructor equivalence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
from native_unwind_inventory import Image
ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',required=True);args=parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+',args.run):raise ValueError('Invalid run')
    raw=(ROOT/'analysis/nso/main-uncompressed.nso').read_bytes();image=Image(raw)
    data=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    constructor=[row for row in data['ScriptMethod'] if row['Name']=='System.Object$$.ctor']
    if len(constructor)!=1 or constructor[0]['Address']!=0x65a2a0 or image.read(0x65a2a0,4)!=bytes.fromhex('c0035fd6'):
        raise ValueError('Expected original Object constructor metadata/immediate return changed')
    word=struct.unpack('<I',image.read(0xc4ac8,4))[0]
    displacement=word&0x3ffffff
    if displacement&(1<<25):displacement-=1<<26
    if word&0xfc000000!=0x94000000 or 0xc4ac8+displacement*4!=0x65a2a0:raise ValueError('Original initializer base-constructor call changed')
    rows=[row for row in map(json.loads,(ROOT/f'analysis/il2cpp/cil-audit-{args.run}/Assembly-CSharp-firstpass.jsonl').open(encoding='utf-8')) if row['type']=='VersionContainer']
    initializer=next(row for row in rows if row['name']=='.cctor')
    retained=[row for row in rows if row['name']=='.ctor' and 'System.Object::.ctor' in row['call_targets']]
    if 'System.Object::.ctor' in initializer['call_targets'] or not retained:raise ValueError('Expected constructor-context boundary is not preserved')
    report=dict(status='PASS_SCOPED_PROVEN_NOOP_CTOR_REMOVAL',recovery_run=args.run,
        source_nso_sha256=hashlib.sha256(raw).hexdigest(),native_object_ctor='0x65A2A0',native_cctor_call_site='0xC4AC8',
        instruction='RET X30',recovered_static_initializer_no_longer_calls_object_ctor=True,instance_constructors_retaining_object_ctor=len(retained),
        scope='Only an original immediate-return Object constructor called outside a managed instance constructor is omitted. Ordinary constructor calls remain; allocation identity and complete initialization/source-build gates are independent. This witness covers VersionContainer, not all constructor contexts.')
    destination(ROOT,ROOT/f'reports/recovered-empty-object-ctor-{args.run}.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
