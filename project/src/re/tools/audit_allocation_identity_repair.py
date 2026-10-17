"""Correlate native allocation identity with a fresh recovered static-field witness."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',required=True)
    parser.add_argument('--harness-log',default='logs/cpp2il-allocation-identity-v13-tests.log')
    parser.add_argument('--source-kind',choices=['scoped','source-profile-project-build'],default='scoped')
    args=parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+',args.run):raise ValueError('Invalid recovery run')
    baseline=json.loads((ROOT/'reports/recovered-allocation-type-gap.json').read_text(encoding='utf-8-sig'))
    direct=json.loads((ROOT/f'reports/recovered-scalars-{args.run}.json').read_text(encoding='utf-8-sig'))
    harness=json.loads(destination(ROOT,ROOT/args.harness_log).read_text(encoding='utf-8-sig'))
    if harness['failed'] or harness['allocation_emission_checks']!=4:raise ValueError('Separate-allocation emission checks did not pass')
    raw=(ROOT/'analysis/nso/main-uncompressed.nso').read_bytes()
    def at(address,count):
        for header in (0x10,0x20,0x30):
            offset,rva,size=struct.unpack_from('<III',raw,header)
            if rva<=address and address+count<=rva+size:return raw[offset+address-rva:offset+address-rva+count]
        raise ValueError('Unmapped native witness')
    if at(0xc4a68,16)!=bytes.fromhex('b5c501f0b5a644f9a00240f9a7592a94') or struct.unpack('<Q',at(0x397b948,8))[0]!=0x3b35180:
        raise ValueError('Native allocation witness changed')
    method=next((row for row in map(json.loads,(ROOT/f'analysis/il2cpp/cil-audit-{args.run}/Assembly-CSharp-firstpass.jsonl').open(encoding='utf-8')) if row['type']=='VersionContainer' and row['name']=='.cctor'),None)
    if method is None:raise ValueError('Missing recovered initializer audit')
    witness=direct['separate_static_identity_witness']
    allocated='System.Runtime.Serialization.FormatterServices::GetUninitializedObject' in method['call_targets']
    matches=witness['tested'] and witness['matches'] and allocated
    source=ROOT/f'analysis/il2cpp/cpp2il-csharp-{args.run}/version/VersionContainer.decompiled.cs'
    if args.source_kind=='source-profile-project-build':
        source=ROOT/f'analysis/il2cpp/source-profile-project-build-{args.run}/Assembly-CSharp-firstpass/VersionContainer.cs'
    report=dict(status='PASS_STATIC_ALLOCATION_IDENTITY_ONLY' if matches else 'ALLOCATION_IDENTITY_REPAIR_FAILED',recovery_run=args.run,
        native=baseline['native'],baseline_run=baseline['recovery_run'],baseline_actual_type=baseline['recovered']['actual_runtime_type'],
        recovered_runtime_identity=witness,explicit_uninitialized_allocation=allocated,cil_call_targets=method['call_targets'],
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),synthetic_allocation_emission_checks=harness['allocation_emission_checks'],
        policy='Fuse only an adjacent constructor of the exact allocated type in the same basic block. Otherwise preserve separate reference allocation and later initialization/calls; no invented parameterless constructor.',
        api_reference='https://learn.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatterservices.getuninitializedobject?view=netframework-4.8.1',
        scope='Confirms the independently witnessed native allocation type in one recovered static field, plus a synthetic emitted-CIL constructor/field-initializer test. Complete initialization order, managed class initialization, special runtime types, exception behavior and whole-game source compilation remain separate gates. This is an explicit recovery lowering, not recovered original C# syntax.')
    destination(ROOT,ROOT/f'reports/recovered-allocation-identity-{args.run}.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2));return 0 if matches else 2
if __name__=='__main__':raise SystemExit(main())
