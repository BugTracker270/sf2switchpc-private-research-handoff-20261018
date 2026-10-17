"""Keep recovered scalar success separate from a witnessed allocation-type failure."""
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    run='nso-stack-headers-v11'
    raw=(ROOT/'analysis/nso/main-uncompressed.nso').read_bytes()
    def at(address,count):
        for header in (0x10,0x20,0x30):
            offset,rva,size=struct.unpack_from('<III',raw,header)
            if rva<=address and address+count<=rva+size:return raw[offset+address-rva:offset+address-rva+count]
        raise ValueError('Unmapped native witness')
    slot=struct.unpack('<Q',at(0x397b948,8))[0]
    script=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    names=[row['Name'] for row in script['ScriptMetadata'] if row['Address']==slot]
    if names!=['VersionContainer_TypeInfo']:raise ValueError('Native allocation metadata differs')
    if at(0xc4a68,16)!=bytes.fromhex('b5c501f0b5a644f9a00240f9a7592a94'):raise ValueError('Native allocation argument/call witness differs')
    direct=json.loads((ROOT/f'reports/recovered-scalars-{run}.json').read_text())
    witness=direct['separate_static_identity_witness']
    if not witness['tested'] or witness['actual']!='System.Object' or witness['matches']:raise ValueError('Expected independently observed allocation-type failure changed')
    source=ROOT/f'analysis/il2cpp/cpp2il-csharp-{run}/version/VersionContainer.decompiled.cs'
    text=source.read_text(encoding='utf-8-sig')
    if '(VersionContainer)new object()' not in text:raise ValueError('Preserved C# allocation evidence changed')
    method=None
    for line in (ROOT/f'analysis/il2cpp/cil-audit-{run}/Assembly-CSharp-firstpass.jsonl').open(encoding='utf-8'):
        row=json.loads(line)
        if row['type']=='VersionContainer' and row['name']=='.cctor':method=row;break
    if not method or 'System.Object::.ctor' not in method['call_targets']:raise ValueError('CIL base-constructor evidence changed')
    tool=ROOT/'refs/Cpp2IL/Cpp2IL.Core/IlGenerator.cs'
    report=dict(status='CONFIRMED_RECOVERED_ALLOCATION_TYPE_MISMATCH',recovery_run=run,
        native=dict(allocation_site='0xC4A74',allocator='0xB5B110',got='0x397B948',metadata_slot=hex(slot),metadata_name=names[0],base_ctor_site='0xC4AC8'),
        recovered=dict(static_field='VersionContainer.Zero',expected_runtime_type='VersionContainer',actual_runtime_type=witness['actual'],cil_constructor_targets=method['call_targets'],source_sha256=hashlib.sha256(source.read_bytes()).hexdigest()),
        source_supported_cause='The emitter fuses an allocation with a later constructor call on the same recovered receiver, without checking the allocated declaring type. This native static initializer contains an inlined derived constructor followed by System.Object::.ctor. The observed CIL instead allocates System.Object; runtime field identity independently confirms the mismatch.',
        tool_source_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(),
        required_research='Preserve native allocation type and inlined constructor/field-initializer order. Calling an extra managed constructor can duplicate side effects and is not accepted as a general repair.',
        scope='The eight scalar accessors pass 768 direct and isolated cases; that does not certify this static field or the whole class. Original game bytes are unchanged. This report records a failure, not a repaired allocation implementation.')
    destination(ROOT,ROOT/'reports/recovered-allocation-type-gap.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
