"""Recheck a small native/metadata mapping and the demonstrated legacy ABI fix."""
import ctypes
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

class HitLayout(ctypes.Structure):
    _fields_=[('klass',ctypes.c_uint64),('monitor',ctypes.c_uint64),('frame',ctypes.c_int32),
      ('attack_interval_id',ctypes.c_int32),('head',ctypes.c_uint8),('block',ctypes.c_uint8),
      ('critical',ctypes.c_uint8),('last',ctypes.c_uint8),('damage',ctypes.c_float)]

def main():
    records={}
    with (ROOT/'analysis'/'nso'/'native-corpus'/'functions.jsonl').open() as stream:
        for line in stream:
            item=json.loads(line)
            if item['rva'] in (0xf968c0,0xf968d0,0xf61910):records[item['rva']]=item
            if len(records)==3:break
    checks=[]
    for rva,mask,name in ((0xf968c0,0xbd400000,'damage_getter'),(0xf968d0,0xbd000000,'damage_setter')):
        record=records[rva]
        fields=record['assembly'].splitlines()[0].split('\t')
        word=int.from_bytes(bytes.fromhex(fields[1]),'little')
        assert word&0xffc00000==mask,'Unexpected memory operation'
        assert (word&31)==0 and ((word>>5)&31)==0,'Expected S0 and X0'
        offset=((word>>10)&4095)*4
        assert offset==HitLayout.damage.offset==0x1c,'Native/metadata layout mismatch'
        assert 'ret' in record['assembly'] and record['body_bytes']==8
        checks.append(dict(name=name,status='PASS_STATIC_NATIVE_METADATA_MATCH',native_address=record['native_address'],field_offset=hex(offset)))
    connection=sqlite3.connect(ROOT/'analysis'/'il2cpp'/'research.sqlite')
    signature=connection.execute('SELECT signature FROM methods WHERE name=?',('System.String$$op_Equality',)).fetchone()[0]
    assert 'Il2CppObject* __this, System_String_o* a, System_String_o* b' in signature
    native=records[0xf61910]
    assert '71003dd5e0' in native['assembly'].lower(),'Expected static string equality call'
    before=(ROOT/'analysis'/'il2cpp'/'cpp2il-csharp-samples'/'Nekki.SF2.Core.Utils.ModifiedAlignFormula.decompiled.cs').read_text(encoding='utf-8-sig')
    after=(ROOT/'analysis'/'il2cpp'/'cpp2il-csharp-legacy-samples'/'Nekki.SF2.Core.Utils.ModifiedAlignFormula.decompiled.cs').read_text(encoding='utf-8-sig')
    assert 'null == damageAttribute.Name' in before
    assert 'damageAttribute.Name == name' in after
    checks.append(dict(name='legacy_static_argument_sample',status='PASS_SCOPED_CORRECTION',
        native_address=native['native_address'],comparison='Original recovery lost caller argument; patched recovery retains the name argument used by native string equality.',
        limitation='Many unresolved-memory/IL issues remain. This test does not certify other methods.'))
    report=dict(passed=len(checks),failed=0,validation='STATIC_ONLY',checks=checks,
        corpus=str(ROOT/'analysis'/'nso'/'native-corpus'/'functions.jsonl'))
    destination(ROOT,ROOT/'reports'/'native-mapping-tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    connection.execute('''INSERT INTO contradictions(topic,hypothesis_a,hypothesis_b,resolution,status) VALUES(?,?,?,?,?)''',
        ('ModifiedAlignFormula.GetDamAttribute argument','Upstream Cpp2IL compares Name against null',
         'Native static string equality receives item.Name and caller name',
         'IL2CPP <=24 ARM64 static dummy object slot was omitted; local patch corrects this sample','RESOLVED_FOR_SAMPLE'))
    for rva in (0xf968c0,0xf968d0):
        connection.execute('UPDATE methods SET semantic_status=? WHERE rva=?',('STATIC_LEAF_ACCESSOR_VALIDATED',rva))
        connection.execute('INSERT INTO evidence(method_id,kind,source,address,observation,confidence) SELECT id,?,?,?,?,? FROM methods WHERE rva=?',
          ('native_layout_match','native-mapping-tests.json',f'0x{0x7100000000+rva:X}','S0 load/store at object offset 0x1c; ret; matches metadata float field','HIGH_STATIC',rva))
    connection.commit();connection.close()
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
