"""Validate two small native control-flow predicates from ARM64 instruction bytes."""
import json
from pathlib import Path
import re
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def signed(value,bits):return value-(1<<bits) if value&(1<<(bits-1)) else value
def instructions(record):
    return [(int(fields[0],16)-0x7100000000,int.from_bytes(bytes.fromhex(fields[1]),'little'))
        for fields in (line.split('\t') for line in record['assembly'].splitlines())]

def main():
    wanted={0xe57190,0xd94fd0};records={}
    for row in map(json.loads,(ROOT/'analysis/nso/native-corpus/functions.jsonl').open(encoding='utf-8')):
        if row['rva'] in wanted:records[row['rva']]=row
    fixed=instructions(records[0xe57190]);assert len(fixed)==5
    assert fixed[0][1]==0xf9404000 # LDR X0,[X0,#0x80]: this._Fight.
    pc,cbz=fixed[1];assert cbz&0xff00001f==0xb4000000
    assert pc+signed((cbz>>5)&0x7ffff,19)*4==fixed[4][0]
    assert fixed[2][1]==0xaa1f03e1 # Hidden instance MethodInfo* argument cleared.
    pc,branch=fixed[3];assert branch&0xfc000000==0x14000000
    target=pc+signed(branch&0x3ffffff,26)*4
    assert target==0xc9dd50 and fixed[4][1]==0xd65f03c0
    predicate=instructions(records[0xd94fd0])
    targets=[pc+signed(word&0x3ffffff,26)*4 for pc,word in predicate if word&0xfc000000==0x94000000]
    assert targets==[0xf3cc90,0xf3cef0]
    assert predicate[7][1]==0x7100041f # CMP W0,#1
    assert predicate[8][1]==0x1a9fd7e0 # CSET W0,GT
    assert predicate[-1][1]==0xd65f03c0
    script=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    by_name={r['Name']:r['Address'] for r in script['ScriptMethod']}
    for name,address in [('Nekki.SF2.Core.Fights.Fight$$Draw',target),
        ('Nekki.SF2.Core.InputControllers.GamePadController$$get_Current',targets[0]),
        ('Nekki.SF2.Core.InputControllers.GamePadController$$get_DevicesCount',targets[1])]:
        assert by_name[name]==address
    recovered=(ROOT/'analysis/il2cpp/cpp2il-csharp-nso-metadata/Assembly-CSharp/Nekki.SF2.GUI.Fight/FightScene.cs').read_text(encoding='utf-8-sig')
    body=re.search(r'private void FixedUpdate\(\)\s*\{(.*?)\n\t\}',recovered,re.S)[1]
    assert '_Fight != null' in body and '_Fight.Draw();' in body and 'Cpp2ILHelpers' not in body
    checks=[dict(rva=0xe57190,status='PASS_STATIC_CONTROL_FLOW',behavior='Null Fight returns; non-null Fight tail-calls Fight.Draw with MethodInfo*=0. Pseudocode may expand the tail call.'),
        dict(rva=0xd94fd0,status='PASS_STATIC_CONTROL_FLOW',behavior='HaveSecondPlayer compares current GamePadController.DevicesCount > 1.')]
    report=dict(passed=2,failed=0,checks=checks,scope='Small wrappers/predicates only; no whole-combat, physical-controller or runtime parity certification.')
    destination(ROOT,ROOT/'reports/native-behavior-leaf-tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    db=sqlite3.connect(ROOT/'analysis/il2cpp/research.sqlite')
    for row in checks:
        db.execute('UPDATE methods SET semantic_status=? WHERE rva=?',('STATIC_CONTROL_FLOW_VALIDATED',row['rva']))
        for mid, in db.execute('SELECT id FROM methods WHERE rva=?',(row['rva'],)).fetchall():
            if not db.execute('SELECT 1 FROM evidence WHERE method_id=? AND kind=?',(mid,'ARM64_WRAPPER_BYTE_CHECK')).fetchone():
                db.execute('INSERT INTO evidence(method_id,kind,source,address,observation,confidence) VALUES(?,?,?,?,?,?)',
                    (mid,'ARM64_WRAPPER_BYTE_CHECK','reports/native-behavior-leaf-tests.json',hex(0x7100000000+row['rva']),row['behavior'],'HIGH_STATIC_SCOPED'))
    db.commit();db.close();print(json.dumps(report,indent=2))
if __name__=='__main__':main()
