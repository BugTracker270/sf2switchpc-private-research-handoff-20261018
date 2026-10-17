"""Prepare error repairs and scoped typed re-export targets without altering dumps."""
import json
from pathlib import Path
import re
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def write(path,value):destination(ROOT,ROOT/path).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')

def main():
    library=json.loads((ROOT/'analysis/nso/library-targets.json').read_text(encoding='utf-8'))
    failed=set();completed=set()
    for line in (ROOT/'analysis/nso/native-corpus-library/functions.jsonl').open(encoding='utf-8'):
        row=json.loads(line)
        completed.add(row['rva'])
        if row['status']!='PSEUDOCODE_EXPORTED':failed.add(row['rva'])
    if completed!={r['rva'] for r in library}:raise ValueError('Library corpus is incomplete; retain and resume it before follow-up')
    write('analysis/nso/library-repair-targets.json',[r for r in library if r['rva'] in failed])
    all_targets=json.loads((ROOT/'analysis/nso/native-targets.json').read_text(encoding='utf-8'))
    patterns=[r'ApplicationController\$\$Awake$',r'SystemProperties\$\$SetFrameRate$',r'PvpScene\$\$',
      r'FightScene\$\$FixedUpdate$',r'Fights.Fight\$\$(?:RenderFight|RenderCamera|CheckModelsCollision|Detect|GetDamage|Strike)',
      r'ModelPhysics\$\$',r'ModelNode\$\$TimeStep$',r'ModelContainer\$\$(?:Render|FixedUpdate)$',
      r'\.Animation\.Data\.AnimationData\$\$',r'ModifiedAlignFormula\$\$',r'Hit\$\$(?:get_damage|set_damage)$',
      r'ListSF\$\$(?:get_UsersPath|DeleteSaveSlot|SomeSaveSlotIsNotEmpty)$',r'UserDataValidator\$\$',
      r'Roster\$\$SaveToFile$',r'MainSettings\$\$SaveToFile$',r'XmlUtils\$\$SaveDocumentAndUpdateHash$',
      r'FilesUtil\$\$(?:WriteAllBytes_NintendoSDK|ReadAllBytes_NintendoSDK|SaveXmlFile)$',
      r'GeneralMenuScene\$\$LoadGameAtSaveSlot$',r'GeneralMenuScene\.<LoadGameAtSaveSlot>.*\$\$MoveNext$']
    targets=[dict(r,preserve_prototype=True) for r in all_targets if any(re.search(p,r['name']) for p in patterns)]
    targets += [dict(name='SF2_codegen_registration_initializer',rva=0x15f3060,end_rva=0x15f307b,
        signature='void SF2_codegen_registration_initializer (void);',assembly='NATIVE_BOOTSTRAP_OBSERVED',preserve_prototype=False),
        dict(name='SF2_codegen_register_runtime',rva=0xb0e140,end_rva=0xb0e53f,
        signature='void SF2_codegen_register_runtime (void* code_registration, void* metadata_registration, void* options);',
        assembly='NATIVE_RUNTIME_OBSERVED',preserve_prototype=False)]
    # Importing no original code: this list only selects addresses and metadata types.
    write('analysis/nso/typed-behavior-targets.json',targets)
    chosen={r['rva'] for r in targets};pointers=set()
    for line in (ROOT/'analysis/nso/native-corpus/functions.jsonl').open(encoding='utf-8'):
        row=json.loads(line)
        if row['rva'] in chosen:
            pointers.update(int(a,16)-0x7100000000 for a in re.findall(r'PTR_(?:DAT_)?([0-9A-Fa-f]{10,16})',row.get('pseudocode','')))
    script=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    metadata={r['Address']:r for r in script['ScriptMetadata']}
    strings={r['Address']:r for r in script['ScriptString']}
    data=(ROOT/'analysis/nso/main-uncompressed.nso').read_bytes();segments=[struct.unpack_from('<III',data,o) for o in (0x10,0x20,0x30)]
    references=[]
    for pointer in sorted(pointers):
        for offset,rva,size in segments:
            if rva<=pointer and pointer+8<=rva+size:
                slot=struct.unpack_from('<Q',data,offset+pointer-rva)[0]
                if slot in metadata:references.append(dict(got_rva=pointer,slot_rva=slot,kind='METADATA',**metadata[slot]))
                elif slot in strings:references.append(dict(got_rva=pointer,slot_rva=slot,kind='STRING',Signature='System_String_o*',Name='StringLiteral_'+hex(slot),**strings[slot]))
                break
    write('analysis/nso/typed-behavior-metadata.json',references)
    print('Library repairs:',len(failed),'typed targets:',len(targets),'referenced metadata slots:',len(references))
if __name__=='__main__':main()
