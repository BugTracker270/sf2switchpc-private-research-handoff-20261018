"""Select a bounded native family, with metadata types, from the private index."""
import argparse
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pattern',required=True)
    parser.add_argument('--name',required=True)
    parser.add_argument('--maximum',type=int,default=400)
    args=parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+',args.name):raise ValueError('Invalid name')
    pattern=re.compile(args.pattern)
    db=sqlite3.connect(ROOT/'analysis/nso/corpus.sqlite');db.row_factory=sqlite3.Row
    targets=[];pointers=set()
    metadata=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    matching={r['Address']:r for r in reversed(metadata['ScriptMethod']) if pattern.search(r['Name'])}
    if not 0<len(matching)<=args.maximum:raise ValueError(f'Bounded selection gate: {len(matching)} targets')
    for rva,row in sorted(matching.items()):
        indexed=db.execute('SELECT * FROM functions WHERE rva=?',(rva,)).fetchone()
        if indexed is None:raise ValueError('Function absent from corpus')
        with (ROOT/indexed['corpus']).open('rb') as stream:
            stream.seek(indexed['offset']);record=json.loads(stream.read(indexed['length']))
        pointers.update(int(s,16)-0x7100000000 for s in re.findall(r'PTR_(?:DAT_)?([0-9a-fA-F]{10,16})',record.get('pseudocode','')))
        # A failed decompilation still has native instructions. Recognize only
        # adjacent ADRP/LDR pairs, with the exact same base register.
        lines=record.get('assembly','').splitlines()
        for first,second in zip(lines,lines[1:]):
            page=re.search(r'\tadrp (x\d+),0x([0-9a-fA-F]+)$',first)
            if not page:continue
            load=re.search(r'\tldr x\d+,\['+page[1]+r'(?:, #0x([0-9a-fA-F]+))?\]$',second)
            if load:pointers.add(int(page[2],16)+int(load[1] or '0',16)-0x7100000000)
        targets.append(dict(rva=rva,end_rva=record.get('end_rva',rva+max(4,record.get('body_bytes',4))),name=row['Name'],signature=row['Signature'],preserve_prototype=True))
    data=(ROOT/'analysis/nso/main-uncompressed.nso').read_bytes()
    segments=[struct.unpack_from('<III',data,o) for o in (0x10,0x20,0x30)]
    slots={r['Address']:r for r in metadata['ScriptMetadata']};strings={r['Address']:r for r in metadata['ScriptString']}
    references=[]
    for pointer in sorted(pointers):
        for offset,rva,size in segments:
            if rva<=pointer and pointer+8<=rva+size:
                slot=struct.unpack_from('<Q',data,offset+pointer-rva)[0]
                if slot in slots:references.append(dict(got_rva=pointer,slot_rva=slot,kind='METADATA',**slots[slot]))
                elif slot in strings:references.append(dict(got_rva=pointer,slot_rva=slot,kind='STRING',Signature='System_String_o*',Name='StringLiteral_'+hex(slot),**strings[slot]))
                break
    for suffix,records in [('targets',targets),('metadata',references)]:
        path=destination(ROOT,ROOT/f'analysis/nso/{args.name}-{suffix}.json')
        if path.exists():raise ValueError('Preserve prior selection: '+str(path))
        path.write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(name=args.name,targets=len(targets),metadata_slots=len(references))))
if __name__=='__main__':main()
