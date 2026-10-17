"""Index witnessed adjacent ARM64 ADRP/LDR references to IL2CPP metadata slots."""
import argparse
import collections
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]
BASE=0x7100000000
PAGE=re.compile(r'^([0-9a-f]+)\t[0-9a-f]+\tadrp (x\d+),0x([0-9a-f]+)$')

def build():
    source=sqlite3.connect((ROOT/'analysis/nso/corpus.sqlite').as_uri()+'?mode=ro',uri=True)
    groups=collections.defaultdict(list)
    for rva,name,corpus,offset,length in source.execute('SELECT rva,name,corpus,offset,length FROM functions ORDER BY corpus,offset'):
        groups[corpus].append((rva,name,offset,length))
    source.close()
    metadata=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    slots={r['Address']:('METADATA',r['Name']) for r in metadata['ScriptMetadata']}
    slots.update({r['Address']:('STRING',r['Value']) for r in metadata['ScriptString']})
    raw=(ROOT/'analysis/nso/main-uncompressed.nso').read_bytes();segments=[struct.unpack_from('<III',raw,o) for o in (0x10,0x20,0x30)]
    db=sqlite3.connect(destination(ROOT,ROOT/'analysis/nso/data-refs.sqlite'))
    db.executescript('''DROP TABLE IF EXISTS refs;
        CREATE TABLE refs(function_rva INTEGER,function_name TEXT,instruction_rva INTEGER,got_rva INTEGER,slot_rva INTEGER,kind TEXT,value TEXT,
            PRIMARY KEY(function_rva,instruction_rva,slot_rva));
        CREATE INDEX refs_value ON refs(value); CREATE INDEX refs_slot ON refs(slot_rva);''')
    functions=references=0;counts=collections.Counter()
    for corpus,records in groups.items():
        with (ROOT/corpus).open('rb') as stream:
            for rva,name,offset,length in records:
                stream.seek(offset);row=json.loads(stream.read(length));lines=row.get('assembly','').splitlines();functions+=1
                for first,second in zip(lines,lines[1:]):
                    page=PAGE.fullmatch(first)
                    if not page:continue
                    load=re.fullmatch(r'([0-9a-f]+)\t[0-9a-f]+\tldr x\d+,\['+page[2]+r'(?:, #0x([0-9a-f]+))?\]',second)
                    if not load or int(load[1],16)!=int(page[1],16)+4:continue
                    got=int(page[3],16)+int(load[2] or '0',16)-BASE
                    slot=None
                    for start,address,size in segments:
                        if address<=got and got+8<=address+size:slot=struct.unpack_from('<Q',raw,start+got-address)[0];break
                    if slot not in slots:continue
                    kind,value=slots[slot];counts[kind]+=1;references+=1
                    db.execute('INSERT INTO refs VALUES(?,?,?,?,?,?,?)',(rva,name,int(page[1],16)-BASE,got,slot,kind,value))
    db.commit()
    report=dict(status='PASS_BOUNDED_NATIVE_DATA_REFERENCE_INDEX',functions_scanned=functions,references=references,by_kind=dict(counts),
        distinct_slots=db.execute('SELECT COUNT(DISTINCT slot_rva) FROM refs').fetchone()[0],
        scope='Adjacent, address-contiguous ADRP xN/page followed by LDR xM/[xN, immediate], with file-backed GOT value matching a known metadata/string slot. Direct instruction witnesses only; interleaved loads, ADD forms, indirect dataflow and runtime reachability are not covered.')
    db.close();destination(ROOT,ROOT/'analysis/nso/data-refs-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--build',action='store_true');parser.add_argument('--string');parser.add_argument('--metadata');parser.add_argument('--limit',type=int,default=30)
    args=parser.parse_args()
    if args.build:build();return
    if (args.string is None)==(args.metadata is None):raise ValueError('Select exactly one string or metadata query')
    db=sqlite3.connect((ROOT/'analysis/nso/data-refs.sqlite').as_uri()+'?mode=ro',uri=True)
    for row in db.execute('SELECT DISTINCT function_rva,function_name,got_rva,slot_rva,value FROM refs WHERE kind=? AND value LIKE ? ORDER BY function_rva LIMIT ?',
            ('STRING' if args.string is not None else 'METADATA','%'+(args.string if args.string is not None else args.metadata)+'%',args.limit)):
        print(json.dumps(dict(function_rva=hex(row[0]),function_name=row[1],got_rva=hex(row[2]),slot_rva=hex(row[3]),value=row[4]),ensure_ascii=False))
    db.close()
if __name__=='__main__':main()
