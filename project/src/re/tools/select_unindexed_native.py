"""Select a bounded set of frequently called native targets outside metadata exports."""
import argparse
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--name',required=True);parser.add_argument('--limit',type=int,default=20)
    args=parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+',args.name) or not 1<=args.limit<=1000:raise ValueError('Bounded valid name/count required (1..1000)')
    path=destination(ROOT,ROOT/f'analysis/nso/{args.name}-targets.json')
    if path.exists():raise ValueError('Preserve prior native selection')
    with (ROOT/'analysis/nso/main-uncompressed.nso').open('rb') as stream:header=stream.read(0x100)
    _,text_start,text_size=struct.unpack_from('<III',header,0x10)
    db=sqlite3.connect((ROOT/'analysis/nso/corpus.sqlite').as_uri()+'?mode=ro',uri=True)
    rows=db.execute("""SELECT callee_rva,COUNT(DISTINCT caller_rva),COUNT(*) FROM calls
        WHERE kind='bl' AND callee_rva NOT IN (SELECT rva FROM functions) AND callee_rva>=? AND callee_rva<?
        GROUP BY callee_rva ORDER BY COUNT(DISTINCT caller_rva) DESC,callee_rva LIMIT ?""",(text_start,text_start+text_size,args.limit)).fetchall()
    db.close()
    targets=[dict(rva=rva,end_rva=min(rva+0x4000,text_start+text_size-1),name=f'NativeTarget_{rva:08X}',signature='',
        preserve_prototype=True,distinct_direct_callers=callers,direct_calls=calls,
        selection_scope='Direct BL target outside the current function index. Discovery extent is bounded; function body and semantics require native review. Existing Ghidra prototype preserved, no parameter/return types invented.') for rva,callers,calls in rows]
    if not targets:raise ValueError('No unindexed direct-call targets remain in this index; indirect/native discovery is a separate task')
    path.write_text(json.dumps(targets,indent=2)+'\n',encoding='utf-8');print(json.dumps(dict(name=args.name,targets=len(targets),path=str(path))))
if __name__=='__main__':main()
