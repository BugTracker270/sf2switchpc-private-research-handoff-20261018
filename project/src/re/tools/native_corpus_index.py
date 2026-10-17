"""Local byte-offset index for native exports. Pseudocode is not original source."""
import argparse
import collections
import json
from pathlib import Path
import re
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]
DB=ROOT/'analysis/nso/corpus.sqlite'

def ingest(db,corpus):
    counts=collections.Counter()
    with corpus.open('rb') as stream:
        while True:
            offset=stream.tell();line=stream.readline()
            if not line or not line.endswith(b'\n'):break
            row=json.loads(line);rva=row['rva'];counts[row['status']]+=1
            existing=db.execute('SELECT status FROM functions WHERE rva=?',(rva,)).fetchone()
            if existing and existing[0]=='PSEUDOCODE_EXPORTED' and row['status']!='PSEUDOCODE_EXPORTED':continue
            db.execute('INSERT OR REPLACE INTO functions VALUES(?,?,?,?,?,?,?,?,?)',
                (rva,row['name'],row.get('signature'),str(corpus.relative_to(ROOT)),offset,len(line),row['status'],row.get('body_bytes'),row.get('prototype_applied')))
            db.execute('DELETE FROM calls WHERE caller_rva=?',(rva,))
            calls=[]
            for instruction in row.get('assembly','').splitlines():
                match=re.search(r'\t(bl|b)\s+0x([0-9a-fA-F]+)',instruction)
                if match:calls.append((rva,int(match[2],16)-0x7100000000,match[1],instruction))
            db.executemany('INSERT INTO calls VALUES(?,?,?,?)',calls)
    return dict(path=str(corpus.relative_to(ROOT)),counts=dict(counts))

def summary(db,files,metadata_count):
    return dict(corpora=files,unique_records=db.execute('SELECT COUNT(*) FROM functions').fetchone()[0],
        by_status=dict(db.execute('SELECT status,COUNT(*) FROM functions GROUP BY status')),
        direct_call_edges=db.execute('SELECT COUNT(*) FROM calls').fetchone()[0],metadata_unique_addresses=metadata_count,
        additional_native_addresses=db.execute('SELECT COUNT(*) FROM functions WHERE rva NOT IN (SELECT rva FROM aliases)').fetchone()[0],
        warning='Direct branches and exported entries only. Indirect/native coverage, function boundaries and all semantics require separate validation; pseudocode export is not a semantic completion claim.')

def append(folder):
    if not re.fullmatch('[a-z0-9-]+',folder):raise ValueError('Invalid native corpus folder')
    corpus=destination(ROOT,ROOT/'analysis/nso'/folder/'functions.jsonl')
    if not DB.exists() or not corpus.exists():raise ValueError('Existing index and completed corpus required')
    previous=json.loads((ROOT/'analysis/nso/corpus-summary.json').read_text(encoding='utf-8-sig'))
    with sqlite3.connect(destination(ROOT,DB)) as db:
        record=ingest(db,corpus)
        files=[row for row in previous['corpora'] if row['path']!=record['path']]+[record]
        report=summary(db,files,previous['metadata_unique_addresses']);db.commit()
    destination(ROOT,ROOT/'analysis/nso/corpus-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(appended=record,unique_records=report['unique_records'],by_status=report['by_status'],additional_native_addresses=report['additional_native_addresses']),indent=2))

def build():
    db=sqlite3.connect(destination(ROOT,DB))
    db.executescript('''DROP TABLE IF EXISTS functions; DROP TABLE IF EXISTS aliases; DROP TABLE IF EXISTS calls;
    CREATE TABLE functions(rva INTEGER PRIMARY KEY,name TEXT,signature TEXT,corpus TEXT,offset INTEGER,length INTEGER,status TEXT,body_bytes INTEGER,prototype_applied INTEGER);
    CREATE TABLE aliases(rva INTEGER,name TEXT,signature TEXT);
    CREATE INDEX alias_names ON aliases(name);
    CREATE TABLE calls(caller_rva INTEGER,callee_rva INTEGER,kind TEXT,instruction TEXT);
    CREATE INDEX calls_caller ON calls(caller_rva); CREATE INDEX calls_callee ON calls(callee_rva);''')
    files=[]
    folders=['native-corpus','native-corpus-repairs','native-corpus-library','native-corpus-library-repairs',
        'typed-behavior-corpus','typed-behavior-corpus-v2','typed-behavior-corpus-v3','typed-behavior-ai-layout-v2',
        'typed-combat-layout-v2','typed-combat-prototype-repairs-v2','native-regex-switch-repair-v1',
        'typed-geometry-layout-v2','native-runtime-object-allocation','native-collision-runtime-helpers',
        'typed-damage-attributes-layout-v2','typed-animation-bezier-layout-v2','typed-quests-loading-layout-v2',
        'native-quest-runtime-helpers','typed-menu-currency-gates-layout-v2','typed-currency-codec-pvp-layout-v2',
        'native-currency-runtime-helpers','typed-currency-long-persistence','native-currency-long-runtime-helpers-v2',
        'typed-save-slot-persistence','typed-save-writer-slot-schema',
        'native-currency-long-runtime-pointer-repair-v3','typed-save-switch-load-fallback',
        'typed-save-roster-initialization','typed-save-xml-hash-fallback',
        'native-runtime-boundary-v1','native-runtime-plt-repairs-v2','native-exception-factory-dependencies-v1']
    folders+=sorted(path.name for path in (ROOT/'analysis/nso').glob('native-engine-batch-v1-*') if path.is_dir())
    folders+=sorted(path.name for path in (ROOT/'analysis/nso').glob('native-engine-unwind-v1-*') if path.is_dir())
    for folder in folders:
        corpus=ROOT/'analysis/nso'/folder/'functions.jsonl'
        if not corpus.exists():continue
        files.append(ingest(db,corpus))
    metadata=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    db.executemany('INSERT INTO aliases VALUES(?,?,?)',[(r['Address'],r['Name'],r.get('Signature')) for r in metadata['ScriptMethod']])
    db.commit()
    report=summary(db,files,len({r['Address'] for r in metadata['ScriptMethod']}))
    db.close()
    destination(ROOT,ROOT/'analysis/nso/corpus-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))

def query(pattern,limit,export):
    db=sqlite3.connect(DB);db.row_factory=sqlite3.Row
    rows=db.execute('''SELECT DISTINCT f.* FROM functions f JOIN aliases a USING(rva)
        WHERE a.name LIKE ? ORDER BY f.rva LIMIT ?''',('%'+pattern+'%',limit)).fetchall()
    for record in rows:
        item=dict(record)
        if export:
            folder=destination(ROOT,ROOT/export);folder.mkdir(exist_ok=True,parents=True)
            with (ROOT/item['corpus']).open('rb') as stream:
                stream.seek(item['offset']);data=json.loads(stream.read(item['length']))
            destination(ROOT,folder/(f'{item["rva"]:08x}.json')).write_text(json.dumps(data,indent=2),encoding='utf-8')
            destination(ROOT,folder/(f'{item["rva"]:08x}.c')).write_text(data.get('pseudocode','/* '+data.get('error','No pseudocode')+' */'),encoding='utf-8')
            item['export']=str(folder/(f'{item["rva"]:08x}.c'))
        print(json.dumps(item,ensure_ascii=False))
    db.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',action='store_true');parser.add_argument('--append-folder');parser.add_argument('--name',default='')
    parser.add_argument('--limit',type=int,default=30);parser.add_argument('--export')
    args=parser.parse_args()
    if args.build and args.append_folder:raise ValueError('Choose full rebuild or incremental append')
    if args.build:build()
    elif args.append_folder:append(args.append_folder)
    else:query(args.name,args.limit,args.export)
if __name__=='__main__':main()
