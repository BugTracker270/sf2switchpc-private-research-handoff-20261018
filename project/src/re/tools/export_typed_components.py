"""Export component fields using metadata-only DLLs in a documented staging copy."""
import collections
from concurrent.futures import ThreadPoolExecutor,as_completed
import json
from pathlib import Path
import sqlite3
import sys
import urllib.parse
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
from catalog_assets import Page,get
ROOT=Path(__file__).resolve().parents[3]

def references(value,path=''):
    if isinstance(value,dict):
        if 'm_FileID' in value and 'm_PathID' in value:
            if value['m_PathID']:yield path,int(value['m_FileID']),int(value['m_PathID'])
        else:
            for key,child in value.items():yield from references(child,path+'/'+key)
    elif isinstance(value,list):
        for index,child in enumerate(value):yield from references(child,path+f'/{index}')

def fetch(row):
    try:
        data=json.loads(get('/Assets/Json?Path='+urllib.parse.quote(row['descriptor'])))
        row['data']=data;row['status']='PARSED'
        row['typed_field_count']=len(data.get('m_Structure') or {}) if row['class']=='MonoBehaviour' else None
        row['references']=list(references(data))
    except Exception as error:row.update(status='ERROR',error=str(error))
    return row

def main():
    output=destination(ROOT,ROOT/'analysis'/'assets'/'typed-components')
    output.mkdir(exist_ok=True)
    corpus=destination(ROOT,output/'components.jsonl')
    if corpus.exists():raise ValueError('Typed component corpus exists; preserve prior output')
    root=Page();root.feed(get('/Bundles/View?Path='+urllib.parse.quote('{"P":[]}')).decode())
    links={link['href']:link['text'] for link in root.links if link['href'].startswith('/Collections/View?')}
    targets=[]
    for href,name in links.items():
        page=Page();page.feed(get(href).decode())
        for row in page.rows:
            if len(row['cells'])!=3 or row['cells'][1] not in ('MonoBehaviour','MonoScript','GameObject'):continue
            link=next((l for l in row['links'] if l['href'].startswith('/Assets/View?')),None)
            if not link:continue
            descriptor=urllib.parse.parse_qs(urllib.parse.urlsplit(link['href']).query)['Path'][0]
            targets.append(dict(source_file=name,path_id=int(row['cells'][0]),name=row['cells'][2],
                **{'class':row['cells'][1]},descriptor=descriptor))
    db=sqlite3.connect(destination(ROOT,output/'components.sqlite'))
    db.executescript('''CREATE TABLE components(source_file TEXT,path_id INTEGER,class TEXT,name TEXT,status TEXT,typed_fields INTEGER,PRIMARY KEY(source_file,path_id));
    CREATE TABLE references_raw(source_file TEXT,path_id INTEGER,field_path TEXT,target_file_id INTEGER,target_path_id INTEGER);
    CREATE INDEX component_class_idx ON components(class);''')
    stats=collections.Counter();typed=0;total=0
    with ThreadPoolExecutor(max_workers=4) as pool,corpus.open('w',encoding='utf-8') as writer:
        jobs=[pool.submit(fetch,row) for row in targets]
        for future in as_completed(jobs):
            row=future.result();writer.write(json.dumps(row,ensure_ascii=False)+'\n');total+=1
            stats[row['class']+':'+row['status']]+=1
            if row.get('typed_field_count',0):typed+=1
            db.execute('INSERT INTO components VALUES(?,?,?,?,?,?)',(row['source_file'],row['path_id'],row['class'],row['name'],row['status'],row.get('typed_field_count')))
            db.executemany('INSERT INTO references_raw VALUES(?,?,?,?,?)',[(row['source_file'],row['path_id'],*r) for r in row.get('references',[])])
            if total%500==0:
                writer.flush();print(total,'/',len(targets),'typed/structural asset records',flush=True)
    db.commit();db.close()
    report=dict(total=total,by_type_status=dict(stats),mono_behaviours_with_nonempty_typed_fields=typed,
        provenance='Original serialized data copied unchanged, augmented with Il2CppDumper metadata-only DLLs to inform deserialization.',
        backend='Original is IL2CPP; Mono staging detection is synthetic. No shipping managed implementations were found.',
        limitations=['Pointer targets are recorded with original file/path IDs; graph resolution is a separate check.',
                    'A component with zero custom fields may legitimately have none; zero is not automatically a decode failure.'])
    destination(ROOT,output/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2),flush=True)

if __name__=='__main__':main()
