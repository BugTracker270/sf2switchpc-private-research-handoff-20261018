"""Repeat MonoBehaviour decoding sequentially after a clean local API reset.

Preserves the original parallel export and reports differences; no source edits.
"""
import collections
import json
from pathlib import Path
import sys
import urllib.parse
import urllib.request
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
from catalog_assets import BASE,Page,get
from export_typed_components import fetch
ROOT=Path(__file__).resolve().parents[3]

def post(path,data=None):
    body=urllib.parse.urlencode(data).encode() if data else b''
    request=urllib.request.Request(BASE+path,data=body,method='POST')
    with urllib.request.urlopen(request,timeout=240) as response:return response.read()

def main():
    output=destination(ROOT,ROOT/'analysis/assets/typed-components/sequential-validation.jsonl')
    if output.exists():raise ValueError('Preserve existing sequential validation')
    baseline={}
    for row in map(json.loads,(ROOT/'analysis/assets/typed-components/components.jsonl').open(encoding='utf-8')):
        if row['class']=='MonoBehaviour':baseline[(row['source_file'],row['path_id'])]=row
    log=ROOT/'logs/assetripper.log';log_start=log.stat().st_size
    post('/Reset');post('/LoadFolder',{'path':str(ROOT/'analysis/assets/typed-stage/Data')})
    page=Page();page.feed(get('/Bundles/View?Path='+urllib.parse.quote('{"P":[]}')).decode())
    collections_map={}
    for link in page.links:
        if link['href'].startswith('/Collections/View?'):
            descriptor=json.loads(urllib.parse.parse_qs(urllib.parse.urlsplit(link['href']).query)['Path'][0])
            collections_map[link['text']]=descriptor
    counts=collections.Counter();changes=[]
    with output.open('w',encoding='utf-8') as writer:
        for index,((source,path_id),old) in enumerate(sorted(baseline.items()),1):
            row={k:old[k] for k in ('source_file','path_id','name','class')}
            row['descriptor']=json.dumps({'C':collections_map[source],'D':path_id},separators=(',',':'))
            row=fetch(row);row['provenance']='Sequential decode after reset, identical raw staging data and metadata-only DLLs'
            counts[row['status']]+=1
            if row.get('data')!=old.get('data'):
                changes.append(dict(source_file=source,path_id=path_id,name=row['name'],old_status=old['status'],new_status=row['status'],
                    old_field_count=old.get('typed_field_count'),new_field_count=row.get('typed_field_count')))
            writer.write(json.dumps(row,ensure_ascii=False)+'\n')
            if index%250==0:writer.flush();print(index,'/',len(baseline),'sequential component decodes',flush=True)
    with log.open('rb') as stream:stream.seek(log_start);new_log=stream.read().decode('utf-8-sig',errors='replace')
    destination(ROOT,ROOT/'logs/assetripper-sequential-validation.log').write_text(new_log,encoding='utf-8')
    report=dict(total=len(baseline),by_status=dict(counts),changed_records=changes,changed_count=len(changes),
        layout_log='logs/assetripper-sequential-validation.log',
        limitation='Repeatability/deserialization evidence, not proof of gameplay equivalence. Original parallel output retained.')
    destination(ROOT,ROOT/'analysis/assets/typed-components/sequential-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2),flush=True)
if __name__=='__main__':main()
