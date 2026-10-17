"""Resolve serialized PPtr identities without substituting generated Unity GUIDs."""
import collections
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
from export_typed_components import references
ROOT=Path(__file__).resolve().parents[3]

def main():
    folder=ROOT/'analysis/assets/typed-components'
    manifest=json.loads((ROOT/'analysis/assets/source-manifest-summary.json').read_text(encoding='utf-8'))
    files={Path(row['path']).name:row for row in manifest['files']}
    objects={}
    for line in (ROOT/'analysis/assets/source-objects.jsonl').open(encoding='utf-8'):
        row=json.loads(line);objects[(Path(row['source_file']).name,row['path_id'])]=row
    records={}
    for line in (folder/'components.jsonl').open(encoding='utf-8'):
        row=json.loads(line);records[(row['source_file'],row['path_id'])]=row
    sequential=folder/'sequential-validation.jsonl'
    if sequential.exists():
        for line in sequential.open(encoding='utf-8'):
            row=json.loads(line);records[(row['source_file'],row['path_id'])]=row
    retry=folder/'retry-resources.assets-15075.json'
    if retry.exists() and not sequential.exists():
        row=records[('resources.assets',15075)].copy()
        data=json.loads(retry.read_text(encoding='utf-8-sig'))
        row.update(data=data,status='PARSED_AFTER_RETRY',references=list(references(data)),typed_field_count=len(data.get('m_Structure') or {}))
        records[('resources.assets',15075)]=row
    layout_log=ROOT/'logs'/('assetripper-sequential-validation.log' if sequential.exists() else 'assetripper.log')
    mismatch_types=set(re.findall(r'because script (.+?) layout mismatched',layout_log.read_text(encoding='utf-8-sig',errors='replace')))
    def resolve(source,file_id,path_id):
        if path_id==0:return None,'NULL',None
        if source not in files:return None,'GENERATED_OR_UNMAPPED_SOURCE',None
        external=None
        if file_id==0:target_file=source
        else:
            external=next((x for x in files[source]['externals'] if x['file_id']==file_id),None)
            if external is None:return None,'INVALID_EXTERNAL_INDEX',None
            target_file=Path(external['path'].replace('\\','/')).name
        target=(target_file,path_id)
        return target,('RESOLVED_ORIGINAL' if target in objects else 'MISSING_OBJECT_OR_FILE'),external
    db=sqlite3.connect(destination(ROOT,ROOT/'analysis/assets/asset-graph.sqlite'))
    db.executescript('''DROP TABLE IF EXISTS edges; DROP TABLE IF EXISTS components;
    CREATE TABLE edges(source_file TEXT,source_id INTEGER,field_path TEXT,target_file_id INTEGER,target_id INTEGER,resolved_file TEXT,status TEXT,external_guid TEXT);
    CREATE INDEX edge_source ON edges(source_file,source_id); CREATE INDEX edge_target ON edges(resolved_file,target_id);
    CREATE TABLE components(source_file TEXT,path_id INTEGER,name TEXT,class TEXT,script_type TEXT,game_object_id INTEGER,decode_status TEXT,PRIMARY KEY(source_file,path_id));''')
    counts=collections.Counter();types=collections.Counter();anomalies=[];scene_scripts=collections.defaultdict(collections.Counter)
    header_checks=collections.Counter();header_errors=[]
    streams={name:open(item['path'],'rb') for name,item in files.items()}
    with destination(ROOT,ROOT/'analysis/assets/asset-graph-edges.jsonl').open('w',encoding='utf-8') as writer:
        for (source,path_id),row in records.items():
            data=row.get('data',{});script_type=None;decode=row['status']
            obj=objects.get((source,path_id))
            if obj and row['class'] in ('MonoBehaviour','GameObject'):
                stream=streams[source];stream.seek(obj['offset']);raw=stream.read(obj['size'])
                try:
                    if row['class']=='MonoBehaviour':
                        if len(raw)<32:raise ValueError('Truncated MonoBehaviour header')
                        go_file,go_id=struct.unpack_from('<iq',raw,0);script_file,script_id=struct.unpack_from('<iq',raw,16)
                        expected_go=data.get('m_GameObject',{});expected_script=data.get('m_Script',{})
                        if (go_file,go_id)!=(expected_go.get('m_FileID'),expected_go.get('m_PathID')):raise ValueError('GameObject identity differs')
                        if (script_file,script_id)!=(expected_script.get('m_FileID'),expected_script.get('m_PathID')):raise ValueError('Script identity differs')
                        if raw[12]!=data.get('m_Enabled'):raise ValueError('Enabled byte differs')
                    else:
                        count=struct.unpack_from('<i',raw)[0]
                        if not 0<=count<=10000 or 4+count*12>len(raw):raise ValueError('GameObject component bounds')
                        component_ids=[struct.unpack_from('<iq',raw,4+i*12) for i in range(count)]
                        expected=[(x['m_Component']['m_FileID'],x['m_Component']['m_PathID']) for x in data.get('m_Components',[])]
                        if component_ids!=expected:raise ValueError('Component identities differ')
                    header_checks[row['class']+':PASS_RAW_IDENTITY_MATCH']+=1
                except (ValueError,struct.error) as error:
                    header_checks[row['class']+':FAIL']+=1
                    header_errors.append(dict(source_file=source,path_id=path_id,error=str(error)))
            script=data.get('m_Script',{})
            if script:
                target,status,_=resolve(source,int(script.get('m_FileID',0)),int(script.get('m_PathID',0)))
                target_row=records.get(target,{}) if target else {}
                sd=target_row.get('data',{})
                script_type='.'.join(filter(None,(sd.get('m_Namespace'),sd.get('m_ClassName')))) or None
            if script_type:
                types[script_type]+=1
                if script_type in mismatch_types:
                    decode='TYPE_HAS_LAYOUT_WARNING_INSTANCE_UNCERTAIN'
                    anomalies.append(dict(source_file=source,path_id=path_id,name=row['name'],script_type=script_type,status=decode))
                if source.startswith('level'):scene_scripts[source][script_type]+=1
            game_object=data.get('m_GameObject',{})
            db.execute('INSERT INTO components VALUES(?,?,?,?,?,?,?)',(source,path_id,row['name'],row['class'],script_type,game_object.get('m_PathID'),decode))
            for field_path,file_id,target_id in row.get('references',[]):
                target,status,external=resolve(source,file_id,target_id);counts[status]+=1
                if field_path in ('/m_PrefabInternal','/m_CorrespondingSourceObject'):
                    counts[status]-=1;status='GENERATED_EDITOR_REFERENCE';counts[status]+=1
                item=dict(source_file=source,source_id=path_id,field_path=field_path,target_file_id=file_id,target_id=target_id,
                    resolved_file=target[0] if target else None,status=status,external_guid=external['guid'] if external else None)
                writer.write(json.dumps(item,ensure_ascii=False)+'\n')
                db.execute('INSERT INTO edges VALUES(?,?,?,?,?,?,?,?)',tuple(item.values()))
    db.commit();db.close()
    for stream in streams.values():stream.close()
    report=dict(reference_counts={k:v for k,v in counts.items() if v},raw_identity_checks=dict(header_checks),raw_identity_errors=header_errors,
        components=len(records),typed_script_types=len(types),known_layout_mismatch_types=sorted(mismatch_types),
        components_with_known_type_mismatch=anomalies,scene_script_types={k:dict(v) for k,v in scene_scripts.items()},
        limitations=['Resolved identities do not prove component field layout or scene runtime availability.',
            'GameObject component identities and MonoBehaviour GameObject/script identities are independently compared against original object bytes.',
            'Prefab/editor references added by AssetRipper are explicitly generated; they are not resolved through original external tables.',
            'Custom-field PPtr interpretation still depends on correct metadata-assisted field layout; no complete decode proof is claimed.',
            'Sequential reset/reload restored four initial failures. ScreenModel still emits a layout warning; GUISkin reports invalid script ID.',
            'Type-level warnings conservatively flag related instances; the log does not identify the exact failing object.'])
    destination(ROOT,ROOT/'analysis/assets/asset-graph-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('scene_script_types','components_with_known_type_mismatch')},indent=2))
    print('Components with known type mismatch:',len(anomalies))
if __name__=='__main__':main()
