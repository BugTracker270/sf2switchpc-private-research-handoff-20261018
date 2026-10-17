"""Index metadata locally; address placement is not semantic validation."""
import json
import re
import sqlite3
import struct
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination

ROOT=Path(__file__).resolve().parents[3]
FEATURES={
 'combat':r'combat|fight|damage|hitbox|hurtbox|attack|battle|combo|knock|block',
 'animation':r'animat|skelet|bone|motion|pose',
 'ai':r'(?:^|[._$])ai(?:[._$]|$)|opponent|behavio.*tree',
 'story':r'story|quest|sensei|campaign|tournament|progress',
 'sparring':r'sparring|versus|multiplayer|player2|secondplayer',
 'save':r'save|persist|profile|user.*data|slot',
 'economy_equipment':r'equip|weapon|armor|shop|reward|currency|money|enchant|inventory',
 'input_platform':r'input|switch|nintendo|controller|joycon|gamepad|rewired',
 'ui_localization':r'localiz|language|dialog|menu|screen|widget|canvas',
 'audio':r'audio|sound|music|fmod',
 'bootstrap':r'bootstrap|gamemanager|gamestate|scene.*load'}

def main():
    source=ROOT/'analysis'/'il2cpp'/'effective-main'
    data=json.loads((source/'script.json').read_text(encoding='utf-8-sig'))
    with (ROOT/'unpacked'/'effective'/'exefs'/'main').open('rb') as stream:header=stream.read(256)
    text_start,text_size=struct.unpack_from('<II',header,0x14)
    database=destination(ROOT,ROOT/'analysis'/'il2cpp'/'research.sqlite')
    if database.exists(): raise ValueError('Index already exists; preserve prior research annotations')
    connection=sqlite3.connect(database)
    connection.executescript('''
    PRAGMA journal_mode=DELETE;
    CREATE TABLE methods(id INTEGER PRIMARY KEY,name TEXT,signature TEXT,type_signature TEXT,rva INTEGER,
      native_address TEXT,module TEXT,address_validation TEXT,semantic_status TEXT,source TEXT);
    CREATE INDEX method_name_idx ON methods(name);
    CREATE INDEX method_rva_idx ON methods(rva);
    CREATE TABLE feature_methods(feature TEXT,method_id INTEGER,classification TEXT,PRIMARY KEY(feature,method_id));
    CREATE TABLE metadata_addresses(kind TEXT,address INTEGER,name TEXT,source TEXT);
    CREATE TABLE evidence(id INTEGER PRIMARY KEY,method_id INTEGER,kind TEXT,source TEXT,address TEXT,observation TEXT,confidence TEXT);
    CREATE TABLE contradictions(id INTEGER PRIMARY KEY,topic TEXT,hypothesis_a TEXT,hypothesis_b TEXT,resolution TEXT,status TEXT);
    ''')
    method_rows=[];feature_rows=[]
    counts={name:0 for name in FEATURES};outside=0
    for i,method in enumerate(data['ScriptMethod'],1):
        rva=method['Address']
        valid=text_start <= rva < text_start+text_size
        outside+=not valid
        method_rows.append((i,method['Name'],method.get('Signature'),method.get('TypeSignature'),rva,
            f'0x{0x7100000000+rva:X}','main','WITHIN_NSO_TEXT' if valid else 'OUTSIDE_NSO_TEXT','UNANALYZED','Il2CppDumper script.json'))
        for feature,pattern in FEATURES.items():
            if re.search(pattern,method['Name'],re.I):
                counts[feature]+=1;feature_rows.append((feature,i,'NAME_HEURISTIC_UNVERIFIED'))
    connection.executemany('INSERT INTO methods VALUES(?,?,?,?,?,?,?,?,?,?)',method_rows)
    connection.executemany('INSERT INTO feature_methods VALUES(?,?,?)',feature_rows)
    for kind in ('ScriptMetadata','ScriptMetadataMethod'):
        connection.executemany('INSERT INTO metadata_addresses VALUES(?,?,?,?)',
            [(kind,row['Address'],row.get('Name',''),'script.json') for row in data[kind]])
    connection.commit();connection.close()
    dump=(source/'dump.cs').read_text(encoding='utf-8-sig')
    images=[{'index':int(index),'assembly':assembly,'type_start':int(start)} for index,assembly,start in re.findall(r'^// Image (\d+): (.+?) - (\d+)\s*$',dump,re.M)]
    summary=dict(method_records=len(method_rows),unique_method_addresses=len({m[4] for m in method_rows}),
        addresses_outside_text=outside,text_rva_start=hex(text_start),text_bytes=text_size,
        image_base='0x7100000000 (Ghidra loader default; verify against import inventory)',
        metadata_types=len(re.findall(r'TypeDefIndex: \d+',dump)),assemblies=images,
        database=str(database),feature_name_candidates=counts,
        warning='Names/type shells recovered; no method bodies or gameplay semantics certified. Feature tags are heuristics.')
    destination(ROOT,ROOT/'analysis'/'il2cpp'/'index-summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    coverage=dict(overall='IN_PROGRESS',metadata_method_records=len(method_rows),native_functions_semantically_validated=0,
        features={feature:dict(name_candidates=count,fully_understood=0,partially_inferred=0,not_analyzed=count,
                  status='NOT_ANALYZED',candidate_method='metadata name heuristic; candidates overlap') for feature,count in counts.items()})
    destination(ROOT,ROOT/'reports'/'analysis-coverage.json').write_text(json.dumps(coverage,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in summary.items() if k!='assemblies'},indent=2))
    print('Assembly names:', ', '.join(i['assembly'] for i in images))

if __name__=='__main__':main()
