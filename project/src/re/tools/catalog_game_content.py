"""Index original XML and strictly validate observed point-frame animation files."""
import collections
import hashlib
import json
import math
import re
from pathlib import Path
import sqlite3
import struct
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def looks_xml(data):
    head=data.lstrip(b'\xef\xbb\xbf \t\r\n')[:32]
    return head.startswith(b'<?xml') or bool(re.match(rb'<[A-Za-z_]',head))

def decode_point_frames(data):
    if len(data)<4:raise ValueError('Missing frame count')
    frames=struct.unpack_from('<i',data)[0]
    if not 0<frames<=100000:raise ValueError('Invalid frame count')
    offset=4;nodes=collections.Counter();flags=collections.Counter()
    for _ in range(frames):
        if offset+5>len(data):raise ValueError('Truncated frame header')
        flags[data[offset]]+=1
        count=struct.unpack_from('<i',data,offset+1)[0]
        if not 0<count<=100000:raise ValueError('Invalid node count')
        offset+=5;end=offset+count*12
        if end>len(data):raise ValueError('Truncated node coordinates')
        if not all(math.isfinite(value[0]) for value in struct.iter_unpack('<f',data[offset:end])):
            raise ValueError('Non-finite node coordinate')
        nodes[count]+=1;offset=end
    if offset!=len(data):raise ValueError('Trailing bytes')
    return dict(frames=frames,node_count_distribution=dict(nodes),frame_marker_distribution=dict(flags),
                encoding='LE int32 frame count; each frame: uint8 marker, LE int32 node count, node_count * XYZ float32',
                time_unit='Not encoded in this format; timing must be linked to moves/native clock')

def tree_json(node):return dict(tag=node.tag,attributes=node.attrib,text=(node.text or '').strip(),children=[tree_json(c) for c in node])

def main():
    folder=ROOT/'analysis'/'assets'/'unity-export'/'ExportedProject'/'Assets'/'Resources'/'gamedata'
    output=destination(ROOT,Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'analysis'/'assets'/'content')
    output.mkdir(exist_ok=True)
    db=sqlite3.connect(destination(ROOT,output/'content.sqlite'))
    db.executescript('''CREATE TABLE IF NOT EXISTS xml_files(path TEXT PRIMARY KEY,sha256 TEXT,root_tag TEXT,elements INTEGER);
    CREATE TABLE IF NOT EXISTS records(source TEXT,tag TEXT,name TEXT,identifier TEXT,attributes TEXT,classification TEXT);
    CREATE INDEX IF NOT EXISTS record_tag ON records(tag);CREATE INDEX IF NOT EXISTS record_name ON records(name);''')
    if db.execute('SELECT COUNT(*) FROM xml_files').fetchone()[0]:raise ValueError('Content catalog exists; preserve annotations')
    xml_summary=[];all_tags=collections.Counter()
    for path in sorted(folder.rglob('*.bytes')):
        data=path.read_bytes()
        if not looks_xml(data):continue
        if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():raise ValueError('DTD/entity forbidden')
        try:tree=ET.fromstring(data)
        except ET.ParseError as error:
            xml_summary.append(dict(path=str(path),status='XML_PARSE_FAILED',error=str(error)));continue
        counts=collections.Counter(n.tag for n in tree.iter());all_tags.update(counts)
        relative=str(path.relative_to(folder));digest=hashlib.sha256(data).hexdigest()
        db.execute('INSERT INTO xml_files VALUES(?,?,?,?)',(relative,digest,tree.tag,sum(counts.values())))
        for node in tree.iter():
            if node.attrib:
                db.execute('INSERT INTO records VALUES(?,?,?,?,?,?)',(relative,node.tag,node.get('Name',node.get('name','')),
                    node.get('Id',node.get('ID','')),json.dumps(node.attrib,ensure_ascii=False),'RECOVERED_DATA_NOT_RUNTIME_REACHABILITY'))
        xml_summary.append(dict(path=relative,sha256=digest,root=tree.tag,element_counts=dict(counts),status='PARSED'))
    move_path=folder/'animations'/'moves.bytes';moves_root=ET.parse(move_path).getroot()
    templates=list(moves_root.find('Templates'));moves=list(moves_root.find('Moves'));triggers=list(moves_root.find('Triggers'))
    destination(ROOT,output/'moves.json').write_text(json.dumps(dict(source=str(move_path),source_sha256=hashlib.sha256(move_path.read_bytes()).hexdigest(),
        templates=[tree_json(n) for n in templates],moves=[tree_json(n) for n in moves],triggers=[tree_json(n) for n in triggers]),indent=2)+'\n',encoding='utf-8')
    animations=[];animation_errors=[]
    for path in sorted((folder/'animations').rglob('*.bytes')):
        data=path.read_bytes()
        if looks_xml(data):continue
        try:record=dict(path=str(path.relative_to(folder)),sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),status='VALIDATED_POINT_FRAMES',**decode_point_frames(data))
        except ValueError as error:
            animation_errors.append(dict(path=str(path.relative_to(folder)),error=str(error)));continue
        animations.append(record)
    by_name={Path(a['path']).name.casefold():a for a in animations}
    references=[]
    for move in moves:
        name=move.get('FileName')
        if not name:continue
        match=by_name.get(Path(name).name.casefold())
        bounds={key:int(move.get(key)) for key in ('FirstFrame','EndFrame') if move.get(key,'').lstrip('-').isdigit()}
        status='MISSING' if not match else 'RESOLVED'
        if match and any(v>=match['frames'] or v<0 for v in bounds.values()):status='FRAME_BOUND_REQUIRES_SEMANTIC_REVIEW'
        references.append(dict(move=move.get('Name'),file=name,status=status,source_frames=match['frames'] if match else None,bounds=bounds))
    report=dict(xml_files=len(xml_summary),xml_parse_failures=sum(x['status']!='PARSED' for x in xml_summary),files=xml_summary,
        moves=len(moves),templates=len(templates),triggers=len(triggers),animations=animations,animation_parse_errors=animation_errors,
        explicit_move_file_references=references,reference_status_counts=dict(collections.Counter(r['status'] for r in references)),
        source='Only original TextAssets whose payload hashes were validated against serialized input',
        format_reference='Gymnast Tool Suite source-only SF2 import_bin_sf2.py; decoder independently implemented and matched against supplied Switch data',
        limitations=['Unused mobile content remains in the dump; data presence is not runtime feature availability.',
            'Frame-bound checks use a provisional zero-based interpretation; boundary mismatches require native parser evidence. No frame duration is inferred from animation count.'])
    destination(ROOT,output/'content-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    db.commit();db.close()
    print(json.dumps({key:report[key] for key in ('xml_files','xml_parse_failures','moves','templates','triggers','reference_status_counts')},indent=2))
    print('Validated custom point-frame animations:',len(animations),'other/failed candidates:',len(animation_errors))

if __name__=='__main__':main()
