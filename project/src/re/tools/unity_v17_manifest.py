"""Bounded read-only Unity serialized-v17 inventory and raw TextAsset validation.

Format cross-check: K0lb3/UnityPy SerializedFile/ObjectReader (MIT).
This is a narrow independent parser, not a general Unity exporter.
"""
import collections
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination

ROOT=Path(__file__).resolve().parents[3]

class Reader:
    def __init__(self,stream,limit,endian='<'):
        self.stream,self.limit,self.endian=stream,limit,endian
    def read(self,n):
        if n<0 or self.stream.tell()+n>self.limit:raise ValueError('Serialized metadata bounds')
        data=self.stream.read(n)
        if len(data)!=n:raise ValueError('Truncated serialized file')
        return data
    def unpack(self,fmt):return struct.unpack(self.endian+fmt,self.read(struct.calcsize(fmt)))[0]
    def align(self):self.read((-self.stream.tell())%4)
    def zstring(self):
        data=bytearray()
        for _ in range(4096):
            b=self.read(1)
            if b==b'\0':return data.decode('utf-8',errors='strict')
            data.extend(b)
        raise ValueError('Serialized string too long')
    def count(self,maximum=100000):
        value=self.unpack('i')
        if not 0<=value<=maximum:raise ValueError('Serialized count exceeds limit')
        return value

def parse(stream,total):
    raw=stream.read(20)
    if len(raw)!=20:raise ValueError('Truncated Unity header')
    metadata_size,size,version,data_offset=struct.unpack('>IIII',raw[:16])
    if version!=17:raise ValueError(f'Unsupported serialized version {version}')
    if size!=total or not 20<=data_offset<=size or metadata_size>data_offset or raw[16] not in (0,1):
        raise ValueError('Invalid Unity header sizes/endian')
    reader=Reader(stream,data_offset,'>' if raw[16] else '<')
    unity_version=reader.zstring();platform=reader.unpack('i');trees=reader.unpack('?')
    types=[]
    for _ in range(reader.count()):
        class_id=reader.unpack('i');stripped=reader.unpack('?');script_index=reader.unpack('h')
        script_id=reader.read(16).hex() if class_id==114 else None
        type_hash=reader.read(16).hex()
        if trees:
            nodes=reader.count(1000000);strings=reader.count(64*1024*1024)
            reader.read(nodes*24+strings)
        types.append(dict(class_id=class_id,stripped=stripped,script_type_index=script_index,script_id=script_id,type_hash=type_hash))
    objects=[];ids=set()
    for _ in range(reader.count(1000000)):
        reader.align();path_id=reader.unpack('q');relative=reader.unpack('I');length=reader.unpack('I');type_index=reader.unpack('i')
        if path_id in ids or not 0<=type_index<len(types) or data_offset+relative+length>total:
            raise ValueError('Invalid object record')
        ids.add(path_id);objects.append(dict(path_id=path_id,offset=data_offset+relative,size=length,type_index=type_index,**types[type_index]))
    scripts=[]
    for _ in range(reader.count()):
        index=reader.unpack('i');reader.align();scripts.append(dict(file_index=index,path_id=reader.unpack('q')))
    externals=[]
    for index in range(reader.count()):
        empty=reader.zstring();guid=reader.read(16).hex();kind=reader.unpack('i');path=reader.zstring()
        externals.append(dict(file_id=index+1,guid=guid,type=kind,path=path))
    info=reader.zstring()
    extents=sorted((o['offset'],o['offset']+o['size']) for o in objects if o['size'])
    if any(a[1]>b[0] for a,b in zip(extents,extents[1:])):raise ValueError('Overlapping Unity objects')
    return dict(unity_version=unity_version,serialized_version=version,platform_id=platform,endian=reader.endian,
        type_tree_enabled=trees,types=types,objects=objects,scripts=scripts,externals=externals,metadata_end=stream.tell())

def hash_range(stream,start,size):
    stream.seek(start);hasher=hashlib.sha256()
    while size:
        chunk=stream.read(min(size,1024*1024))
        if not chunk:raise ValueError('Object range truncated')
        hasher.update(chunk);size-=len(chunk)
    return hasher.hexdigest()

def text_payload(stream,obj,endian):
    stream.seek(obj['offset']);reader=Reader(stream,obj['offset']+obj['size'],endian)
    name_size=reader.count(4096);name=reader.read(name_size).decode('utf-8');reader.align()
    length=reader.count(256*1024*1024);offset=stream.tell()
    if offset+length>reader.limit:raise ValueError('TextAsset payload exceeds object')
    return name,offset,length

def main():
    source=ROOT/'unpacked'/'effective'/'romfs'/'Data'
    exported=ROOT/'analysis'/'assets'/'unity-export'/'ExportedProject'/'Assets'
    export_hashes=collections.defaultdict(list)
    for path in exported.rglob('*.bytes'):
        with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        export_hashes[digest].append(str(path))
    db=sqlite3.connect(ROOT/'analysis'/'assets'/'assets.sqlite')
    names={(file,path_id):(kind,name) for file,path_id,kind,name in db.execute('SELECT source_file,path_id,class,name FROM assets')}
    files=[];class_counts=collections.Counter();text_count=matches=0
    manifest=destination(ROOT,ROOT/'analysis'/'assets'/'source-objects.jsonl')
    with manifest.open('w',encoding='utf-8') as writer:
        for path in sorted(source.rglob('*')):
            if not path.is_file():continue
            with path.open('rb') as stream:header=stream.read(20)
            if len(header)<20 or struct.unpack_from('>I',header,8)[0]!=17:continue
            with path.open('rb') as stream:
                data=parse(stream,path.stat().st_size)
                entry={key:value for key,value in data.items() if key not in ('objects','types')}
                entry.update(path=str(path),objects=len(data['objects']),type_count=len(data['types']))
                files.append(entry)
                for obj in data['objects']:
                    row=dict(source_file=str(path),source_relative=str(path.relative_to(source)),**obj)
                    row['object_sha256']=hash_range(stream,obj['offset'],obj['size'])
                    kind,name=names.get((path.name,obj['path_id']),('UNKNOWN',''))
                    row.update(class_name=kind,name=name,provenance='serialized object table; direct file offset and bytes')
                    class_counts[kind]+=1
                    if obj['class_id']==49:
                        text_count+=1
                        raw_name,offset,length=text_payload(stream,obj,data['endian'])
                        digest=hash_range(stream,offset,length)
                        matched=export_hashes.get(digest,[])
                        row.update(raw_name=raw_name,payload_offset=offset,payload_size=length,payload_sha256=digest,
                            export_matches=matched,export_status='EXACT_RAW_PAYLOAD_MATCH' if matched else 'MISSING_OR_CHANGED')
                        matches+=bool(matched)
                    writer.write(json.dumps(row,ensure_ascii=False)+'\n')
            print(path.name,len(data['objects']),'objects',flush=True)
    report=dict(files=files,total_objects=sum(class_counts.values()),class_counts=dict(class_counts),
        text_assets=text_count,exact_text_payload_matches=matches,unmatched_text_assets=text_count-matches,
        status='PASS_RAW_TEXT_EXPORT_INTEGRITY' if text_count and matches==text_count else 'FAIL_TEXT_EXPORT_INTEGRITY',
        limitations=['Texture/audio stream references are retained by raw extraction and AssetRipper; not decoded by this narrow parser.',
          'Unity project GUIDs generated by AssetRipper are not assumed to be original source-project GUIDs.'],manifest=str(manifest))
    destination(ROOT,ROOT/'analysis'/'assets'/'source-manifest-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(report['status'],report['total_objects'],'objects;',text_count,'TextAssets;',matches,'exact payload matches',flush=True)
    if matches!=text_count:raise RuntimeError('TextAsset export integrity mismatch')

if __name__=='__main__':main()
