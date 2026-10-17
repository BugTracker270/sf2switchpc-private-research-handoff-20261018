"""Recover bounded LZMA-alone tactic data; original compressed TextAssets retained."""
import collections
import hashlib
import json
import lzma
from pathlib import Path
import struct
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination,require_space
ROOT=Path(__file__).resolve().parents[3]

def decompress(data,maximum=64*1024*1024):
    if len(data)<13:raise ValueError('Truncated LZMA-alone header')
    expected=struct.unpack_from('<Q',data,5)[0]
    known=expected!=0xffffffffffffffff
    if known and not 0<expected<=maximum:raise ValueError('Uncompressed length exceeds explicit limit')
    limit=expected if known else maximum
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE,memlimit=64*1024*1024)
    decoded=decoder.decompress(data,max_length=limit+1)
    if len(decoded)>limit or (known and len(decoded)!=expected) or not decoder.eof or decoder.unused_data:raise ValueError('LZMA size, EOF or trailing-data mismatch')
    return decoded

def header(data):
    if len(data)<4:raise ValueError('Tactic header truncated')
    version=struct.unpack_from('<I',data)[0];offset=4;names=[]
    if version not in (1,2):raise ValueError('Unknown tactic format version')
    for _ in range(2 if version==1 else 1):
        end=data.find(b'\0',offset,min(len(data),offset+257))
        if end<0:raise ValueError('Weapon identifier terminator absent')
        names.append(data[offset:end].decode('utf-8',errors='strict'));offset=end+1
    return dict(version_candidate=version,weapon_identifiers=names,payload_start=offset,
        interpretation='First uint32 and two zero-terminated strings observed; remaining table schema requires native-reader validation.')

def main():
    source=ROOT/'analysis/assets/unity-export/ExportedProject/Assets/Resources/gamedata/tactics_compressed'
    output=destination(ROOT,Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'analysis/assets/tactics-decoded-v2');output.mkdir(exist_ok=True)
    manifest=destination(ROOT,output/'manifest.jsonl')
    if manifest.exists():raise ValueError('Preserve prior tactics manifest')
    files=sorted(source.glob('*.bytes'));advertised=0
    for path in files:
        with path.open('rb') as stream:data=stream.read(13)
        if len(data)==13 and data[0]==0x5d:
            size=struct.unpack_from('<Q',data,5)[0]
            if size<=64*1024*1024:advertised+=size
    require_space(ROOT,min(advertised,2*1024**3)+100*1024**2)
    rows=[];identifiers=set();versions=collections.Counter()
    with manifest.open('w',encoding='utf-8') as writer:
        for i,path in enumerate(files,1):
            data=path.read_bytes();row=dict(source=str(path.relative_to(ROOT)),compressed_bytes=len(data),source_sha256=hashlib.sha256(data).hexdigest())
            try:
                if data.lstrip().startswith(b'<'):
                    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():raise ValueError('DTD/entity forbidden')
                    tree=ET.fromstring(data);row.update(status='PARSED_UNCOMPRESSED_XML_REFERENCE',root_tag=tree.tag,xml_elements=sum(1 for _ in tree.iter()))
                    rows.append(row);writer.write(json.dumps(row)+'\n');continue
                decoded=decompress(data);metadata=header(decoded)
                target=destination(ROOT,output/(path.stem+'.bin'))
                if target.exists():raise ValueError('Decoded target exists')
                target.write_bytes(decoded);row.update(output=str(target.relative_to(ROOT)),decoded_bytes=len(decoded),decoded_sha256=hashlib.sha256(decoded).hexdigest(),
                    **metadata,status='PASS_BOUNDED_LZMA_SIZE_EOF')
                versions[metadata['version_candidate']]+=1;identifiers.update(metadata['weapon_identifiers'])
            except Exception as error:row.update(status='ERROR_OR_OTHER_FORMAT',error=str(error),header_hex=data[:16].hex())
            rows.append(row);writer.write(json.dumps(row)+'\n')
            if i%100==0:writer.flush();print(i,'/',len(files),'tactic payloads inspected',flush=True)
    report=dict(total=len(rows),status_counts=dict(collections.Counter(r['status'] for r in rows)),
        decoded_bytes=sum(r.get('decoded_bytes',0) for r in rows),version_candidates=dict(versions),weapon_identifiers=sorted(identifiers),
        unresolved=[r for r in rows if r['status']=='ERROR_OR_OTHER_FORMAT'],
        limitation='Decompression integrity and observed headers only. AI table layout, selection behavior and runtime reachability remain under investigation.')
    destination(ROOT,output/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2),flush=True)
if __name__=='__main__':main()
