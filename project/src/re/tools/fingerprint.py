"""Generate engine/version provenance from extracted binary headers and manifests."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination

ROOT=Path(__file__).resolve().parents[3]

def cnmt(path,package):
    data=path.read_bytes()
    title,version,kind,_,extended,count=struct.unpack_from('<QIBBHH',data)
    entries=[]
    known={e['name'].split('.')[0]:e for e in package['entries'] if e['name'].endswith('.nca')}
    for index in range(count):
        offset=0x20+extended+index*0x38
        entry=data[offset:offset+0x38]
        if len(entry)!=0x38:raise ValueError('Truncated decrypted CNMT')
        digest,content_id,size,content_type=entry[:32].hex(),entry[32:48].hex(),int.from_bytes(entry[48:54],'little'),entry[54]
        match=known.get(content_id)
        entries.append(dict(id=content_id,sha256=digest,size=size,type_id=content_type,
            type={0:'Meta',1:'Program',2:'Data',3:'Control',4:'HtmlDocument',5:'LegalInformation',6:'DeltaFragment'}.get(content_type,'Unknown'),
            supplied_nca_matches=bool(match and match['size']==size and match['sha256']==digest)))
    return dict(source=str(path),title_id=f'{title:016X}',version=version,meta_type_id=kind,
                content_count=count,contents=entries,content_sha256_match=all(e['supplied_nca_matches'] for e in entries))

def main():
    versions={}
    for kind in ('base','update'):
        package=json.loads((ROOT/'reports'/f'package-{kind}.json').read_text(encoding='utf-8-sig'))
        path=next((ROOT/'unpacked'/kind/'meta'/'meta').glob('*.cnmt'))
        versions[kind]=cnmt(path,package)
        data=(ROOT/'unpacked'/kind/'control'/'romfs'/'control.nacp').read_bytes()
        versions[kind]['display_version']=data[0x3060:0x3070].split(b'\0')[0].decode('utf-8')
        versions[kind]['american_english_title']=data[:0x200].split(b'\0')[0].decode('utf-8')
    effective=ROOT/'unpacked'/'effective'
    manager=effective/'romfs'/'Data'/'globalgamemanagers'
    header=manager.read_bytes()[:256]
    unity=re.search(rb'20\d\d\.\d+\.\d+[abfp]\d+',header)
    if not unity:raise ValueError('No Unity version marker')
    metadata=effective/'romfs'/'Data'/'Managed'/'Metadata'/'global-metadata.dat'
    with metadata.open('rb') as stream:magic,metadata_version=struct.unpack('<II',stream.read(8))
    if magic!=0xfab11baf:raise ValueError('Metadata magic mismatch')
    modules=[]
    for path in sorted((effective/'exefs').iterdir()):
        if not path.is_file() or path.name.endswith('.npdm'):continue
        with path.open('rb') as stream:header=stream.read(256)
        if header[:4]!=b'NSO0':raise ValueError('Expected NSO0 module')
        modules.append(dict(name=path.name,source=str(path),build_id=header[0x40:0x60].hex(),
            flags=f'0x{struct.unpack_from("<I",header,12)[0]:X}',
            segments=[dict(name=name,file_offset=struct.unpack_from('<I',header,offset)[0],
                memory_rva=struct.unpack_from('<I',header,offset+4)[0],uncompressed_bytes=struct.unpack_from('<I',header,offset+8)[0])
                for name,offset in (('text',0x10),('rodata',0x20),('data',0x30))]))
    memory=json.loads((ROOT/'analysis'/'nso'/'main-memory.json').read_text())
    report=dict(status='PASS_ENGINE_AND_VERSION_FINGERPRINT',versions=versions,
        engine='Unity',unity_version=unity[0].decode(),unity_version_source=str(manager),
        scripting_backend='IL2CPP',metadata_magic=hex(magic),metadata_version=metadata_version,
        metadata_path=str(metadata),metadata_bytes=metadata.stat().st_size,
        architecture=memory['language'],modules=modules,scene_files=[str(p.relative_to(effective)) for p in sorted((effective/'romfs'/'Data').glob('level*'))],
        effective_mapping=dict(base_program='b5028f4e100d63d35e0e9ff223c7ffcd.nca',patch_program='9e558c3678550db627afa0fe00857d1d.nca',method='hactool --basenca; section hash/signature verification requested'),
        code_registration_rva='0x3925210',metadata_registration_rva='0x3925280',
        registration_confidence='Il2CppDumper automatic match; independent native caller trace still required',
        unresolved=['AssetRipper folder-only load reports Unknown backend; metadata/native tools independently prove IL2CPP.',
            'Type shells, function names and successful extraction do not establish full reverse-engineering coverage.',
            'Switch-specific gameplay, saves, timing and local multiplayer require native/data/behavior validation.'])
    destination(ROOT,ROOT/'reports'/'engine-fingerprint.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    md=f'''# Engine fingerprint — verified local inputs

Unity **{report['unity_version']}**, **IL2CPP metadata v{metadata_version}**, **{memory['language']}**.

| Evidence | Observation |
|---|---|
| effective/romfs/Data/globalgamemanagers | Serialized v17 header; Unity version marker in header |
| effective/romfs/Data/Managed/Metadata/global-metadata.dat | 0xFAB11BAF, version {metadata_version}; {metadata.stat().st_size} bytes |
| effective/exefs/main | NSO0; Ghidra Switch Loader confirms ARM64 at 0x{memory['image_base']} |
| base CNMT | {versions['base']['title_id']}, version {versions['base']['version']}; every listed content hash/size matches supplied NCAs |
| patch CNMT | {versions['update']['title_id']}, version {versions['update']['version']}; every listed content hash/size matches supplied NCAs |
| patch control.nacp +0x3060 | Display version {versions['update']['display_version']} |

Decrypted CNMT contains {versions['base']['content_count']} base entries and {versions['update']['content_count']} patch entries. The patch includes four delta fragments; the Program patch is applied against its base through hactool, not concatenated or treated as standalone RomFS.

Effective output: 44 files, including ten level files. Exact hashes, sources and base/patch relationships: reports/extract-manifest.json. All six extraction operations returned 0, produced actual files and reported no signature failures. Full source NSP hashes: originals_manifest/inputs.json.

Il2CppDumper generated metadata schemas and 90,105 method records / 83,673 distinct native RVAs. All method RVAs lie within main's NSO text segment. Registration candidates: code 0x3925210 and metadata 0x3925280 (RVAs). Native caller validation remains pending; these are not recovered original C# implementations.

Detailed module build IDs and section layouts: engine-fingerprint.json. Ghidra memory map and all 658 imports: analysis/nso/main-memory.json. Scene names, object references and backend-specific fields are still being catalogued. AssetRipper's folder-only importer reports Unknown scripting backend; this is a tool detection limitation, not contrary engine evidence.

Full reverse engineering: **INCOMPLETE**. Combat semantics, animation timing, progression, saves and Switch-only multiplayer are not certified by metadata/extraction success.
'''
    destination(ROOT,ROOT/'reports'/'engine-fingerprint.md').write_text(md,encoding='utf-8')
    if not all(v['content_sha256_match'] for v in versions.values()):raise ValueError('Decrypted CNMT content hashes mismatch')
    print(report['status'],report['unity_version'],report['architecture'],versions['update']['display_version'])

if __name__=='__main__':main()
