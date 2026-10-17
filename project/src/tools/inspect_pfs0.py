"""Read-only PFS0 inventory and optional bounded NCA copying; never decrypts.

Format reference: SciresM/hactool pfs0.h (ISC). Implemented independently.
No ticket/key bytes are emitted. NCA labels remain unknown for encrypted headers.
"""
import argparse
import hashlib
import json
import re
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from usb_boundary import destination, require_space

def read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError('Truncated container')
    return data

def parse_pfs0(stream, total):
    magic, count, strings_size, reserved = struct.unpack('<4sIII', read_exact(stream, 16))
    if magic != b'PFS0':
        raise ValueError('Input is not PFS0')
    header_size = 16 + count * 24 + strings_size
    if count > 100000 or strings_size > 64*1024*1024 or header_size > total or reserved:
        raise ValueError('Invalid PFS0 header limits/reserved field')
    entries = [struct.unpack('<QQII', read_exact(stream, 24)) for _ in range(count)]
    strings = read_exact(stream, strings_size)
    result, names, extents = [], set(), []
    for offset, size, name_offset, padding in entries:
        if padding or name_offset >= len(strings):
            raise ValueError('Invalid PFS0 entry')
        end = strings.find(b'\0', name_offset)
        if end < 0:
            raise ValueError('Unterminated filename')
        name = strings[name_offset:end].decode('utf-8', errors='strict')
        if not name or name in ('.', '..') or any(c in name for c in '/\\:') or name.endswith((' ', '.')) or any(ord(c)<32 for c in name):
            raise ValueError('Unsafe PFS0 filename')
        if name.casefold() in names:
            raise ValueError('Duplicate or case-colliding filename')
        if re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', name, re.I):
            raise ValueError('Reserved Windows filename')
        names.add(name.casefold())
        absolute = header_size + offset
        if absolute + size > total:
            raise ValueError('PFS0 entry exceeds input')
        if size:
            extents.append((absolute, absolute + size))
        result.append(dict(name=name,offset=absolute,relative_offset=offset,size=size))
    extents.sort()
    if any(a[1] > b[0] for a,b in zip(extents,extents[1:])):
        raise ValueError('Overlapping PFS0 entries')
    return dict(magic='PFS0',file_count=count,header_size=header_size,entries=result)

def inspect_nca_header(stream, offset, size):
    if size < 0x400:
        return dict(status='too_short')
    stream.seek(offset + 0x200)
    header = read_exact(stream, 0x40)
    magic = header[:4]
    if magic not in (b'NCA0', b'NCA2', b'NCA3'):
        return dict(status='encrypted_or_unrecognized',content_type='UNKNOWN',
                    note='No plaintext NCA magic at +0x200; header key required for classification')
    return dict(status='plaintext_header',magic=magic.decode(),distribution=header[4],content_type_id=header[5],
                content_type={0:'Program',1:'Meta',2:'Control',3:'Manual',4:'Data',5:'PublicData'}.get(header[5],'UNKNOWN'),
                title_id=f'{struct.unpack_from("<Q",header,0x10)[0]:016X}',
                declared_size=struct.unpack_from('<Q',header,8)[0],
                rights_managed=any(header[0x30:0x40]))

def inventory(path, root, kind, extract=False):
    path = Path(path)
    with path.open('rb') as stream:
        result = parse_pfs0(stream,path.stat().st_size)
        result.update(source=str(path),kind=kind)
        stream.seek(0)
        result['source_sha256'] = hashlib.file_digest(stream,'sha256').hexdigest()
        if extract:
            require_space(root,sum(e['size'] for e in result['entries'] if e['name'].endswith('.nca')))
        for entry in result['entries']:
            is_nca = entry['name'].endswith('.nca')
            if is_nca:
                entry['nca'] = inspect_nca_header(stream,entry['offset'],entry['size'])
            if entry['name'].endswith('.cnmt.xml') and entry['size'] <= 1024*1024:
                stream.seek(entry['offset'])
                xml = read_exact(stream,entry['size'])
                if b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():
                    raise ValueError('XML declarations forbidden')
                tree=ET.fromstring(xml)
                result['supplied_cnmt_xml'] = dict(source=entry['name'],
                    status='untrusted package sidecar; not decrypted/signed CNMT',
                    fields={child.tag:child.text for child in tree if not len(child)},
                    contents=[{field.tag:field.text for field in child} for child in tree if child.tag=='Content'])
            stream.seek(entry['offset'])
            hasher = hashlib.sha256()
            remaining = entry['size']
            output = None
            target = destination(root,Path(root)/'unpacked'/'nsp_pfs0'/kind/entry['name']) if extract and is_nca else None
            partial = destination(root,Path(str(target)+'.partial')) if target else None
            try:
                if target and not target.exists():
                    output = partial.open('xb')
                while remaining:
                    chunk = read_exact(stream,min(4*1024*1024,remaining))
                    hasher.update(chunk)
                    if output:
                        output.write(chunk)
                    remaining -= len(chunk)
                digest = hasher.hexdigest()
                if output:
                    output.flush()
                    output.close()
                    output = None
                    partial.replace(target)
                if target:
                    with target.open('rb') as check:
                        if target.stat().st_size != entry['size'] or hashlib.file_digest(check,'sha256').hexdigest() != digest:
                            raise ValueError('Existing/extracted NCA mismatch')
                    entry['output'] = str(target)
                entry['sha256'] = digest
                content_id = entry['name'].split('.')[0]
                if is_nca and re.fullmatch('[0-9a-fA-F]{32}',content_id):
                    entry['content_id_matches_sha256_prefix'] = digest.startswith(content_id.lower())
            finally:
                if output:
                    output.close()
        return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--kind',choices=['base','update'],required=True)
    parser.add_argument('--extract-ncas',action='store_true')
    args=parser.parse_args()
    report=destination(args.root,args.root/'reports'/f'package-{args.kind}.json')
    result=inventory(args.input,args.root,args.kind,args.extract_ncas)
    report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(report),entries=result['file_count'],source_sha256=result['source_sha256'],
          nca_headers=[e.get('nca',{}).get('status') for e in result['entries'] if e['name'].endswith('.nca')]),indent=2))

if __name__=='__main__':
    main()
