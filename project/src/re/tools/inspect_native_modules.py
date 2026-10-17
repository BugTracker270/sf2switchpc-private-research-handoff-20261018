"""Verify all supplied ExeFS NSOs and inventory dependency-module code ranges."""
import collections
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from native_unwind_inventory import Image,inventory
from nso_symbol_inventory import symbols
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--revision',type=int,default=2);args=parser.parse_args()
    if not 1<=args.revision<=99:raise ValueError('Invalid module inventory revision')
    folder=destination(ROOT,ROOT/f'analysis/nso/module-inventory-v{args.revision}')
    if folder.exists():raise ValueError('Preserve prior module inventory')
    folder.mkdir(parents=True);modules={}
    for name in ('main','rtld','sdk','subsdk0'):
        source=ROOT/'unpacked/effective/exefs'/name;path=ROOT/f'analysis/nso/{name}-uncompressed.nso'
        raw=path.read_bytes();image=Image(raw);original=source.read_bytes();checks=[]
        flags=struct.unpack_from('<I',original,12)[0]
        if struct.unpack_from('<I',raw,12)[0]&7:raise ValueError('Image remains compressed')
        for index,(offset,rva,size) in enumerate(image.segments):
            expected=original[0xa0+index*32:0xc0+index*32].hex();actual=hashlib.sha256(raw[offset:offset+size]).hexdigest()
            checked=bool(flags&(1<<(index+3)))
            if checked and actual!=expected:raise ValueError('Original NSO segment digest mismatch')
            checks.append(dict(segment=('text','rodata','data')[index],rva=rva,bytes=size,hash_enabled=checked,sha256=actual,header_hash_match=actual==expected))
        rows,symbol_hash=symbols(path)
        if symbol_hash!=digest(path):raise ValueError('Symbol/image hash mismatch')
        function_symbols=[row for row in rows if row['role']=='EXPORT' and row['type']==2]
        families={family:sum(family.lower() in row['name'].lower() for row in rows) for family in ('FMOD','nvn','nn','opus','vorbis','avcodec','malloc')}
        module=dict(source_sha256=digest(source),uncompressed_sha256=symbol_hash,build_id=raw[0x40:0x60].hex(),segments=checks,
            dynamic_symbols=len(rows),symbol_roles=dict(collections.Counter(row['role'] for row in rows)),
            defined_function_symbols=len(function_symbols),unique_defined_function_addresses=len({row['value'] for row in function_symbols}),symbol_name_family_counts=families)
        if name=='main':
            frame_summary=json.loads((ROOT/'reports/native-unwind-inventory.json').read_text())
            module['unwind']=dict(status=frame_summary['status'],validated_ranges=frame_summary['validated_records'],errors=frame_summary['errors'],source='reports/native-unwind-inventory.json')
        else:
            try:
                frame=inventory(image)
                module['unwind']=dict(status='PASS_FRAME_RANGE_INVENTORY' if not frame['errors'] else 'PARTIAL_FRAME_INVENTORY_WITH_ERRORS',declared_entries=frame['declared_entries'],validated_ranges=len(frame['frames']),errors=len(frame['errors']),cies=len(frame['cies']))
                for kind in ('frames','errors','cies'):
                    with destination(ROOT,folder/(name+'-'+kind+'.jsonl')).open('w',encoding='utf-8') as stream:
                        for row in frame[kind]:stream.write(json.dumps(row)+'\n')
            except (ValueError,struct.error) as error:
                module['unwind']=dict(status='UNSUPPORTED_OR_ABSENT_FRAME_HEADER',error=str(error),validated_ranges=None)
        modules[name]=module
    report=dict(status='PASS_SUPPLIED_MODULE_IMAGES_AND_SEGMENT_HASHES',modules=modules,
        scope='Original supplied main/rtld/sdk/subsdk0 NSOs only. Enabled segment hashes are compared with original compressed-module headers; symbol-name families are string observations, not runtime reachability. Additional module FDE decoding is reported independently and can be absent/unsupported. No SDK download, native library implementation parity, OS emulation or whole-NSP semantic completion claim.')
    destination(ROOT,folder/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    destination(ROOT,ROOT/'reports/native-module-inventory.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
