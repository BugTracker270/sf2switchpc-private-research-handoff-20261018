"""Bounds-check the observed Unity 2018.1 IL2CPP v24 ARM64 registration tables.

Layout cross-check: pinned Il2CppDumper and LibCpp2IL structure definitions.
Only known table strides are interpreted; interop records are not guessed.
"""
import collections
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

class Image:
    def __init__(self,data):
        if data[:4]!=b'NSO0' or struct.unpack_from('<I',data,12)[0]&7:raise ValueError('Decompressed NSO required')
        self.data=data;self.segments=[struct.unpack_from('<III',data,o) for o in (0x10,0x20,0x30)]
        if any(off+size>len(data) for off,rva,size in self.segments):raise ValueError('NSO segment file bounds')
        self.bss_size=struct.unpack_from('<I',data,0x3c)[0]
    def read(self,rva,size):
        if size<0:raise ValueError('Negative read size')
        for off,start,length in self.segments:
            if start<=rva and rva+size<=start+length:return self.data[off+rva-start:off+rva-start+size]
        raise ValueError('Read outside file-backed segment')
    def pointers(self,rva,count):
        if not 0<=count<=10000000:raise ValueError('Pointer count bounds')
        return [v[0] for v in struct.iter_unpack('<Q',self.read(rva,count*8))]
    def executable(self,rva):
        _,start,size=self.segments[0];return start<=rva<start+size
    def writable(self,rva):
        _,start,size=self.segments[2];return start<=rva<start+size+self.bss_size

def main():
    image=Image((ROOT/'analysis/nso/main-uncompressed.nso').read_bytes())
    code_names=['methodPointers','reversePInvokeWrappers','genericMethodPointers','invokerPointers','customAttributeGenerators','unresolvedVirtualCallPointers','interopData']
    meta_names=['genericClasses','genericInsts','genericMethodTable','types','methodSpecs','fieldOffsets','typeDefinitionSizes','metadataUsages']
    report=dict(code_registration_rva='0x3925210',metadata_registration_rva='0x3925280',code_tables={},metadata_tables={})
    code_pointers=set()
    for index,name in enumerate(code_names):
        count,pointer=struct.unpack('<QQ',image.read(0x3925210+index*16,16))
        entry=dict(count=count,pointer_rva=hex(pointer))
        if name!='interopData':
            values=image.pointers(pointer,count) if count else []
            invalid=[v for v in values if v and not image.executable(v)]
            entry.update(nonzero=sum(v!=0 for v in values),outside_text=len(invalid),unique_nonzero=len(set(values)-{0}),validation='BOUNDED_POINTER_TABLE')
            if invalid:raise ValueError('Code pointer outside executable text: '+name)
            if name in ('methodPointers','genericMethodPointers'):code_pointers.update(values)
        else:
            if count:image.read(pointer,1)
            entry['validation']='START_MAPPED_RECORD_STRIDE_NOT_INTERPRETED'
        report['code_tables'][name]=entry
    for index,name in enumerate(meta_names):
        count,pointer=struct.unpack('<QQ',image.read(0x3925280+index*16,16))
        if count>10000000:raise ValueError('Metadata count bounds')
        stride=12 if name in ('genericMethodTable','methodSpecs') else 8
        values=image.pointers(pointer,count) if count and stride==8 else []
        if count:image.read(pointer,count*stride)
        entry=dict(count=count,pointer_rva=hex(pointer),validated_table_bytes=count*stride)
        if name=='metadataUsages':
            invalid=[v for v in values if not image.writable(v)]
            entry.update(slots_outside_writable_memory=len(invalid))
            if invalid:raise ValueError('Metadata usage slot outside writable memory')
        report['metadata_tables'][name]=entry
    script=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    addresses={row['Address'] for row in script['ScriptMethod']}
    missing=sorted(addresses-code_pointers)
    report.update(metadata_method_records=len(script['ScriptMethod']),metadata_unique_addresses=len(addresses),
        metadata_addresses_in_native_registration=len(addresses)-len(missing),missing_addresses=[hex(a) for a in missing],
        status='PASS_REGISTRATION_ADDRESS_CONSISTENCY' if not missing else 'FAIL_ADDRESS_MAPPING',
        limitation='Valid pointer-table/address membership does not establish correct method-to-name aliases or recovered function semantics.')
    destination(ROOT,ROOT/'analysis/il2cpp/registration-integrity.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
    if missing:raise ValueError('Metadata method mappings absent from native registration')
if __name__=='__main__':main()
