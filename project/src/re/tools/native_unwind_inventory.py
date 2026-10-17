"""Validate NSO exception-frame ranges independently of managed metadata."""
import bisect
import collections
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

class Image:
    def __init__(self,raw):
        if raw[:4]!=b'NSO0':raise ValueError('Expected uncompressed NSO image')
        self.raw=raw;self.segments=[struct.unpack_from('<III',raw,h) for h in (0x10,0x20,0x30)]
        for offset,rva,size in self.segments:
            if offset<0x100 or offset+size>len(raw) or rva+size>0x100000000:raise ValueError('Invalid NSO segment bounds')
    def read(self,address,size):
        if size<0:raise ValueError('Negative read size')
        for offset,rva,length in self.segments:
            if rva<=address and address+size<=rva+length:return self.raw[offset+address-rva:offset+address-rva+size]
        raise ValueError(f'Unmapped read {address:#x}+{size:#x}')

class Cursor:
    def __init__(self,image,start,end):
        if start>end:raise ValueError('Invalid cursor range')
        self.image=image;self.position=start;self.end=end
    def take(self,count):
        if count<0 or self.position+count>self.end:raise ValueError('Truncated frame data')
        result=self.image.read(self.position,count);self.position+=count;return result
    def number(self,fmt):return struct.unpack('<'+fmt,self.take(struct.calcsize('<'+fmt)))[0]
    def leb(self,signed=False):
        value=0
        for shift in range(0,70,7):
            byte=self.number('B');value|=(byte&127)<<shift
            if byte<128:
                if signed and byte&64:value-=1<<(shift+7)
                if (signed and not -(1<<63)<=value<(1<<63)) or (not signed and value>=(1<<64)):raise ValueError('LEB128 overflow')
                return value
        raise ValueError('Unterminated LEB128')
    def cstring(self,maximum=32):
        output=bytearray()
        for _ in range(maximum):
            byte=self.number('B')
            if byte==0:return output.decode('ascii')
            if not 32<=byte<127:raise ValueError('Non-ASCII augmentation')
            output.append(byte)
        raise ValueError('Augmentation exceeds bound')
    def encoded(self,encoding,data_base=None):
        if encoding==255 or encoding&128:raise ValueError('Omitted/indirect address is not directly resolved')
        at=self.position;form=encoding&15
        formats={0:'Q',2:'H',3:'I',4:'Q',10:'h',11:'i',12:'q'}
        if form in formats:value=self.number(formats[form])
        elif form in (1,9):value=self.leb(form==9)
        else:raise ValueError('Unsupported pointer data format')
        application=encoding&112
        if application==0:return value
        if application==16:return at+value
        if application==48 and data_base is not None:return data_base+value
        raise ValueError('Unsupported or missing relative-address base')

def record(image,address,region_start,region_end):
    if not region_start<=address<region_end:raise ValueError('Frame outside exception region')
    cursor=Cursor(image,address,region_end);length=cursor.number('I')
    if length in (0,0xffffffff) or length<4:raise ValueError('Only nonempty DWARF32 exception records are accepted')
    end=address+4+length
    if end>region_end:raise ValueError('Exception record exceeds region')
    cursor.end=end;return cursor,end

def cie(image,address,region_start,region_end):
    cursor,end=record(image,address,region_start,region_end)
    if cursor.number('I')!=0:raise ValueError('CIE identifier is not zero')
    version=cursor.number('B')
    if version not in (1,3):raise ValueError('Unsupported CIE version')
    augmentation=cursor.cstring();code_align=cursor.leb();data_align=cursor.leb(True)
    return_register=cursor.number('B') if version==1 else cursor.leb()
    pointer_encoding=0;lsda_encoding=255;personality=None
    if augmentation:
        if not augmentation.startswith('z'):raise ValueError('Unsupported augmentation without size')
        augmentation_size=cursor.leb();augmentation_end=cursor.position+augmentation_size
        if augmentation_end>end:raise ValueError('CIE augmentation exceeds record')
        for letter in augmentation[1:]:
            if letter=='R':pointer_encoding=cursor.number('B')
            elif letter=='L':lsda_encoding=cursor.number('B')
            elif letter=='P':
                encoding=cursor.number('B')
                # Record the encoded reference, never dereference a dynamic
                # loader GOT slot or pretend to resolve a personality import.
                personality=dict(encoding=encoding,reference=cursor.encoded(encoding&127))
            elif letter in 'SBG':pass
            else:raise ValueError('Unknown CIE augmentation field')
        if cursor.position!=augmentation_end:raise ValueError('CIE augmentation length mismatch')
    return dict(rva=address,end_rva=end,version=version,augmentation=augmentation,code_alignment=code_align,
        data_alignment=data_align,return_register=return_register,pointer_encoding=pointer_encoding,lsda_encoding=lsda_encoding,
        personality=personality,cfi_start=cursor.position)

def fde(image,address,table_start,region_start,region_end,cache):
    cursor,end=record(image,address,region_start,region_end)
    link_address=cursor.position;link=cursor.number('I')
    if link==0:raise ValueError('FDE points to a CIE record itself')
    cie_address=link_address-link
    if cie_address not in cache:cache[cie_address]=cie(image,cie_address,region_start,region_end)
    context=cache[cie_address]
    start=cursor.encoded(context['pointer_encoding']);size=cursor.encoded(context['pointer_encoding']&15)
    if start!=table_start:raise ValueError('Search-table start and FDE start disagree')
    text_start=image.segments[0][1];text_end=text_start+image.segments[0][2]
    if size<=0 or start%4 or size%4 or not text_start<=start<start+size<=text_end:raise ValueError('FDE code range outside aligned NSO text')
    if context['augmentation'].startswith('z'):
        augmentation_size=cursor.leb();cursor.take(augmentation_size)
    return dict(rva=start,end_rva=start+size,fde_rva=address,fde_end_rva=end,cie_rva=cie_address,cfi_start=cursor.position,cfi_bytes=end-cursor.position)

def inventory(image):
    mod=struct.unpack('<I',image.read(4,4))[0]
    # Relative 32-bit fields can point backwards in rtld. Sign extension is
    # required; treating a negative displacement as uint32 adds four GiB.
    magic,*offsets=struct.unpack('<4s6i',image.read(mod,28))
    if magic!=b'MOD0':raise ValueError('Invalid MOD0 magic')
    header_start=mod+offsets[3];header_end=mod+offsets[4]
    cursor=Cursor(image,header_start,header_end)
    version,frame_encoding,count_encoding,table_encoding=cursor.take(4)
    if version!=1 or table_encoding!=0x3b:raise ValueError('Expected version-1 signed data-relative table')
    frame_start=cursor.encoded(frame_encoding);count=cursor.encoded(count_encoding)
    if not 0<count<=1000000 or cursor.position+count*8!=header_end:raise ValueError('Frame table count/extent mismatch')
    ro_start=image.segments[1][1];ro_end=ro_start+image.segments[1][2]
    if not (ro_start<=header_start<header_end<=ro_end and ro_start<=frame_start<ro_end):raise ValueError('Exception sections not inside read-only segment')
    frames=[];errors=[];cache={};previous=-1
    for index in range(count):
        start=cursor.encoded(table_encoding,header_start);address=cursor.encoded(table_encoding,header_start)
        if start<previous:raise ValueError('Search table is not sorted')
        previous=start
        try:
            row=fde(image,address,start,frame_start,ro_end,cache)
            context=cache[row['cie_rva']]
            if (row['fde_rva']<header_end and row['fde_end_rva']>header_start) or (context['rva']<header_end and context['end_rva']>header_start):raise ValueError('Exception record overlaps its search header')
            frames.append(row)
        except (ValueError,struct.error,UnicodeError) as error:errors.append(dict(index=index,rva=start,fde_rva=address,error=str(error)))
    return dict(mod0_rva=mod,header_start=header_start,header_end=header_end,frame_start=frame_start,declared_entries=count,
        frames=frames,errors=errors,cies=list(cache.values()))

def main():
    folder=destination(ROOT,ROOT/'analysis/nso/unwind-inventory-v1')
    if folder.exists():raise ValueError('Preserve prior unwind inventory')
    raw=(ROOT/'analysis/nso/main-uncompressed.nso').read_bytes();image=Image(raw);result=inventory(image)
    folder.mkdir(parents=True)
    for name,rows in [('frames',result['frames']),('errors',result['errors'])]:
        with destination(ROOT,folder/(name+'.jsonl')).open('w',encoding='utf-8') as stream:
            for row in rows:stream.write(json.dumps(row)+'\n')
    destination(ROOT,folder/'cies.json').write_text(json.dumps(result['cies'],indent=2)+'\n',encoding='utf-8')
    starts=sorted({row['rva'] for row in result['frames']});ends={row['rva']:row['end_rva'] for row in result['frames']}
    metadata=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    methods={row['Address'] for row in metadata['ScriptMethod']}
    db=sqlite3.connect((ROOT/'analysis/nso/corpus.sqlite').as_uri()+'?mode=ro',uri=True)
    exported={row[0] for row in db.execute("SELECT rva FROM functions WHERE status='PSEUDOCODE_EXPORTED'")};db.close()
    inside=0
    for address in methods-set(starts):
        i=bisect.bisect_right(starts,address)-1
        if i>=0 and starts[i]<=address<ends[starts[i]]:inside+=1
    overlaps=0;covered=0;last_end=image.segments[0][1]
    for row in sorted(result['frames'],key=lambda row:row['rva']):
        if row['rva']<last_end:overlaps+=1
        covered+=max(0,row['end_rva']-max(last_end,row['rva']));last_end=max(last_end,row['end_rva'])
    report={key:result[key] for key in ('mod0_rva','header_start','header_end','frame_start','declared_entries')}
    report.update(status='PASS_FRAME_RANGE_INVENTORY' if not result['errors'] else 'PARTIAL_FRAME_INVENTORY_WITH_ERRORS',
        validated_records=len(result['frames']),errors=len(result['errors']),unique_range_starts=len(starts),cies=len(result['cies']),
        metadata_unique_addresses=len(methods),metadata_at_range_start=len(methods&set(starts)),metadata_inside_other_ranges=inside,
        metadata_not_covered=len(methods-set(starts))-inside,indexed_pseudocode_addresses=len(exported),
        range_starts_with_pseudocode=len(set(starts)&exported),range_starts_without_pseudocode=len(set(starts)-exported),
        overlapping_ranges=overlaps,covered_text_bytes=covered,text_bytes=image.segments[0][2],source_sha256=hashlib.sha256(raw).hexdigest(),
        cie_augmentation_counts=dict(collections.Counter(row['augmentation'] for row in result['cies'])),
        references=['https://refspecs.linuxfoundation.org/LSB_4.0.0/LSB-Core-generic/LSB-Core-generic.html',
            'https://refspecs.linuxfoundation.org/LSB_4.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html',
            'https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/libunwind/src/DwarfParser.hpp'],
        scope='Original MOD0 and exception-header table, every selected FDE/CIE record, pointer encodings, independent start agreement, record extents and aligned text ranges. CFI instruction programs, LSDA landing pads, personalities, actual stack unwinding and function semantics are not executed or certified. Ranges may include fragments and are not a semantic function-completion denominator. Coverage is the corpus snapshot when this report was generated.')
    destination(ROOT,folder/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    destination(ROOT,ROOT/'reports/native-unwind-inventory.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
    if result['errors']:raise ValueError('Some FDE records failed; inspect preserved errors before using their targets')
if __name__=='__main__':main()
