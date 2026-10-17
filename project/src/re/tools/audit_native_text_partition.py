"""Account for original text bytes without treating padding-like bytes as proven dead code."""
import collections
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
from native_unwind_inventory import Image
ROOT=Path(__file__).resolve().parents[3]

def partition(start,end,ranges):
    if start<0 or end<start:raise ValueError('Invalid text extent')
    result=[];cursor=start
    for a,b,kind in sorted(ranges):
        if a<cursor or b<=a or b>end:raise ValueError('Overlapping or out-of-bounds ranges')
        if a>cursor:result.append((cursor,a,'RESIDUAL'))
        result.append((a,b,kind));cursor=b
    if cursor<end:result.append((cursor,end,'RESIDUAL'))
    if sum(b-a for a,b,_ in result)!=end-start:raise ValueError('Text accounting differs')
    return result

def words(data):
    if len(data)%4:raise ValueError('Unaligned residual text')
    values=collections.Counter(value[0] for value in struct.iter_unpack('<I',data))
    return dict(zero_bytes=4*values[0],nop_bytes=4*values[0xd503201f],
        other_bytes=len(data)-4*values[0]-4*values[0xd503201f],
        most_common_words=[dict(word=f'0x{value:08x}',count=count) for value,count in values.most_common(8)])

def main():
    image=Image((ROOT/'analysis/nso/main-uncompressed.nso').read_bytes());digest=hashlib.sha256(image.raw).hexdigest()
    manifest=json.loads((ROOT/'reports/native-unwind-inventory.json').read_text(encoding='utf-8-sig'))
    frame_path=ROOT/'analysis/nso/unwind-inventory-v1/frames.jsonl'
    if hashlib.sha256(frame_path.read_bytes()).hexdigest()!=manifest['frames_file_sha256']:raise ValueError('Frame inventory changed')
    plt=json.loads((ROOT/'analysis/nso/validated-plt-layout.json').read_text(encoding='utf-8-sig'))
    if plt['status']!='PASS_ORIGINAL_PLT_BYTES_AND_GOT_LAYOUT' or plt['original_nso_sha256']!=digest or plt['code_bytes_modified']:raise ValueError('Original PLT byte evidence required')
    rows=[(row['rva'],row['end_rva'],'VALIDATED_FRAME') for row in map(json.loads,frame_path.open(encoding='utf-8'))]
    rows.append((plt['start_rva'],plt['start_rva']+plt['bytes'],'VALIDATED_PLT'))
    _,start,length=image.segments[0]
    result=partition(start,start+length,rows);counts=collections.Counter();gaps=collections.Counter();residuals=0
    path=destination(ROOT,ROOT/'analysis/nso/text-residual-partition-v1.jsonl')
    with path.open('w',encoding='utf-8') as output:
        for a,b,kind in result:
            counts[kind]+=b-a
            if kind!='RESIDUAL':continue
            data=image.read(a,b-a);observed=words(data);residuals+=1
            for key in ('zero_bytes','nop_bytes','other_bytes'):gaps[key]+=observed[key]
            output.write(json.dumps(dict(start_rva=a,end_rva=b,bytes=b-a,sha256=hashlib.sha256(data).hexdigest(),**observed))+'\n')
    report=dict(status='PASS_BYTE_PARTITION_RESIDUAL_REVIEW_REQUIRED',source_nso_sha256=digest,text_bytes=length,
        bytes_by_inventory_kind=dict(counts),residual_regions=residuals,residual_word_observations=dict(gaps),
        details=str(path.relative_to(ROOT)),complete_source=False,
        scope='Exact nonoverlapping byte partition using validated FDE extents and independently verified PLT entries. Residual zero/NOP words are byte observations and not proof of padding, dead code or source completeness. Other residual words include module/bootstrap material and require code/data review. Function bodies/control flow can cross FDE bounds; no code is modified or automatically discarded.')
    destination(ROOT,ROOT/'reports/native-text-partition.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
