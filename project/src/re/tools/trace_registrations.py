"""Independently locate ARM64 ADRP+ADD references to recovered registration RVAs."""
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def signed(value,bits):return value-(1<<bits) if value&(1<<(bits-1)) else value

def adrp_target(word,pc):
    if word&0x9f000000!=0x90000000:return None
    immediate=((word>>5)&0x7ffff)*4+((word>>29)&3)
    return (pc&~4095)+(signed(immediate,21)<<12)

def add_immediate(word):
    if word&0xff800000!=0x91000000:return None
    return (word&31,(word>>5)&31,((word>>10)&4095)<<(12 if word&(1<<22) else 0))

def main():
    source=ROOT/'analysis/nso/main-uncompressed.nso';data=source.read_bytes()
    text_file,text_rva,text_size=struct.unpack_from('<III',data,0x10)
    targets={0x3925210:'Il2CppDumper/Cpp2IL code registration',0x3925280:'Il2CppDumper/Cpp2IL metadata registration'}
    pointer_locations={}
    for segment_offset in (0x10,0x20,0x30):
        file_offset,rva,size=struct.unpack_from('<III',data,segment_offset)
        for target in targets:
            needle=struct.pack('<Q',target);position=file_offset
            while True:
                position=data.find(needle,position,file_offset+size)
                if position<0:break
                if position%8==0:pointer_locations[rva+position-file_offset]=target
                position+=1
    pages={v&~4095 for v in (*targets,*pointer_locations)};matches=[]
    for offset in range(0,text_size-4,4):
        pc=text_rva+offset;word=struct.unpack_from('<I',data,text_file+offset)[0]
        page=adrp_target(word,pc)
        if page not in pages:continue
        register=word&31
        for distance in range(4,40,4):
            add_pc=pc+distance
            if offset+distance+4>text_size:break
            add_word=struct.unpack_from('<I',data,text_file+offset+distance)[0]
            decoded=add_immediate(add_word)
            formed=page+decoded[2] if decoded and decoded[1]==register else None
            load=((add_word&0xffc00000)==0xf9400000 and ((add_word>>5)&31)==register)
            pointer_location=page+((add_word>>10)&4095)*8 if load else None
            indirect=pointer_location in pointer_locations
            if formed in targets or indirect:
                target=pointer_locations[pointer_location] if indirect else formed
                destination_register=add_word&31 if indirect else decoded[0]
                context=[]
                for context_pc in range(max(text_rva,pc-16),min(text_rva+text_size,add_pc+48),4):
                    w=struct.unpack_from('<I',data,text_file+context_pc-text_rva)[0]
                    row=dict(rva=hex(context_pc),word_hex=hex(w))
                    if w&0x7c000000==0x14000000:
                        row.update(branch_kind='BL' if w&(1<<31) else 'B',target_rva=hex(context_pc+signed(w&0x3ffffff,26)*4))
                    context.append(row)
                matches.append(dict(adrp_rva=hex(pc),add_or_load_rva=hex(add_pc),operation='LDR_GOT_POINTER' if indirect else 'ADD_ADDRESS',
                    pointer_location=hex(pointer_location) if indirect else None,destination_register='X'+str(destination_register),
                    target_rva=hex(target),target_evidence=targets[target],context=context))
    report=dict(source=str(source),pointer_locations={hex(k):hex(v) for k,v in pointer_locations.items()},matches=matches,status='STATIC_REFERENCES_FOUND' if len({x['target_rva'] for x in matches})==2 else 'INCOMPLETE',
        limitation='Static address formation and nearby branch evidence. Registration invocation and runtime metadata initialization still require separate validation.')
    destination(ROOT,ROOT/'analysis/nso/registration-xrefs.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    for m in matches:print(m['adrp_rva'],m['add_or_load_rva'],m['operation'],m['destination_register'],m['target_rva'])
    print(report['status'])
if __name__=='__main__':main()
