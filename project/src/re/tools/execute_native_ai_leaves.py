"""Execute bounded original ARM64 functions against synthetic valid containers.

No Switch OS, graphics, or game runtime is provided. Original text is read-only;
metadata initialization guards are pre-set, and no game function is mocked.
"""
import collections
import hashlib
import json
import math
from pathlib import Path
import random
import struct
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools/python-unicorn-2.1.4'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_BLOCK,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC,UC_ARM64_REG_Q0,UC_ARM64_REG_CPACR_EL1

HEAP=0x10000000;STACK=0x20000000;STOP=0x30000000
FUNCTIONS={
    'hit_damage_get':(0xf968c0,0xf968c8),
    'hit_damage_set':(0xf968d0,0xf968d8),
    'distance_within':(0x103e5a0,0x103e65c),
    'interframe':(0x103e660,0x103e7b0),
    'frame_index':(0x10418f0,0x1041964),
    'eligible_animations':(0x103e830,0x103e934),
    'list_float_count':(0x15904b0,0x15904b8),
    'list_float_item':(0x15904c0,0x1590588),
    'list_int_item':(0x1580c10,0x1580cd8),
    'list_object_count':(0x1586ea0,0x1586ea8),
    'list_object_item':(0x1586eb0,0x1586f78),
    'list_object_add':(0x1584e60,0x1584efc),
}

def f32(v):return struct.unpack('<f',struct.pack('<f',v))[0]
def next32(v,up):
    if math.isnan(v):return v
    if v==0:return struct.unpack('<f',struct.pack('<I',1 if up else 0x80000001))[0]
    bits=struct.unpack('<I',struct.pack('<f',v))[0]
    if (up and v==math.inf) or (not up and v==-math.inf):return v
    bits+=1 if (v>0)==up else -1
    return struct.unpack('<f',struct.pack('<I',bits))[0]

def expected(ds,fs,value):
    inside=len(ds)>=2 and ds[0]<=value<ds[-1]
    if not inside:return False,-1
    for i,upper in enumerate(ds[1:]):
        if value<upper:return True,fs[i]
    return True,-1

class NativeScope:
    def __init__(self):
        raw=(ROOT/'analysis/nso/main-uncompressed.nso').read_bytes();self.raw=raw
        segments=[struct.unpack_from('<III',raw,o) for o in (0x10,0x20,0x30)]
        end=max(rva+n for _,rva,n in segments)+struct.unpack_from('<I',raw,0x3c)[0]
        self.vm=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.vm.mem_map(0,(end+0xfff)&~0xfff)
        for offset,rva,n in segments:self.vm.mem_write(rva,raw[offset:offset+n])
        text_rva,text_size=segments[0][1:]
        self.vm.mem_protect(text_rva,((text_size+0xfff)//0x1000)*0x1000,UC_PROT_READ|UC_PROT_EXEC)
        self.vm.mem_map(HEAP,0x200000);self.vm.mem_map(STACK,0x100000);self.vm.mem_map(STOP,0x1000)
        self.vm.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
        self.guards=[0x3b86bdc,0x3b86bdd,0x3b89762,0x3b89703,0x3b86be4,0x3b86b59,0x3b89729]
        for rva in self.guards:self.vm.mem_write(rva,b'\1')
        self.visited=collections.Counter();self.calls=collections.Counter();self.last_blocks=[]
        self.vm.hook_add(UC_HOOK_BLOCK,self.block)
    def block(self,vm,address,size,_):
        self.last_blocks.append(address);self.last_blocks=self.last_blocks[-24:]
        for name,(start,end) in FUNCTIONS.items():
            if start<=address and address+size<=end:self.visited[name]+=1;return
        raise RuntimeError(f'Execution escaped reviewed functions at {address:#x} size {size}; trail {self.last_blocks}')
    def put(self,address,fmt,*values):self.vm.mem_write(address,struct.pack('<'+fmt,*values))
    def sequence(self,address,values,kind):
        array=address+0x100
        if len(values)*struct.calcsize('<'+kind)>0x7000:raise ValueError('Test array exceeds sandbox allocation')
        self.put(address+0x10,'Qi',array,len(values));self.put(array+0x18,'Q',len(values))
        if values:self.put(array+0x20,str(len(values))+kind,*values)
        return address
    def call(self,name,this,value=None,integer=None):
        vm=self.vm;vm.reg_write(UC_ARM64_REG_SP,STACK+0x80000);vm.reg_write(UC_ARM64_REG_X30,STOP)
        vm.reg_write(UC_ARM64_REG_X0,this);vm.reg_write(UC_ARM64_REG_X1,0 if integer is None else integer&0xffffffff)
        vm.reg_write(UC_ARM64_REG_X2,0)
        if value is not None:vm.reg_write(UC_ARM64_REG_Q0,struct.unpack('<I',struct.pack('<f',value))[0])
        self.last_blocks=[];vm.emu_start(FUNCTIONS[name][0],STOP,count=20000)
        if vm.reg_read(UC_ARM64_REG_PC)!=STOP:raise RuntimeError('Bounded function did not return')
        self.calls[name]+=1
        return vm.reg_read(UC_ARM64_REG_X0)&0xffffffff

def main():
    started=time.monotonic();print('Loading read-only ARM64 scope',flush=True)
    scope=NativeScope();checks=0;failures=[]
    print('ARM64 memory and bounded code hook ready',flush=True)
    def check(label,actual,want):
        nonlocal checks
        checks+=1
        if actual!=want:raise AssertionError(f'{label}: {actual} != {want}')
    # Actual original accessors; compare IEEE-754 payload bits including NaN.
    for bits in [0,0x80000000,0x3f800000,0xbf800000,0x7f800000,0xff800000,0x7fc12345]:
        scope.put(HEAP+0x1c,'I',bits);scope.call('hit_damage_get',HEAP)
        check('native damage getter',scope.vm.reg_read(UC_ARM64_REG_Q0)&0xffffffff,bits)
        scope.vm.reg_write(UC_ARM64_REG_Q0,bits);scope.call('hit_damage_set',HEAP)
        check('native damage setter',struct.unpack('<I',scope.vm.mem_read(HEAP+0x1c,4))[0],bits)
    # Full int32 arithmetic, including native wraparound before signed compare.
    for first in [-5,0,7,2147483647,-2147483648]:
        for count in [0,1,4]:
            scope.put(HEAP+0x10,'Q',HEAP+0x1000);scope.put(HEAP+0x20,'i',first)
            scope.put(HEAP+0x1018,'i',count)
            for frame in [-2147483648,-7,-1,0,6,7,10,2147483647]:
                index=struct.unpack('<i',struct.pack('<I',(frame-first)&0xffffffff))[0]
                want=-1 if index>=count else index
                got=scope.call('frame_index',HEAP,integer=frame)
                check('native frame offset',got,want&0xffffffff)
    source=ROOT/'analysis/assets/ai-tables-v1/unarmed-pair-expanded.json'
    data=json.loads(source.read_text(encoding='utf-8'));items=[];candidate_frames=[]
    for block in data:
        for entry in block['decoded']['entries']:
            for group in entry['groups']:
                for table in group['tables']:
                    for frame in table['frames']:
                        items.extend(frame)
                        if frame and len(frame)<=48:candidate_frames.append(frame)
    indices=random.Random(0x534632).sample(range(len(items)),min(256,len(items)))
    samples=[dict(distances=[],interframes=[]),dict(distances=[0],interframes=[]),
        dict(distances=[-2,0,0,2],interframes=[-1,0,7])]+[items[i] for i in indices]
    for sample_number,sample in enumerate(samples,1):
        ds=sample['distances'];fs=sample['interframes']
        scope.sequence(HEAP+0x10000,ds,'f');scope.sequence(HEAP+0x20000,fs,'i')
        scope.put(HEAP+0x18,'QQ',HEAP+0x10000,HEAP+0x20000)
        values=[math.nan,-math.inf,math.inf,-0.0,0.0]
        positions=sorted(set([0,len(ds)-1]+list(range(0,len(ds),max(1,len(ds)//12))))) if ds else []
        for i in positions:
            value=f32(ds[i]);values.extend([next32(value,False),value,next32(value,True)])
        for value in values:
            inside,want=expected(ds,fs,value)
            check('native inclusive/exclusive distance',scope.call('distance_within',HEAP,value),int(inside))
            check('native piecewise interframe',scope.call('interframe',HEAP,value),want&0xffffffff)
        if sample_number%32==0:print('Native interval samples',sample_number,'checks',checks,flush=True)
    # Actual candidate filter also appends to an existing receiver. Positive
    # iframes qualify; zero and negative values do not. Order is preserved.
    selection_cases=0
    frames_to_test=[[],[dict(animation='synthetic',distances=[-2,2],interframes=[v]) for v in [-1,0,5]]]
    frames_to_test += [candidate_frames[i] for i in random.Random(0x4149).sample(range(len(candidate_frames)),64)]
    for frame in frames_to_test:
        pointers=[];identities=[]
        for i,item in enumerate(frame):
            base=HEAP+0x30000+i*0x5000;identity=HEAP+0x1f0000+i*8
            scope.sequence(base+0x1000,item['distances'],'f');scope.sequence(base+0x3000,item['interframes'],'i')
            scope.put(base+0x10,'QQQ',identity,base+0x1000,base+0x3000)
            pointers.append(base);identities.append(identity)
        scope.sequence(HEAP+0x5000,pointers,'Q');scope.put(HEAP+0x10,'Q',HEAP+0x5000)
        distances=[-math.inf,-1.0,0.0,1.0,10.0,math.inf,math.nan]
        if frame and frame[0]['distances']:distances.extend(frame[0]['distances'][:4])
        for distance in distances:
            receiver=HEAP+0x180000;scope.sequence(receiver,[HEAP+0x1f1000]*128,'Q')
            scope.put(receiver+0x18,'ii',2,0)
            want=[identity for item,identity in zip(frame,identities) if expected(item['distances'],item['interframes'],distance)[1]>0]
            got=scope.call('eligible_animations',HEAP,value=distance,integer=receiver)
            size,version=struct.unpack('<ii',scope.vm.mem_read(receiver+0x18,8))
            output=list(struct.unpack('<'+str(size)+'Q',scope.vm.mem_read(receiver+0x120,size*8)))
            check('native candidate count',got,len(want));check('native receiver count',size,2+len(want))
            check('native receiver version',version,len(want))
            check('native append identity/order',output,[HEAP+0x1f1000]*2+want);selection_cases+=1
    # Each reviewed instruction range must still match the supplied binary.
    hashes={name:hashlib.sha256(scope.vm.mem_read(start,end-start)).hexdigest() for name,(start,end) in FUNCTIONS.items()}
    report=dict(status='PASS_BOUNDED_ORIGINAL_ARM64_EXECUTION',checks=checks,failures=failures,
        sampled_original_intervals=len(indices),candidate_selection_cases=selection_cases,calls=dict(scope.calls),executed_support_functions=dict(scope.visited),
        original_text_sha256=hashes,metadata_initialization_guard_rvas=[hex(r) for r in scope.guards],
        text_modified=False,game_function_mocks=0,seconds=time.monotonic()-started,
        scope='Original position-independent ARM64 mapped at RVA zero. Valid synthetic managed containers; initialization guards pre-set. No Nintendo OS or complete game execution, no runtime parity or FPS claim.')
    destination(ROOT,ROOT/'reports/native-ai-execution.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
