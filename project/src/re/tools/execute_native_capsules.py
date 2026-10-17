"""Execute complete original capsule math with a narrowly modeled allocator."""
import collections
import hashlib
import json
import struct
from execute_native_ai_leaves import NativeScope,FUNCTIONS,ROOT,HEAP,STACK,STOP
from usb_boundary import destination
from unicorn import arm64_const as reg

class CapsuleScope(NativeScope):
    def __init__(self):
        self.types={};self.allocations=collections.Counter();self.next_allocation=HEAP+0x1c0000
        super().__init__()
    def block(self,vm,address,size,context):
        if address==0xb5b110:
            klass=vm.reg_read(reg.UC_ARM64_REG_X0)
            if klass not in self.types:raise ValueError('Allocator received an unreviewed type')
            if self.next_allocation+32>HEAP+0x200000:raise ValueError('Bounded allocation arena exhausted')
            pointer=self.next_allocation;self.next_allocation+=32
            vm.mem_write(pointer,b'\0'*32);self.put(pointer,'Q',klass)
            vm.reg_write(reg.UC_ARM64_REG_X0,pointer);vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30))
            self.allocations[self.types[klass]]+=1;return
        super().block(vm,address,size,context)
    def invoke(self,name,integers,floats,instruction_limit=20000):
        vm=self.vm;sp=STACK+0x80000
        vm.reg_write(reg.UC_ARM64_REG_SP,sp);vm.reg_write(reg.UC_ARM64_REG_X30,STOP)
        for i in range(8):vm.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),integers[i] if i<len(integers) else 0)
        for i,value in enumerate(integers[8:]):self.put(sp+i*8,'Q',value)
        for i,value in enumerate(floats):vm.reg_write(getattr(reg,'UC_ARM64_REG_Q'+str(i)),struct.unpack('<I',struct.pack('<f',value))[0])
        self.last_blocks=[];vm.emu_start(FUNCTIONS[name][0],STOP,count=instruction_limit)
        if vm.reg_read(reg.UC_ARM64_REG_PC)!=STOP:raise ValueError('Capsule call did not return within instruction bound')
        self.calls[name]+=1;return vm.reg_read(reg.UC_ARM64_REG_X0)&0xffffffff

def main():
    FUNCTIONS.update(capsules=(0x15c5210,0x15c5698),segment_intersection=(0x15c4cb0,0x15c50a0),
        distance_contact=(0x15c50a0,0x15c520c),equation_line=(0x15c4a90,0x15c4b7c),
        allocated_equation_line=(0x15c4b80,0x15c4ca8),equation_ctor=(0x10eb720,0x10eb74c),object_ctor=(0x65a2a0,0x65a2a4))
    scope=CapsuleScope();vm=scope.vm
    for got,klass,name in [(0x3980340,HEAP+0x10000,'Mathf'),(0x39d6110,HEAP+0x11000,'Vector3f'),(0x39fb428,HEAP+0x12000,'EquationLine')]:
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',klass);scope.put(klass+0x122,'B',0)
        if name!='Mathf':scope.types[klass]=name;scope.put(klass+0xe8,'I',32)
    guards=[0x3b898fd,0x3b898f9,0x3b898f8,0x3b89901,0x3b898ad,0x3b898fb,0x3b898fc]
    for address in guards:vm.mem_write(address,b'\1')
    if bytes(vm.mem_read(0x2ca430c,4))!=bytes.fromhex('ffe6db2e'):raise ValueError('Native geometry epsilon changed')
    pointers={name:HEAP+0x100*(i+1) for i,name in enumerate(['a1','a2','b1','b2','lineA','lineB','ra','rb'])}
    fixture=ROOT/'analysis/reconstruction/capsule-reference/capsule-fixtures-v2.jsonl';cases=checks=hits=0
    for text in fixture.open(encoding='utf-8'):
        row=json.loads(text);scope.next_allocation=HEAP+0x1c0000
        for name in ['a1','a2','b1','b2','lineA','lineB']:scope.put(pointers[name]+0x10,'3f',*row[name])
        scope.put(pointers['ra']+0x10,'3f',-123,-456,7);scope.put(pointers['rb']+0x10,'3f',-321,-654,9)
        args=[0,pointers['a1'],pointers['a2'],pointers['b1'],pointers['b2'],pointers['ra'],pointers['rb'],
            pointers['lineA'] if row['providedA'] else 0,pointers['lineB'] if row['providedB'] else 0,0]
        actual=scope.invoke('capsules',args,[row['radiusA'],row['radiusB']]);checks+=1
        if bool(actual)!=row['hit']:raise AssertionError(f'Capsule hit differs at fixture {cases}')
        for name,key in [('ra','resultABits'),('rb','resultBBits')]:
            bits=list(struct.unpack('<3I',vm.mem_read(pointers[name]+0x10,12)));checks+=3
            if bits!=row[key]:raise AssertionError(f'Capsule output {name} differs at fixture {cases}: {bits} != {row[key]}')
        cases+=1;hits+=actual
    report=dict(status='PASS_COMPILED_CAPSULE_REFERENCE_VS_ORIGINAL_ARM64',cases=cases,checks=checks,contacts=hits,
        fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),calls=dict(scope.calls),executed_functions=dict(scope.visited),
        runtime_allocation_model=dict(scope.allocations),allocation_hook_rva='0xB5B110',game_function_mocks=0,text_modified=False,
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n in ['capsules','segment_intersection','distance_contact','equation_line','allocated_equation_line','equation_ctor','object_ctor']},
        metadata_initialization_guards=[hex(g) for g in guards],
        scope='Original complete capsule/segment/contact/line math and constructors, finite nondegenerate inputs including optional-null line objects. IL2CPP allocation is modeled as zeroed 32-byte Vector3f/EquationLine objects; no GC/lifetime or whole-combat parity claim.')
    destination(ROOT,ROOT/'reports/native-capsule-geometry.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
