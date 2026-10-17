"""Validate original array size/header/overflow flow at explicit runtime boundaries."""
import collections
import hashlib
import json
import random
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP,STOP
from usb_boundary import destination
from unicorn import arm64_const as reg

class ArrayScope(CapsuleScope):
    def __init__(self):
        self.boundaries=collections.Counter();self.requests=[];self.element_size=1
        self.klass=HEAP+0x1000;self.element_class=HEAP+0x2000
        self.output=HEAP+0x80000;self.exception=HEAP+0x3000;self.raised=None
        super().__init__()
    def block(self,vm,address,size,context):
        def result(value):
            vm.reg_write(reg.UC_ARM64_REG_X0,value);vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30))
        if address==0xb04f60:
            if vm.reg_read(reg.UC_ARM64_REG_X0)!=self.klass:raise ValueError('Unknown array class initialization')
            self.boundaries['supplied_initialized_class_layout']+=1;result(self.klass);return
        if address==0xb409e0:
            if vm.reg_read(reg.UC_ARM64_REG_X0)!=self.klass:raise ValueError('Unknown element-size class')
            self.boundaries['supplied_element_size']+=1;result(self.element_size);return
        if address in (0xb5afc0,0xb5b020,0xb5af60):
            count=vm.reg_read(reg.UC_ARM64_REG_X0);klass=vm.reg_read(reg.UC_ARM64_REG_X1)
            if klass!=self.klass or count<32 or count>0x10000:raise ValueError('Unbounded or unexpected allocation')
            self.requests.append((address,count,klass));self.boundaries['supplied_allocator_'+hex(address)]+=1
            # Atomic memory is deliberately dirty; original array code must
            # clear it. Other allocator contracts supply zeroed managed data.
            vm.mem_write(self.output,bytes([0xcc if address==0xb5afc0 else 0])*count+b'\xa5'*16)
            self.put(self.output,'QQ',klass,0);result(self.output);return
        if address==0x23730a8:
            dest=vm.reg_read(reg.UC_ARM64_REG_X0);value=vm.reg_read(reg.UC_ARM64_REG_X1)&255;count=vm.reg_read(reg.UC_ARM64_REG_X2)
            if not self.requests or dest!=self.output+16 or count!=self.requests[-1][1]-16 or value!=0:raise ValueError('Unexpected memset contract')
            self.boundaries['supplied_memset']+=1;vm.mem_write(dest,bytes([value])*count);result(dest);return
        if address==0xb4d960:
            self.boundaries['supplied_overflow_exception_factory']+=1;result(self.exception);return
        if address==0xb4c880:
            self.raised=vm.reg_read(reg.UC_ARM64_REG_X0);self.boundaries['exception_raiser_stop']+=1
            vm.reg_write(reg.UC_ARM64_REG_PC,STOP);return
        super().block(vm,address,size,context)

def main():
    FUNCTIONS['array_new_specific']=(0xb5fe50,0xb5ffa4)
    scope=ArrayScope();vm=scope.vm;cases=checks=0;randoms=random.Random(0x4152524159)
    profiler=struct.unpack('<Q',vm.mem_read(0x39d3ec0,8))[0];scope.put(profiler,'B',0)
    scope.put(scope.klass+0x11e,'B',1);scope.put(scope.klass+0x40,'Q',scope.element_class);scope.put(scope.element_class+0x121,'B',2)
    def check(actual,want,label):
        nonlocal checks
        checks+=1
        if actual!=want:raise AssertionError(f'{label}: case {cases}: {actual!r} != {want!r}')
    for kind,flags,descriptor in [(0xb5afc0,2,0),(0xb5af60,18,0),(0xb5b020,18,HEAP+0x4000)]:
        scope.put(scope.klass+0x121,'B',flags);scope.put(scope.klass+8,'Q',descriptor)
        for element_size in (1,2,4,8,16,24):
            scope.element_size=element_size
            for length in [0,1,2,3,7,16,63,127]+[randoms.randrange(0,1024) for _ in range(24)]:
                count=32+element_size*length;scope.requests=[];scope.raised=None
                scope.invoke('array_new_specific',[scope.klass,length],[])
                check(vm.reg_read(reg.UC_ARM64_REG_X0),scope.output,'returned array identity')
                check(scope.requests,[(kind,count,scope.klass)],'allocation class/size/path')
                check(struct.unpack('<QQQQ',vm.mem_read(scope.output,32)),(scope.klass,0,0,length),'array header')
                check(bytes(vm.mem_read(scope.output+32,count-32)),bytes(count-32),'zeroed elements')
                check(bytes(vm.mem_read(scope.output+count,16)),b'\xa5'*16,'allocation red zone')
                check(scope.raised,None,'normal return does not raise');cases+=1
    invalid=[1<<31,(1<<31)+1,1<<32,(1<<63)-1,1<<63,(1<<64)-1]
    for length in invalid:
        scope.requests=[];scope.raised=None;scope.invoke('array_new_specific',[scope.klass,length],[])
        check(scope.raised,scope.exception,'oversized request raises supplied exception');check(scope.requests,[],'overflow never allocates array');cases+=1
    report=dict(status='PASS_NATIVE_ARRAY_HEADER_AND_OVERFLOW_BOUNDARIES',cases=cases,checks=checks,
        executed_functions=dict(scope.visited),runtime_boundaries=dict(scope.boundaries),original_text_sha256=hashlib.sha256(vm.mem_read(0xb5fe50,340)).hexdigest(),
        text_modified=False,game_function_mocks=0,profiler_enabled=False,
        scope='Original Array::NewSpecific control flow, size calculation, allocation-path choice, bounds/length header and return identity. Class initialization, element size, three allocator contracts, memset and overflow exception construction are explicitly supplied runtime boundaries; raiser is a stop boundary. Normal sizes are bounded to 24,584 bytes; large lengths test only pre-allocation overflow rejection. No real allocation failure, profiler, GC, OS allocation, huge-array memory or whole-runtime parity claim.')
    destination(ROOT,ROOT/'reports/native-array-boundary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
