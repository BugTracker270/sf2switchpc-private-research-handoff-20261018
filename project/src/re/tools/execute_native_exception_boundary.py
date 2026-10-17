"""Observe original exception-pointer transport at supplied C++ runtime boundaries."""
import collections
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP,STOP
from usb_boundary import destination
from unicorn import arm64_const as reg

class ExceptionScope(CapsuleScope):
    def __init__(self):
        self.boundary_calls=collections.Counter();self.requested=[];self.thrown=None
        self.payload=HEAP+0x40000
        super().__init__()
    def block(self,vm,address,size,context):
        if address==0x2373078:
            requested=vm.reg_read(reg.UC_ARM64_REG_X0)
            if requested!=8:raise ValueError('Unexpected C++ exception allocation size')
            self.requested.append(requested);self.boundary_calls['supplied_cxx_allocate_exception']+=1
            vm.mem_write(self.payload,b'\xcc'*16);vm.reg_write(reg.UC_ARM64_REG_X0,self.payload)
            vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30));return
        if address==0x2373088:
            pointer=vm.reg_read(reg.UC_ARM64_REG_X0)
            if pointer!=self.payload:raise ValueError('Native throw did not receive its allocated payload')
            self.thrown=dict(payload=pointer,exception=struct.unpack('<Q',vm.mem_read(pointer,8))[0],
                rtti=vm.reg_read(reg.UC_ARM64_REG_X1),destructor=vm.reg_read(reg.UC_ARM64_REG_X2))
            self.boundary_calls['supplied_cxx_throw_stop']+=1;vm.reg_write(reg.UC_ARM64_REG_PC,STOP);return
        super().block(vm,address,size,context)

def main():
    FUNCTIONS['raise_to_boundary']=(0xb4c880,0xb4c97c)
    scope=ExceptionScope();vm=scope.vm;rtti=HEAP+0x60000
    # The Switch dynamic loader supplies the C++ RTTI import at runtime. Only
    # the sandbox GOT data is initialized here; no source bytes are changed.
    scope.put(0x397b170,'Q',rtti);cases=checks=0
    def check(actual,expected,label):
        nonlocal checks
        checks+=1
        if actual!=expected:raise AssertionError(f'{label} differs at case {cases}: {actual} != {expected}')
    for i in range(32):
        exception=HEAP+0x1000+i*0x100;trace=HEAP+0x50000+i*0x100
        scope.put(exception+0x10,'Q',trace);scope.requested=[];scope.thrown=None
        scope.invoke('raise_to_boundary',[exception,0 if i%2 else HEAP+0x70000,(i*0x9e3779b97f4a7c15)&0xffffffffffffffff],[])
        if scope.thrown is None:raise ValueError('Expected C++ throw boundary was not reached')
        check(scope.thrown['exception'],exception,'original exception identity');check(scope.thrown['payload'],scope.payload,'C++ wrapper identity')
        check(scope.thrown['rtti'],rtti,'supplied exception-wrapper RTTI');check(scope.thrown['destructor'],0,'null native destructor')
        check(scope.requested,[8],'C++ allocation request');check(struct.unpack('<Q',vm.mem_read(exception+0x10,8))[0],trace,'existing trace retained')
        check(bytes(vm.mem_read(scope.payload+8,8)),b'\xcc'*8,'eight-byte wrapper bound');cases+=1
    report=dict(status='PASS_NATIVE_EXCEPTION_POINTER_TO_CXX_BOUNDARY',cases=cases,checks=checks,
        executed_functions=dict(scope.visited),calls=dict(scope.calls),external_runtime_boundaries=dict(scope.boundary_calls),
        original_text_sha256=hashlib.sha256(vm.mem_read(0xb4c880,252)).hexdigest(),
        supplied_cpp_rtti_got='0x397B170',game_function_mocks=0,text_modified=False,
        scope='Original exception raiser with a non-null pre-existing System.Exception.trace_ips at +0x10. C++ allocate_exception and throw are explicit supplied boundaries; the payload carries the same exception pointer, RTTI import and null destructor. No stack capture, allocation failure, actual C++ unwinding, managed catch/filter, null exception or full runtime parity claim.')
    destination(ROOT,ROOT/'reports/native-exception-boundary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
