"""Produce original-code scalar accessor fixtures, including bounded error paths."""
import collections
import hashlib
import json
import random
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP,STOP
from usb_boundary import destination
from unicorn import arm64_const as reg

class ScalarScope(CapsuleScope):
    def __init__(self):
        self.boundaries=collections.Counter();self.raised=None;super().__init__()
    def block(self,vm,address,size,context):
        if address==0xb54a50:
            namespace=vm.reg_read(reg.UC_ARM64_REG_X1);name=vm.reg_read(reg.UC_ARM64_REG_X2)
            if vm.reg_read(reg.UC_ARM64_REG_X0)!=HEAP+0x50000 or bytes(vm.mem_read(namespace,7))!=b'System\0' or bytes(vm.mem_read(name,25))!=b'IndexOutOfRangeException\0':raise ValueError('Factory class lookup differs')
            self.boundaries['supplied_class_lookup']+=1
            vm.reg_write(reg.UC_ARM64_REG_X0,HEAP+0x51000);vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30));return
        if address==0xb5b110:
            if vm.reg_read(reg.UC_ARM64_REG_X0)!=HEAP+0x51000:raise ValueError('Factory allocation class differs')
            self.boundaries['supplied_opaque_exception_allocation']+=1;vm.mem_write(HEAP+0x40000,b'\0'*128);self.put(HEAP+0x40000,'Q',HEAP+0x51000)
            vm.reg_write(reg.UC_ARM64_REG_X0,HEAP+0x40000);vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30));return
        if address==0xb2e3d0:
            if vm.reg_read(reg.UC_ARM64_REG_X0)!=HEAP+0x40000 or vm.reg_read(reg.UC_ARM64_REG_X1)!=0:raise ValueError('Factory initialization arguments differ')
            self.boundaries['supplied_object_initialization']+=1
            # The factory must preserve its allocation even if this void
            # runtime helper clobbers the caller-saved return register.
            vm.reg_write(reg.UC_ARM64_REG_X0,0xdecafbad);vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30));return
        if address==0xb4c880:
            if vm.reg_read(reg.UC_ARM64_REG_X0)!=HEAP+0x40000:raise ValueError('Unexpected bounds-exception identity')
            self.raised='System.IndexOutOfRangeException';self.boundaries['exception_raiser_stop']+=1
            vm.reg_write(reg.UC_ARM64_REG_PC,STOP);return
        super().block(vm,address,size,context)

def main():
    properties=['Production','Major','Minor','DataVersion']
    FUNCTIONS.update(index_exception_factory=(0xb4d8f0,0xb4d930),corlib_getter=(0xb547a0,0xb547b0),class_lookup_thunk=(0xb07210,0xb07214),object_initialization_thunk=(0xb2e3c0,0xb2e3c8))
    for index,name in enumerate(properties):
        base=0xc3240+index*0x80
        FUNCTIONS['get_'+name]=(base,base+(56 if index==0 else 60))
        FUNCTIONS['set_'+name]=(base+0x40,base+0x40+(60 if index==0 else 64))
    scope=ScalarScope();vm=scope.vm;obj=HEAP+0x1000;array=HEAP+0x2000
    scope.put(obj+0x10,'Q',array);cases=checks=0;randoms=random.Random(0x5343414c4152)
    corlib_slot=struct.unpack('<Q',vm.mem_read(0x39d3b38,8))[0];scope.put(corlib_slot,'Q',HEAP+0x50000)
    path=destination(ROOT,ROOT/'analysis/il2cpp/scalar-native-fixtures-v1.jsonl')
    def check(actual,want,label):
        nonlocal checks
        checks+=1
        if actual!=want:raise AssertionError(f'{label} differs at {cases}: {actual!r} != {want!r}')
    with path.open('w',encoding='utf-8') as output:
        for length in range(6):
            for sample in range(16):
                source=[randoms.randrange(-(1<<31),1<<31) for _ in range(length)]
                if source:source[0]=[0,1,-1,-(1<<31),(1<<31)-1][sample%5]
                value=[0,1,-1,-(1<<31),(1<<31)-1,randoms.randrange(-(1<<31),1<<31)][sample%6]
                for index,name in enumerate(properties):
                    for operation in ('get','set'):
                        scope.put(array+0x18,'Q',length)
                        vm.mem_write(array+0x20,struct.pack('<'+str(length)+'i',*source) if source else b'\xcc'*4)
                        scope.raised=None;scope.invoke(operation+'_'+name,[obj,value&0xffffffff],[])
                        actual=list(struct.unpack('<'+str(length)+'i',vm.mem_read(array+0x20,4*length))) if length else []
                        expected=source.copy();exception='System.IndexOutOfRangeException' if index>=length else None
                        returned=None
                        if not exception:
                            if operation=='set':expected[index]=value
                            else:returned=struct.unpack('<i',struct.pack('<I',vm.reg_read(reg.UC_ARM64_REG_X0)&0xffffffff))[0]
                        check(scope.raised,exception,'native bounds path');check(actual,expected,'native array mutation')
                        if operation=='get' and not exception:check(returned,source[index],'native scalar result')
                        output.write(json.dumps(dict(property=name,operation=operation,source=source,value=value,result=returned,after=actual,exception=scope.raised))+'\n');cases+=1
    report=dict(status='PASS_NATIVE_SCALAR_ACCESSORS',cases=cases,checks=checks,executed_functions=dict(scope.visited),runtime_boundaries=dict(scope.boundaries),
        fixtures=str(path.relative_to(ROOT)),fixtures_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n.startswith(('get_','set_')) or n in ('index_exception_factory','corlib_getter','class_lookup_thunk','object_initialization_thunk')},text_modified=False,
        scope='Eight original VersionContainer int-array accessors with synthetic lengths 0..5 and int32 boundary/random values. Bounds errors execute the original IndexOutOfRangeException factory, corlib getter and two thunks; class lookup, opaque exception allocation and object initialization are explicit supplied runtime boundaries. The original raiser is a stop boundary. The factory retains allocation identity even when the initialization boundary clobbers X0. No field/default-constructor internals, string parsing, static initialization, unwinding or whole-game parity is claimed.')
    destination(ROOT,ROOT/'reports/native-scalar-accessors.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
