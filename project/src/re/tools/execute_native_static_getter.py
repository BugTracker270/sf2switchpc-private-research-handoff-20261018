"""Run the unchanged static getter with an explicit metadata-assurance boundary."""
from collections import Counter
import hashlib
import json
import random
import struct
from execute_native_ai_leaves import NativeScope, FUNCTIONS, ROOT, HEAP, STACK, STOP
from usb_boundary import destination
from unicorn import arm64_const as reg


class GetterScope(NativeScope):
    def __init__(self):
        self.boundaries=Counter()
        super().__init__()

    def block(self, vm, address, size, context):
        if address==0xB12650:
            if vm.reg_read(reg.UC_ARM64_REG_X0)!=self.metadata_index:
                raise AssertionError('Original metadata assurance argument differs')
            self.boundaries['supplied_method_metadata_assurance']+=1
            vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30))
        else:
            return super().block(vm,address,size,context)


def main():
    report_path=ROOT/'reports/static-leaf-getter-selection-v31b.json'
    metadata=json.loads(report_path.read_text(encoding='utf-8-sig'))
    if (metadata['status']!='PASS_STATIC_GETTER_NATIVE_METADATA_AND_NEGATIVE_GUARDS'
            or metadata['owner_cctor'] or metadata['getter_fde_bytes']!=84 or metadata['field_offset']!=8):
        raise ValueError('Independent native/metadata proof not satisfied')
    FUNCTIONS.clear();FUNCTIONS.update(static_getter=(0x78C270,0x78C2C4))
    scope=GetterScope();vm=scope.vm
    body=bytes(vm.mem_read(0x78C270,84))
    if hashlib.sha256(body).hexdigest()!=metadata['getter_native_sha256']:
        raise ValueError('Original getter bytes differ')
    got=int(metadata['type_got'],16);slot=int(metadata['type_metadata_slot'],16)
    if struct.unpack('<Q',vm.mem_read(got,8))[0]!=slot:
        raise ValueError('Original GOT class-slot pointer differs')
    method_handle_slot=struct.unpack('<Q',vm.mem_read(0x39BD738,8))[0]
    scope.metadata_index=struct.unpack('<I',vm.mem_read(method_handle_slot,4))[0]
    klass=HEAP+0x1000;storage=HEAP+0x2000;flag=0x3A36614
    scope.put(slot,'Q',klass);scope.put(klass+0xB8,'Q',storage)
    randomizer=random.Random(0x53465347)
    values=[0,1,0x10000000,0xFEDCBA9876543210]+[randomizer.getrandbits(64) for _ in range(28)]
    cases=checks=0
    for initialized in [0,1]:
        for value in values:
            vm.mem_write(storage,b'\xA5'*8+struct.pack('<Q',value)+b'\x5A'*16)
            vm.mem_write(flag,bytes([initialized]))
            before=scope.boundaries['supplied_method_metadata_assurance']
            sp=STACK+0x80000;x19=0x1122334455667788;x29=0x1020304050607080
            vm.reg_write(reg.UC_ARM64_REG_SP,sp);vm.reg_write(reg.UC_ARM64_REG_X19,x19)
            vm.reg_write(reg.UC_ARM64_REG_X29,x29);vm.reg_write(reg.UC_ARM64_REG_X30,STOP)
            vm.reg_write(reg.UC_ARM64_REG_X0,0)
            vm.emu_start(0x78C270,STOP,count=1000)
            actual=[vm.reg_read(reg.UC_ARM64_REG_PC),vm.reg_read(reg.UC_ARM64_REG_X0),
                    vm.reg_read(reg.UC_ARM64_REG_SP),vm.reg_read(reg.UC_ARM64_REG_X19),vm.reg_read(reg.UC_ARM64_REG_X29),
                    bytes(vm.mem_read(storage,32)),bytes(vm.mem_read(flag,1)),
                    scope.boundaries['supplied_method_metadata_assurance']-before]
            expected=[STOP,value,sp,x19,x29,b'\xA5'*8+struct.pack('<Q',value)+b'\x5A'*16,b'\x01',1-initialized]
            if actual!=expected:raise AssertionError('Original static getter contract differs')
            cases+=1;checks+=len(expected)
    report=dict(status='PASS_ORIGINAL_STATIC_GETTER_AT_METADATA_ASSURANCE_BOUNDARY',cases=cases,checks=checks,
        getter_rva='0x78C270',getter_bytes=84,getter_sha256=hashlib.sha256(body).hexdigest(),
        selection_report_sha256=hashlib.sha256(report_path.read_bytes()).hexdigest(),
        cold_cases=32,already_assured_cases=32,runtime_boundaries=dict(scope.boundaries),executed_blocks=dict(scope.visited),
        native_text_modified=False,field_visibility_changed=False,
        scope='Unchanged original 84-byte getter executes from entry to RET for actual GOT/type-slot addresses and valid synthetic runtime-class/static-storage objects. The sole supplied boundary is known method-metadata assurance; its original argument and cold/hot call count are checked. Returned field bits, unchanged static storage, assurance flag and SP/X19/X29 restoration are checked. No original metadata initialization, managed class initializer, allocation, active detector or whole caller executes. Owner metadata independently proves no .cctor. Actual recovered CLR getter/caller identity requires separate tests.')
    destination(ROOT,ROOT/'reports/native-static-getter-v31b.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=report['status'],cases=cases,checks=checks)))


if __name__=='__main__':main()
