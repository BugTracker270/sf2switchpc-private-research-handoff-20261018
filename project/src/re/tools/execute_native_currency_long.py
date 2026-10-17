"""Check original 64-bit currency codec and copied roster balance getters."""
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP
from usb_boundary import destination
from unicorn import arm64_const as reg

LONG_FUNCTIONS=dict(long_from_plain=(0x792bb0,0x792d7c),long_to_plain=(0x7a1dd0,0x7a1dd8),
    long_encrypt_default=(0x7a98b0,0x7a9970),long_encrypt_explicit=(0x7a9970,0x7a99f4),
    long_decrypt_default=(0x7a9a00,0x7a9ac0),long_decrypt_explicit=(0x7a9ac0,0x7a9b44),
    long_internal_decrypt=(0x7a9c70,0x7a9e84),money_get=(0xfd4b70,0xfd4c1c),
    bonus_get=(0xfd4c20,0xfd4cd0),paid_bonus_get=(0xfd50b0,0xfd50d4))
LONG_GUARDS=[0x3a36692,0x3a3668a,0x3a3668b,0x3a3668d,0x3a3668c,0x3a3668e,
    0x3a36691,0x3a36614,0x3b86769,0x3b86851]

def initialize(scope):
    vm=scope.vm
    for got,klass,statics in [(0x39bdb18,HEAP+0x10000,HEAP+0x11000),(0x39bd740,HEAP+0x12000,HEAP+0x13000)]:
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',klass)
        scope.put(klass+0xb8,'Q',statics);scope.put(klass+0x122,'B',0)
    for address in LONG_GUARDS:vm.mem_write(address,b'\1')

def main():
    FUNCTIONS.update(LONG_FUNCTIONS);scope=CapsuleScope();vm=scope.vm;initialize(scope)
    fixture=ROOT/'analysis/reconstruction/currency-long-reference/currency-long-fixtures-v1.jsonl';cases=checks=0
    def call(name,integers):
        scope.invoke(name,integers,[]);return vm.reg_read(reg.UC_ARM64_REG_X0)
    def check(actual,expected,label):
        nonlocal checks
        checks+=1
        if actual!=expected:raise AssertionError(f'{label} differs at fixture {cases}: {actual} != {expected}')
    for text in fixture.open(encoding='utf-8'):
        row=json.loads(text);scope.put(HEAP+0x11000,'q',row['globalKey'])
        scope.put(HEAP+0x13008,'Q',0 if row['mode']==0 else HEAP+0x14000);scope.put(HEAP+0x14031,'B',row['mode']==2)
        value=row['value']&0xffffffffffffffff;explicit=row['explicitKey']&0xffffffffffffffff
        output=HEAP+0x2000;vm.reg_write(reg.UC_ARM64_REG_X8,output)
        call('long_from_plain',[0,value,0]);encoded=struct.unpack('<4Q',vm.mem_read(output,32))
        for a,b in zip(encoded,row['encoded']):check(a,b,'indirect encoded result')
        check(call('long_to_plain',[0,output,0]),value,'by-reference value decode')
        check(list(struct.unpack('<4Q',vm.mem_read(output,32))),row['encoded'],'initialized value remains unchanged')
        for function in ['long_encrypt_default','long_decrypt_default']:check(call(function,[0,value,0]),row['defaultResult'],function)
        for function in ['long_encrypt_explicit','long_decrypt_explicit']:check(call(function,[0,value,explicit,0]),row['explicitResult'],function)
        scope.put(output,'4Q',*row['instanceWords']);check(call('long_internal_decrypt',[output,0]),row['internalResult'],'lazy decode')
        for a,b in zip(struct.unpack('<4Q',vm.mem_read(output,32)),row['internalAfter']):check(a,b,'lazy initialization state')
        roster=HEAP+0x4000
        for function,offset in [('money_get',0x118),('bonus_get',0x138)]:
            scope.put(roster+offset,'4Q',*row['instanceWords'])
            check(call(function,[roster,0]),row['internalResult'],function)
            check(list(struct.unpack('<4Q',vm.mem_read(roster+offset,32))),row['instanceWords'],'getter mutates only value copy')
        scope.put(roster+0x178,'4Q',*row['instanceWords']);vm.reg_write(reg.UC_ARM64_REG_X8,output)
        call('paid_bonus_get',[roster,0]);check(list(struct.unpack('<4Q',vm.mem_read(output,32))),row['instanceWords'],'paid bonus indirect aggregate')
        cases+=1
    report=dict(status='PASS_COMPILED_CURRENCY_LONG_CODEC_VS_ORIGINAL_ARM64',cases=cases,checks=checks,
        fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),executed_functions=dict(scope.visited),calls=dict(scope.calls),
        game_function_mocks=0,text_modified=False,metadata_initialization_guards=[hex(g) for g in LONG_GUARDS],
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in LONG_FUNCTIONS.items()},
        scope='64-bit currency codec and complete Money/Bonus/PaidBonus getters, including indirect 32-byte result ABI and lazy initialization of copied values. Synthetic initialized metadata; absent/inactive/active-consistent detector states. No mismatch callback, reward transaction, wallet setter, real save or full economy parity claim.')
    destination(ROOT,ROOT/'reports/native-currency-long.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
