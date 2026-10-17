"""Execute original ObscuredInt paths used by generic currency counters."""
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP
from usb_boundary import destination
from unicorn import arm64_const as reg

def main():
    FUNCTIONS.update(int_from_plain=(0x7926a0,0x792848),int_to_plain=(0x794890,0x7948b4),
        int_encrypt_default=(0x7a8b60,0x7a8c20),int_encrypt_explicit=(0x7a8c20,0x7a8ca4),
        int_decrypt_default=(0x7a8cb0,0x7a8d70),int_decrypt_explicit=(0x7a8d70,0x7a8df4),
        int_internal_decrypt=(0x7a8f20,0x7a9128),object_ctor=(0x65a2a0,0x65a2a4),
        currency_ctor=(0xd3d2c0,0xd3d358),currency_set_count=(0xd3d370,0xd3d378),
        currency_get_kind=(0xd3d380,0xd3d388),currency_get_count=(0xd3d390,0xd3d39c))
    scope=CapsuleScope();vm=scope.vm
    int_class=HEAP+0x10000;int_statics=HEAP+0x11000;detector_class=HEAP+0x12000;detector_statics=HEAP+0x13000;detector=HEAP+0x14000
    for got,klass,statics in [(0x39bdb08,int_class,int_statics),(0x39bd740,detector_class,detector_statics)]:
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',klass);scope.put(klass+0xb8,'Q',statics);scope.put(klass+0x122,'B',0)
    guards=[0x3a36686,0x3a3667f,0x3a36680,0x3a3667d,0x3a36614,0x3a36681,0x3a36682,0x3a36685,0x3b84ea5]
    for address in guards:vm.mem_write(address,b'\1')
    fixture=ROOT/'analysis/reconstruction/currency-reference/currency-fixtures-v2.jsonl';cases=checks=0
    def check(actual,expected,label):
        nonlocal checks
        checks+=1
        if actual!=expected:raise AssertionError(f'{label} differs at fixture {cases}: {actual} != {expected}')
    for text in fixture.open(encoding='utf-8'):
        row=json.loads(text);scope.put(int_statics,'i',row['globalKey']);scope.put(detector_statics+8,'Q',0 if row['mode']==0 else detector);scope.put(detector+0x31,'B',row['mode']==2)
        value=row['value']&0xffffffff;explicit=row['explicitKey']&0xffffffff
        scope.invoke('int_from_plain',[0,value,0],[])
        words=[vm.reg_read(reg.UC_ARM64_REG_X0),vm.reg_read(reg.UC_ARM64_REG_X1)]
        for a,b in zip(words,row['encoded']):check(a,b,'encoded aggregate word')
        check(scope.invoke('int_to_plain',[0,*words,0],[]),value,'by-value decode')
        for function,key in [('int_encrypt_default','defaultResult'),('int_decrypt_default','defaultResult')]:
            check(scope.invoke(function,[0,value,0],[]),row[key],function)
        for function in ['int_encrypt_explicit','int_decrypt_explicit']:
            check(scope.invoke(function,[0,value,explicit,0],[]),row['explicitResult'],function)
        scope.put(HEAP,'QQ',*row['instanceWords']);check(scope.invoke('int_internal_decrypt',[HEAP,0],[]),row['internalResult'],'unboxed decode')
        actual=struct.unpack('<QQ',vm.mem_read(HEAP,16))
        for a,b in zip(actual,row['internalAfter']):check(a,b,'post-initialization word')
        currency=HEAP+0x2000;kind=HEAP+0x3000
        scope.invoke('currency_ctor',[currency,kind,value,0],[])
        check(scope.invoke('currency_get_kind',[currency,0],[]),kind,'currency kind identity')
        scope.invoke('currency_get_count',[currency,0],[])
        for register,word in zip([reg.UC_ARM64_REG_X0,reg.UC_ARM64_REG_X1],row['encoded']):check(vm.reg_read(register),word,'constructed counter aggregate')
        scope.invoke('currency_set_count',[currency,*row['instanceWords'],0],[]);scope.invoke('currency_get_count',[currency,0],[])
        for register,word in zip([reg.UC_ARM64_REG_X0,reg.UC_ARM64_REG_X1],row['instanceWords']):check(vm.reg_read(register),word,'stored counter aggregate')
        cases+=1
    report=dict(status='PASS_COMPILED_CURRENCY_INT_CODEC_VS_ORIGINAL_ARM64',cases=cases,checks=checks,
        fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),executed_functions=dict(scope.visited),calls=dict(scope.calls),
        game_function_mocks=0,text_modified=False,allocation_calls=dict(scope.allocations),metadata_initialization_guards=[hex(g) for g in guards],
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n.startswith(('int_','currency_'))},
        scope='Generic currency int representation, CurrencyStruct constructor/get/set and aggregate calling convention: default/explicit XOR, zero-key fallback, by-value decode and lazy initialization. Synthetic initialized metadata and absent/inactive/active-consistent detector states. No mismatch callback, roster wallet mutation, real save, complete reward/economy or 64-bit money/bonus parity claim.')
    destination(ROOT,ROOT/'reports/native-currency-codec.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
