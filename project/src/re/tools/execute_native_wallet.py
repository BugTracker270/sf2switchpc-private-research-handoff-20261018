"""Observe original wallet arithmetic at explicit persistence/statistics boundaries."""
import collections
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_currency_long import LONG_FUNCTIONS,LONG_GUARDS,initialize
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP,STACK,STOP
from usb_boundary import destination
from unicorn import arm64_const as reg

WALLET_FUNCTIONS=dict(money_post_pow=(0xfd08d0,0xfd0978),bonus_set=(0xfd0990,0xfd0f60),max_long=(0x663f30,0x663f3c))

class WalletScope(CapsuleScope):
    def __init__(self):
        self.persistence=[];self.statistics_boundary=False;self.boundary_calls=collections.Counter()
        super().__init__()
    def block(self,vm,address,size,context):
        if address==0xcfe1d0:
            # Observe the requested long-valued attribute write and return.
            # This boundary stub deliberately does not execute XML/string IO.
            self.persistence.append([vm.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(3)])
            self.boundary_calls['SaveAttribute_noop_return']+=1
            vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30));return
        if address==0xb5b110:
            # On the reviewed increase path, all wallet fields and writes precede
            # ArgsDict allocation. Stop before statistics allocation/side effects.
            self.statistics_boundary=True;self.boundary_calls['statistics_allocation_stop']+=1
            vm.reg_write(reg.UC_ARM64_REG_PC,STOP);return
        super().block(vm,address,size,context)

def main():
    FUNCTIONS.update(LONG_FUNCTIONS);FUNCTIONS.update(WALLET_FUNCTIONS)
    scope=WalletScope();vm=scope.vm;initialize(scope)
    guards=[0x3b86852,0x3b86853]
    for address in guards:vm.mem_write(address,b'\1')
    names={}
    for label,got,pointer in [('Money',0x397bf30,HEAP+0x15000),('Bonus',0x397bf28,HEAP+0x15100),('PaidBonus',0x39fa538,HEAP+0x15200)]:
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',pointer);names[label]=pointer
    fixture=ROOT/'analysis/reconstruction/wallet-reference/wallet-fixtures-v1.jsonl'
    roster=HEAP+0x4000;cases=checks=0
    def check(actual,expected,label):
        nonlocal checks
        checks+=1
        if actual!=expected:raise AssertionError(f'{label} differs at fixture {cases}: {actual} != {expected}')
    def encoded(value,key):return [key&0xffffffffffffffff,(value^key)&0xffffffffffffffff,0,1]
    for text in fixture.open(encoding='utf-8'):
        row=json.loads(text);scope.put(HEAP+0x11000,'q',row['key']);scope.put(HEAP+0x13008,'Q',0)
        scope.put(roster+0x138,'4Q',*encoded(row['oldValue'],row['key']));scope.put(roster+0x178,'4Q',*row['paidBefore'])
        scope.persistence=[];scope.statistics_boundary=False
        scope.invoke('bonus_set',[roster,row['value']&0xffffffffffffffff,row['type'],int(row['isPaid']),0],[])
        check(list(struct.unpack('<4Q',vm.mem_read(roster+0x138,32))),row['bonusBits'],'bonus balance')
        check(list(struct.unpack('<4Q',vm.mem_read(roster+0x178,32))),row['paidAfter'],'paid bonus balance')
        expected=[[roster,names['Bonus'],row['value']&0xffffffffffffffff]]
        if row['paidWritten']:expected.append([roster,names['PaidBonus'],row['newPaid']&0xffffffffffffffff])
        check(scope.persistence,expected,'persistence boundary arguments/order')
        check(scope.statistics_boundary,row['statisticsBoundary'],'statistics boundary reachability')
        # Start after the imported pow call; supply its double result explicitly.
        # Stop before SaveAttribute. Neither pow nor persistence is certified here.
        vm.reg_write(reg.UC_ARM64_REG_SP,STACK+0x80000);vm.reg_write(reg.UC_ARM64_REG_X19,roster)
        vm.reg_write(reg.UC_ARM64_REG_X20,row['value']&0xffffffffffffffff);vm.reg_write(reg.UC_ARM64_REG_Q0,row['powBits'])
        scope.last_blocks=[];vm.emu_start(0xfd08d0,0xfd0978,count=20000)
        check(vm.reg_read(reg.UC_ARM64_REG_PC),0xfd0978,'money slice end')
        check(list(struct.unpack('<4Q',vm.mem_read(roster+0x118,32))),row['moneyBits'],'money balance')
        check([vm.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(3)],
            [roster,names['Money'],row['persistedMoney']],'money persistence arguments')
        cases+=1
    report=dict(status='PASS_COMPILED_WALLET_ARITHMETIC_AT_BOUNDARIES',cases=cases,checks=checks,
        fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),executed_functions=dict(scope.visited),calls=dict(scope.calls),
        boundary_stubs=dict(scope.boundary_calls),text_modified=False,real_save_files_opened=0,
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in {**LONG_FUNCTIONS,**WALLET_FUNCTIONS}.items()},
        metadata_initialization_guards=[hex(g) for g in LONG_GUARDS+guards],
        scope='Original SetBonus arithmetic through observed SaveAttribute calls; SaveAttribute is a no-op return stub, and increases stop before statistics allocation. Original SetMoney internal post-pow slice to pre-SaveAttribute with supplied compiled-reference pow result. Signed/overflow boundary inputs included. No XML persistence, imported pow, statistics event, whole transaction or gameplay economy parity claim.')
    destination(ROOT,ROOT/'reports/native-wallet-arithmetic.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
