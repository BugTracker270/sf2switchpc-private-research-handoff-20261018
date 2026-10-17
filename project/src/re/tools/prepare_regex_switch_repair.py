"""Validate the three bounded ARM64 switch tables in the failed regex method."""
import hashlib
import json
import struct
from execute_native_ai_leaves import ROOT,NativeScope,FUNCTIONS
from unicorn.arm64_const import UC_ARM64_REG_X8,UC_ARM64_REG_X9,UC_ARM64_REG_PC
from usb_boundary import destination

def main():
    scope=NativeScope();vm=scope.vm;tables=[];checks=0
    for branch,table,count in [(0x701c8c,0x2d8c078,15),(0x7037bc,0x2d8bdf4,156),(0x7045b4,0x2d8c064,5)]:
        # Exact original ldrsw/add/br sequence, then execute that sequence for
        # each permitted index. Stop at the computed destination before its code.
        if bytes(vm.mem_read(branch-8,12))!=bytes.fromhex('2879a8b80801098b00011fd6'):raise ValueError('Switch instruction fingerprint changed')
        data=bytes(vm.mem_read(table,count*4));offsets=struct.unpack('<'+str(count)+'i',data)
        targets=[table+offset for offset in offsets]
        if not all(0x700970<=t<0x70c0c0 and t%4==0 for t in targets):raise ValueError('Switch target escaped declared method')
        # Add only this three-instruction range to the scope. The VM instruction
        # count and exact stop address remain bounded.
        rows=[]
        for i,target in enumerate(targets):
            vm.reg_write(UC_ARM64_REG_X8,i);vm.reg_write(UC_ARM64_REG_X9,table)
            # Hook validates the reviewed switch instruction range.
            FUNCTIONS['regex_switch_'+hex(branch)]=(branch-8,branch+4)
            vm.emu_start(branch-8,target,count=3)
            actual=vm.reg_read(UC_ARM64_REG_PC)
            if actual!=target:raise AssertionError('Original ARM64 switch result differs')
            checks+=1;rows.append(dict(index=i,relative_offset=offsets[i],target_rva=target))
        tables.append(dict(branch_rva=branch,table_rva=table,count=count,table_sha256=hashlib.sha256(data).hexdigest(),entries=rows))
    report=dict(method_rva=0x700970,declared_end_rva=0x70c0bf,status='PASS_NATIVE_SWITCH_TARGETS',checks=checks,tables=tables,
        scope='Original table bytes and original ARM64 ldrsw/add/br execution for all guarded indices. Regex method behavior remains unvalidated.')
    destination(ROOT,ROOT/'analysis/nso/regex-switch-tables.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    targets=json.loads((ROOT/'analysis/nso/library-targets.json').read_text(encoding='utf-8'))
    selected=[r for r in targets if r['rva']==0x700970]
    if len(selected)!=1:raise ValueError('Expected one regex method target')
    destination(ROOT,ROOT/'analysis/nso/regex-switch-repair-targets.json').write_text(json.dumps(selected,indent=2)+'\n',encoding='utf-8')
    print('Native switch targets verified:',checks,'distinct destinations:',[len({r['target_rva'] for r in t['entries']}) for t in tables])
if __name__=='__main__':main()
