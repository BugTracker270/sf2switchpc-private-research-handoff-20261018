"""Compare compiled line/contact fixtures with original ARM64 function bytes."""
import hashlib
import json
import struct
from execute_native_ai_leaves import NativeScope,FUNCTIONS,ROOT,HEAP,STACK,STOP
from usb_boundary import destination
from unicorn import arm64_const as reg

def main():
    FUNCTIONS.update(equation_line=(0x15c4a90,0x15c4b7c),distance_contact=(0x15c50a0,0x15c520c))
    scope=NativeScope();vm=scope.vm
    slot=struct.unpack('<Q',vm.mem_read(0x3980340,8))[0];klass=HEAP+0x10000
    scope.put(slot,'Q',klass);scope.put(klass+0x122,'B',0)
    guards=[0x3b898fb,0x3b898ad]
    for guard in guards:vm.mem_write(guard,b'\1')
    a=HEAP+0x100;b=HEAP+0x200;point=HEAP+0x300;line=HEAP+0x400;projection=HEAP+0x500
    def call(name,integers,floats):
        vm.reg_write(reg.UC_ARM64_REG_SP,STACK+0x80000);vm.reg_write(reg.UC_ARM64_REG_X30,STOP)
        for i in range(8):vm.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),integers[i] if i<len(integers) else 0)
        for i,value in enumerate(floats):vm.reg_write(getattr(reg,'UC_ARM64_REG_Q'+str(i)),struct.unpack('<I',struct.pack('<f',value))[0])
        scope.last_blocks=[];vm.emu_start(FUNCTIONS[name][0],STOP,count=20000)
        if vm.reg_read(reg.UC_ARM64_REG_PC)!=STOP:raise ValueError('Reviewed function failed to return')
        scope.calls[name]+=1;return vm.reg_read(reg.UC_ARM64_REG_X0)&0xffffffff
    fixture=ROOT/'analysis/reconstruction/contact-reference/contact-fixtures.jsonl';cases=checks=hits=0
    for text in fixture.open(encoding='utf-8'):
        row=json.loads(text)
        for address,key in [(a,'a'),(b,'b'),(point,'point')]:scope.put(address+0x10,'3f',*row[key])
        scope.put(projection+0x10,'3f',-123,-456,7)
        call('equation_line',[0,a,b,line],[])
        bits=list(struct.unpack('<3I',vm.mem_read(line+0x10,12)));checks+=3
        if bits!=row['lineBits']:raise AssertionError(f'Line normalization mismatch in case {cases}: {bits} != {row["lineBits"]}')
        hit=call('distance_contact',[0,line,point,projection,a,b],[row['distance'],row['reach']]);checks+=1
        if bool(hit)!=row['hit']:raise AssertionError(f'Contact inclusion mismatch in case {cases}')
        bits=list(struct.unpack('<3I',vm.mem_read(projection+0x10,12)));checks+=3
        if bits!=row['projectionBits']:raise AssertionError(f'Projection mutation mismatch in case {cases}: {bits} != {row["projectionBits"]}')
        cases+=1;hits+=hit
    report=dict(status='PASS_COMPILED_CONTACT_REFERENCE_VS_ORIGINAL_ARM64',cases=cases,checks=checks,contacts=hits,
        fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),calls=dict(scope.calls),executed_functions=dict(scope.visited),
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n in ['equation_line','distance_contact']},
        metadata_initialization_guards=[hex(g) for g in guards],text_modified=False,game_function_mocks=0,
        scope='Finite nondegenerate lines, endpoint projection and contact inclusion/mutation. Original bytes with synthetic initialized objects. Full capsule/collision and hit ordering are not certified.')
    destination(ROOT,ROOT/'reports/native-contact-geometry.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
