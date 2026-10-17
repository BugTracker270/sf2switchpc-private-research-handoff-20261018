"""Compare compiled C# node-step fixtures with unmodified original ARM64."""
import hashlib
import json
import struct
import time
from execute_native_ai_leaves import NativeScope,FUNCTIONS,ROOT,HEAP
from usb_boundary import destination
from unicorn.arm64_const import UC_ARM64_REG_Q0

def main():
    FUNCTIONS.update(node_step=(0xfebd80,0xfebedc),vector_set=(0x15c56a0,0x15c56bc),
        vector_subtract=(0x15c6780,0x15c67b0),vector_multiply=(0x15c5770,0x15c5794),
        vector_add=(0x15c57a0,0x15c57d0),vector_get_y=(0x15c3aa0,0x15c3aa8),vector_set_y=(0x15c3c20,0x15c3c28))
    FUNCTIONS.update(gravity_step=(0xe99520,0xe995dc),gravity_getter=(0xd38960,0xd389c8),slow_mode_getter=(0xd40b70,0xd40bd8))
    scope=NativeScope();vm=scope.vm;start=time.monotonic()
    slot=struct.unpack('<Q',vm.mem_read(0x39d6130,8))[0]
    klass=HEAP+0x10000;statics=HEAP+0x11000;temporary=HEAP+0x12000
    current=HEAP+0x100;previous=HEAP+0x200
    scope.put(slot,'Q',klass);scope.put(klass+0xb8,'Q',statics);scope.put(statics,'Q',temporary)
    scope.put(klass+0x122,'B',0);vm.mem_write(0x3b868bb,b'\1')
    for got,base in [(0x39de158,HEAP+0x13000),(0x397ad38,HEAP+0x15000)]:
        metadata=struct.unpack('<Q',vm.mem_read(got,8))[0]
        scope.put(metadata,'Q',base);scope.put(base+0xb8,'Q',base+0x1000);scope.put(base+0x122,'B',0)
    guards=[0x3b868bb,0x3b85bde,0x3b84da8,0x3b84de2]
    for address in guards:vm.mem_write(address,b'\1')
    fixture=ROOT/'analysis/reconstruction/physics-reference/node-fixtures-v2.jsonl'
    cases=steps=checks=0
    for line in fixture.open(encoding='utf-8'):
        row=json.loads(line);scope.put(current+0x10,'3f',*row['current']);scope.put(previous+0x10,'3f',*row['previous'])
        scope.put(HEAP+0x20,'QQ',current,previous);scope.put(HEAP+0x4c,'f',row['attenuation']);scope.put(HEAP+0x56,'B',row['physics'])
        scope.put(HEAP+0x14004,'f',row['gravity']);scope.put(HEAP+0x160a0,'i',row['slow'])
        scope.call('gravity_step',0)
        bits=vm.reg_read(UC_ARM64_REG_Q0)&0xffffffff
        if bits!=row['gravityPerStepBits']:raise AssertionError('Gravity/slow-mode result differs from compiled C#')
        checks+=1
        for expected in row['expected']:
            scope.call('node_step',HEAP,value=row['gravity']);steps+=1
            for pointer,key in [(current,'currentBits'),(previous,'previousBits')]:
                actual=list(struct.unpack('<3I',vm.mem_read(pointer+0x10,12)));checks+=3
                if actual!=expected[key]:raise AssertionError(f'Case {cases} tick {steps}, {key}: {actual} != {expected[key]}')
        cases+=1
    report=dict(status='PASS_COMPILED_REFERENCE_VS_ORIGINAL_ARM64',cases=cases,steps=steps,bit_exact_float_checks=checks,
        seconds=time.monotonic()-start,fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n=='node_step' or n.startswith(('vector_','gravity_','slow_mode'))},
        calls=dict(scope.calls),executed_functions=dict(scope.visited),metadata_initialization_guards=[hex(a) for a in guards],
        text_modified=False,game_function_mocks=0,
        scope='Per-node integration only. Original ARM64 and real vector helper bytes, synthetic initialized objects. Includes gravity for both node flags and conditional attenuation. No constraints/collision/combat or FPS certification.')
    destination(ROOT,ROOT/'reports/native-node-integration.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
