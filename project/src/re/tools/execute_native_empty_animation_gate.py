"""Execute the no-file animation loader branch; do not perform resource IO."""
import hashlib
import json
import random
import struct
from execute_native_ai_leaves import NativeScope,FUNCTIONS,ROOT,HEAP
from usb_boundary import destination

def main():
    FUNCTIONS.update(animation_read_binary=(0x1017400,0x1017540),string_null_or_empty=(0x3fa880,0x3fa89c))
    scope=NativeScope();vm=scope.vm;guard=0x3b86a3c;vm.mem_write(guard,b'\1')
    klass=HEAP+0x10000;slot=struct.unpack('<Q',vm.mem_read(0x3979a28,8))[0]
    scope.put(slot,'Q',klass);scope.put(klass+0x122,'B',0)
    empty=HEAP+0x2000;scope.put(empty+0x10,'i',0)
    rng=random.Random(0x414e494d);checks=0
    for pointer in [0,empty]:
        for _ in range(128):
            vm.mem_write(HEAP,rng.randbytes(256));scope.put(HEAP+0x48,'Q',pointer)
            before=bytes(vm.mem_read(HEAP,256));scope.call('animation_read_binary',HEAP)
            if bytes(vm.mem_read(HEAP,256))!=before:raise AssertionError('Empty filename loader mutated animation state')
            checks+=1
    report=dict(status='PASS_ORIGINAL_ARM64_EMPTY_ANIMATION_FILE_GATE',checks=checks,
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n in ['animation_read_binary','string_null_or_empty']},
        executed_functions=dict(scope.visited),game_function_mocks=0,text_modified=False,resource_io_calls=0,
        scope='Null and zero-length filename paths with synthetic initialized String metadata and varied animation storage. Original loader immediately returns without loading a file or changing animation fields. Does not validate physics/event behavior of the no-file moves.')
    destination(ROOT,ROOT/'reports/native-empty-animation-gate.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
