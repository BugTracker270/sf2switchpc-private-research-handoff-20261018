"""Observe original boolean setter decisions at an explicit Init callback boundary."""
import hashlib
import json
import struct
from execute_native_ai_leaves import NativeScope, FUNCTIONS, ROOT, HEAP, STOP
from usb_boundary import destination
from unicorn import arm64_const as reg


class BooleanScope(NativeScope):
    def __init__(self):
        self.initializations = 0
        super().__init__()

    def block(self, vm, address, size, context):
        if address == 0x2222A0:
            self.initializations += 1
            vm.reg_write(reg.UC_ARM64_REG_PC, vm.reg_read(reg.UC_ARM64_REG_X30))
            return
        super().block(vm, address, size, context)


def main():
    FUNCTIONS.clear()
    FUNCTIONS.update(get=(0x2221C0, 0x222210), set=(0x222210, 0x222298))
    scope = BooleanScope()
    vm = scope.vm
    slot = struct.unpack('<Q', vm.mem_read(0x3990CD0, 8))[0]
    klass, statics = HEAP + 0x1000, HEAP + 0x2000
    scope.put(slot, 'Q', klass)
    scope.put(klass + 0xB8, 'Q', statics)
    for address in (0x3A33DE0, 0x3A33D2C):
        vm.mem_write(address, b'\1')
    rows = []
    for current in (0, 1):
        for requested in (0, 1):
            scope.put(statics, 'B', current)
            scope.initializations = 0
            scope.call('set', 0, integer=requested)
            stored = vm.mem_read(statics, 1)[0]
            observed = scope.call('get', 0)
            if stored != requested or observed != requested or scope.initializations != int(current == 0 and requested == 1):
                raise AssertionError('Original canonical boolean transition differs')
            rows.append(dict(current=bool(current), requested=bool(requested), stored=bool(stored),
                             getter=bool(observed), initialization_calls=scope.initializations))
    fixture = destination(ROOT, ROOT / 'analysis/il2cpp/boolean-native-fixtures-v1.json')
    fixture.write_text(json.dumps(rows, indent=2) + '\n', encoding='utf-8')
    report = dict(status='PASS_ORIGINAL_CANONICAL_BOOLEAN_TRANSITIONS_AT_INIT_BOUNDARY',
                  cases=len(rows), checks=3 * len(rows), fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                  original_text_sha256={name: hashlib.sha256(vm.mem_read(a, b-a)).hexdigest() for name, (a, b) in FUNCTIONS.items()},
                  text_modified=False, supplied_init_callback='0x2222A0',
                  scope='Original AdvLog getter/setter with synthetic class/static storage and preset metadata guards. '
                        'Init is an explicit supplied callback boundary; only the decision to call it is observed. '
                        'All four canonical 0/1 transitions; initialization contents, noncanonical bytes, threading and whole-game behavior remain outside scope.')
    destination(ROOT, ROOT / 'reports/native-boolean-setter.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
