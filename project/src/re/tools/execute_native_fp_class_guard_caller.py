"""Observe the original scheduled FP load/class macro and complete HFA caller."""
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS, ROOT, HEAP
from usb_boundary import destination
from unicorn import arm64_const as reg


class Scope(CapsuleScope):
    initializer_calls = 0

    def block(self, vm, address, size, context):
        if address == 0xB2E720:
            if vm.reg_read(reg.UC_ARM64_REG_X0) != HEAP + 0x10000:
                raise AssertionError('Initializer class argument differs')
            self.initializer_calls += 1
            self.put(HEAP + 0x10000 + 0xD4, 'I', 1)
            vm.reg_write(reg.UC_ARM64_REG_X0, HEAP + 0x18000)
            vm.reg_write(reg.UC_ARM64_REG_PC, vm.reg_read(reg.UC_ARM64_REG_X30))
            return
        super().block(vm, address, size, context)


def main():
    FUNCTIONS.clear()
    FUNCTIONS.update(relative=(0xA6A1F0, 0xA6A29C), add=(0x15D9380, 0x15D9390))
    scope = Scope()
    vm = scope.vm
    # Actual adjacent class pointer / S10 / flag loads. The FP load has to be
    # retained even when the class macro is recognized by the recovery tool.
    expected = bytes.fromhex('000140f96a1641bd08884439')
    if bytes(vm.mem_read(0xA6A23C, len(expected))) != expected:
        raise ValueError('Original scheduled FP/class witness changed')
    slot = struct.unpack('<Q', vm.mem_read(0x3981A50, 8))[0]
    scope.put(slot, 'Q', HEAP + 0x10000)
    vm.mem_write(0x3A37BD6, b'\1')
    rows = json.loads((ROOT / 'analysis/il2cpp/vector3-native-fixtures-v1.json').read_text())
    cases = checks = 0
    for flags in [0, 1]:
        for finished in [0, 1]:
            for row in rows:
                tween = HEAP + 0x1000
                scope.put(tween + 0x10C, '3I', *row['b'])
                scope.put(tween + 0x118, '3I', *row['a'])
                scope.put(HEAP + 0x10000 + 0x122, 'B', flags)
                scope.put(HEAP + 0x10000 + 0xD4, 'I', finished)
                scope.initializer_calls = 0
                scope.invoke('relative', [0, tween, 0], [])
                got = list(struct.unpack('<3I', vm.mem_read(tween + 0x118, 12)))
                want_calls = int(bool(flags & 1) and finished == 0)
                if got != row['result'] or scope.initializer_calls != want_calls:
                    raise AssertionError(f'Native FP/class caller differs at case {cases}')
                cases += 1
                checks += 4
    report = dict(status='PASS_ORIGINAL_FP_SCHEDULED_CLASS_GUARD_HFA_CALLER', cases=cases,
                  checks=checks, caller_rva='0xA6A1F0', fp_load_rva='0xA6A240', class_macro_rva='0xA6A244',
                  caller_sha256=hashlib.sha256(vm.mem_read(0xA6A1F0, 0xAC)).hexdigest(),
                  fixture_sha256=hashlib.sha256((ROOT/'analysis/il2cpp/vector3-native-fixtures-v1.json').read_bytes()).hexdigest(),
                  scope='Original complete DOTween caller plus original Vector3 addition. Synthetic tween fields, '
                        'metadata guard pre-set, and explicit runtime initializer boundary that marks completion '
                        'and clobbers X0 while preserving ABI FP registers. Three stored component bits and '
                        'initializer-call count checked per case. No game-method mocks, recovered-caller CIL '
                        'certification, initializer contents, threading or complete-game/source proof.')
    destination(ROOT, ROOT/'reports/native-fp-class-guard-caller.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
