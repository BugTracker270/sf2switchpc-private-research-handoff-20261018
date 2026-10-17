"""Execute the reviewed zero-message exception factory to explicit runtime boundaries.

Original ARM64 executes unchanged. Lookup/allocation/managed-invocation boundaries
are supplied and counted; this does not execute original managed constructors.
"""
import collections
import hashlib
import json
import struct
from execute_native_ai_leaves import NativeScope, FUNCTIONS, ROOT, HEAP, STACK, STOP
from usb_boundary import destination
from unicorn import arm64_const as reg

FACTORY = 0xB4DA50
CORE = 0xB4D660
INITIALIZE = 0xB2E3C0
DISPATCH = 0xB2E3D0


class FactoryScope(NativeScope):
    def __init__(self):
        self.boundaries = collections.Counter()
        self.klass = HEAP + 0x2000
        self.image = HEAP + 0x3000
        self.method = HEAP + 0x4000
        self.object = HEAP + 0x5000
        self.invoker = HEAP + 0x6000
        self.method_pointer = HEAP + 0x7000
        self.events = []
        super().__init__()
        self.put(0x39D3B38, 'Q', HEAP + 0x1000)
        self.put(HEAP + 0x1000, 'Q', self.image)
        self.put(self.method, 'QQ', self.method_pointer, self.invoker)
        self.put(self.method + 0x18, 'Q', self.klass)
        self.put(self.klass + 0x121, 'B', 0)

    def string(self, address):
        return bytes(self.vm.mem_read(address, 64)).split(b'\0', 1)[0].decode('ascii')

    def block(self, vm, address, size, context):
        x = lambda n: vm.reg_read(getattr(reg, 'UC_ARM64_REG_X' + str(n)))
        if address == 0xB07210:
            if (x(0), self.string(x(1)), self.string(x(2))) != (self.image, 'System', self.exception_name):
                raise AssertionError('Factory class lookup arguments differ')
            self.events.append('class_lookup'); vm.reg_write(reg.UC_ARM64_REG_X0, self.klass)
        elif address == 0xB5B110:
            if x(0) != self.klass: raise AssertionError('Factory allocation type differs')
            self.events.append('allocation'); vm.mem_write(self.object, b'\0' * 128)
            self.put(self.object, 'Q', self.klass); vm.reg_write(reg.UC_ARM64_REG_X0, self.object)
        elif address == 0xB05200:
            if (x(0), self.string(x(1)), x(2)) != (self.klass, '.ctor', 0):
                raise AssertionError('Initializer did not select exact parameterless constructor')
            self.events.append('zero_argument_constructor_lookup'); vm.reg_write(reg.UC_ARM64_REG_X0, self.method)
        elif address == 0xB2DC20:
            if x(0) != self.method: raise AssertionError('Invocation preparation identity differs')
            self.events.append('invocation_preparation')
        elif address == self.invoker:
            if (x(0), x(1), x(2), x(3)) != (self.method_pointer, self.method, self.object, 0):
                raise AssertionError('Original dispatcher did not pass the allocated object to its constructor')
            self.events.append('supplied_managed_constructor_invocation')
            self.put(self.object + 0x30, 'I', self.marker)
        else:
            return super().block(vm, address, size, context)
        self.boundaries[hex(address)] += 1
        vm.reg_write(reg.UC_ARM64_REG_PC, vm.reg_read(reg.UC_ARM64_REG_X30))


def main():
    FUNCTIONS.clear()
    FUNCTIONS.update(factory=(FACTORY, FACTORY + 40), core=(CORE, CORE + 276),
                     initialize=(INITIALIZE, INITIALIZE + 8), dispatch=(DISPATCH, DISPATCH + 160),
                     corlib=(0xB547A0, 0xB547B0), existing_factory=(0xB4D8F0, 0xB4D930))
    scope = FactoryScope(); checks = 0
    expected = ['class_lookup', 'allocation', 'zero_argument_constructor_lookup',
                'invocation_preparation', 'supplied_managed_constructor_invocation']
    for start, name in [(FACTORY, 'ArrayTypeMismatchException'), (0xB4D8F0, 'IndexOutOfRangeException')]:
        scope.exception_name = name
        for case in range(32):
            scope.marker = (0xC0DEC0DE ^ (case * 0x9E3779B9)) & 0xFFFFFFFF
            scope.events = []
            vm = scope.vm
            vm.reg_write(reg.UC_ARM64_REG_SP, STACK + 0x80000)
            vm.reg_write(reg.UC_ARM64_REG_X30, STOP)
            # An arbitrary incoming X3 must be replaced by the tail wrapper's zero.
            vm.reg_write(reg.UC_ARM64_REG_X3, HEAP + 0x190000 + case * 8)
            vm.emu_start(start, STOP, count=1000)
            actual = [vm.reg_read(reg.UC_ARM64_REG_PC), vm.reg_read(reg.UC_ARM64_REG_X0),
                      scope.events, struct.unpack('<I', vm.mem_read(scope.object + 0x30, 4))[0],
                      struct.unpack('<Q', vm.mem_read(scope.object, 8))[0]]
            wanted = [STOP, scope.object, expected, scope.marker, scope.klass]
            if actual != wanted: raise AssertionError(f'Factory {name} case {case} differs: {actual}')
            checks += len(wanted)
    report = dict(status='PASS_ORIGINAL_NO_ARGUMENT_FACTORY_TO_MANAGED_INVOKER_BOUNDARY',
                  cases=64, checks=checks, factory_rva=hex(FACTORY), existing_factory_rva='0xB4D8F0',
                  reviewed_functions={k: dict(rva=hex(a), bytes=b-a,
                    sha256=hashlib.sha256(scope.vm.mem_read(a, b-a)).hexdigest()) for k, (a, b) in FUNCTIONS.items()},
                  executed_blocks=dict(scope.visited), supplied_runtime_boundaries=dict(scope.boundaries),
                  text_modified=False,
                  scope='Original no-argument ArrayTypeMismatchException tail factory, existing 64-byte IndexOutOfRangeException factory, zero-message generic factory path, corlib getter and default-constructor dispatcher. Corlib class lookup, zeroed allocation, .ctor/0 lookup, invocation preparation and managed invoker are supplied boundaries. Constructor bodies, GC, allocation failure, exception unwinding, alternate message paths and whole gameplay are not executed.')
    destination(ROOT, ROOT/'reports/compiler-priority-native-exception-factory.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
