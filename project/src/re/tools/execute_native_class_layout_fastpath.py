"""Unchanged original Class::Init initialized path and stopped null-assert boundary."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
from execute_native_ai_leaves import NativeScope, FUNCTIONS, ROOT, HEAP, STACK, STOP
from usb_boundary import destination
from unicorn import arm64_const as reg


class Scope(NativeScope):
    def __init__(self):
        self.assert_arguments = None
        super().__init__()

    def block(self, vm, address, size, context):
        if address == 0x2373068:
            self.assert_arguments = [vm.reg_read(register) for register in
                                     (reg.UC_ARM64_REG_X0, reg.UC_ARM64_REG_X1, reg.UC_ARM64_REG_X2, reg.UC_ARM64_REG_X3)]
            vm.emu_stop()  # stop before the imported assertion; no implementation or return supplied
            return
        return super().block(vm, address, size, context)


def main():
    FUNCTIONS.clear()
    FUNCTIONS.update(layout_init=(0xB04F60, 0xB04FEC))
    scope = Scope()
    klass, stack = HEAP + 0x1000, STACK + 0x80000
    original = bytes(scope.vm.mem_read(0xB04F60, 140))
    if hashlib.sha256(original).hexdigest() != '496575374643a8ca7a9f1181d685de0fa4ac68574a3cc50c315d52d74a4d7dd3':
        raise ValueError('Exact original native wrapper differs')
    cases = checks = 0
    registers = (reg.UC_ARM64_REG_X19, reg.UC_ARM64_REG_X29)
    preserved = (0xF0E1D2C3B4A59687, 0x123456789ABCDEF0)
    for flag in range(256):
        if flag & 2 == 0:
            continue
        for incoming_x1 in (0, 1, 0xDEADBEEF5A5A5A5A, klass + 3):
            before = bytearray(b'\xA5' * 0x200)
            before[0x121] = flag
            scope.vm.mem_write(klass, bytes(before))
            scope.vm.reg_write(reg.UC_ARM64_REG_X0, klass)
            scope.vm.reg_write(reg.UC_ARM64_REG_X1, incoming_x1)
            scope.vm.reg_write(reg.UC_ARM64_REG_SP, stack)
            scope.vm.reg_write(reg.UC_ARM64_REG_X30, STOP)
            for register, value in zip(registers, preserved):
                scope.vm.reg_write(register, value)
            scope.vm.emu_start(0xB04F60, STOP, count=100)
            actual = (scope.vm.reg_read(reg.UC_ARM64_REG_PC), scope.vm.reg_read(reg.UC_ARM64_REG_X0),
                scope.vm.reg_read(reg.UC_ARM64_REG_X1), scope.vm.reg_read(reg.UC_ARM64_REG_SP),
                *(scope.vm.reg_read(register) for register in registers), bytes(scope.vm.mem_read(klass, 0x200)))
            expected = (STOP, 1, incoming_x1, stack, *preserved, bytes(before))
            if actual != expected:
                raise AssertionError('Original initialized path differs')
            cases += 1
            checks += len(expected)
    scope.vm.reg_write(reg.UC_ARM64_REG_X0, 0)
    scope.vm.reg_write(reg.UC_ARM64_REG_X1, 0xDEADBEEF5A5A5A5A)
    scope.vm.reg_write(reg.UC_ARM64_REG_SP, stack)
    scope.vm.reg_write(reg.UC_ARM64_REG_X30, STOP)
    scope.vm.emu_start(0xB04F60, STOP, count=100)
    if scope.assert_arguments is None or scope.assert_arguments[2] != 1443:
        raise AssertionError('Original null argument did not reach its exact source-line assertion boundary')
    def cstring(at):
        data = bytearray()
        for index in range(512):
            value = scope.vm.mem_read(at + index, 1)[0]
            if value == 0:
                return data.decode('utf-8')
            data.append(value)
        raise ValueError('Bounded assertion string missing terminator')
    expressions = [cstring(scope.assert_arguments[index]) for index in (0, 1, 3)]
    private = destination(ROOT, ROOT / 'analysis/reconstruction/class-layout-runtime-source-v37/assertion-identity.json')
    private.parent.mkdir(parents=True, exist_ok=True)
    private.write_text(json.dumps(dict(raw_arguments=scope.assert_arguments, expression=expressions[0],
        source_path=expressions[1], source_function=expressions[2], source_line=1443), indent=2) + '\n', encoding='utf-8')
    if expressions[0] != 'klass' or not expressions[1].endswith('Class.cpp') or expressions[2] != 'Init':
        raise AssertionError('Original assertion source/signature identity differs; actual strings preserved privately')
    if bytes(scope.vm.mem_read(0xB04F60, 140)) != original:
        raise AssertionError('Original native code changed')
    report = dict(status='PASS_ORIGINAL_INITIALIZED_LAYOUT_BOOL_AND_NULL_ASSERT_BOUNDARY', cases=cases, checks=checks,
        initialized_flag_values=128, incoming_x1_values_per_flag=4, returned_boolean=True,
        null_assert_boundary_cases=1, null_assert_source_line=1443,
        native_source_sha256='bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968',
        native_code_sha256=hashlib.sha256(original).hexdigest(), native_code_bytes=140, code_unmodified=True,
        guest_function_replacements=0, imported_assertion_stopped_before_execution=True,
        private_assertion_identity_sha256=hashlib.sha256(private.read_bytes()).hexdigest(),
        probe_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        scope='Only the original already-initialized Class::Init path executes to return; 128 flag patterns and four incoming X1 values each verify true result, preserved frame/registers and unchanged class bytes. Null input executes unchanged native instructions to the imported assertion entry, where execution stops. Uninitialized metadata setup, real locking/unwinding/assertion termination, managed .cctor and complete callers are not executed.')
    destination(ROOT, ROOT / 'reports/native-class-layout-bool-v37.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'cases', 'checks', 'null_assert_boundary_cases', 'code_unmodified')}))


if __name__ == '__main__':
    main()
