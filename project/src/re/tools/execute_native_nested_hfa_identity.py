"""Observe three original nested-HFA identity boundaries, without runtime hooks."""
import hashlib
import json
import random
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS, ROOT
from usb_boundary import destination
from unicorn import arm64_const as reg


def main():
    observations = json.loads((ROOT / 'analysis/il2cpp/generic-field-layout-observations.json').read_text())
    methods = observations['aggregate_methods']
    wanted = [('convert', 'DG.Tweening.Plugins.Vector3WrapperPlugin::ConvertToStartValue', 0xA6A1E0),
              ('unwrap', 'DG.Tweening.Core.Surrogates.Vector3Wrapper::op_Implicit', 0xA5D9F0),
              ('wrap', 'DG.Tweening.Core.Surrogates.Vector3Wrapper::op_Implicit', 0xA5DA00)]
    FUNCTIONS.clear()
    for alias, name, address in wanted:
        if sum(row['name'] == name and int(row['rva'], 16) == address for row in methods) != 1:
            raise ValueError('Metadata identity witness differs')
        FUNCTIONS[alias] = (address, address + 4)
    scope = CapsuleScope()
    instructions = []
    for alias, _, address in wanted:
        code = bytes(scope.vm.mem_read(address, 4))
        if code.hex() != 'c0035fd6':
            raise ValueError(f'Expected independently checked immediate RET at {address:X}, got {code.hex()}')
        instructions.append(dict(alias=alias, rva=f'0x{address:X}', sha256=hashlib.sha256(code).hexdigest()))
    bits = [0, 0x80000000, 1, 0x80000001, 0x007fffff, 0x00800000, 0x3f800000, 0xbf800000,
            0x7f7fffff, 0xff7fffff, 0x7f800000, 0xff800000, 0x7fc12345, 0xffc54321, 0x7fa11111, 0xffa22222]
    vectors = [[bits[i], bits[(i+3) % len(bits)], bits[(i+7) % len(bits)]] for i in range(len(bits))]
    generator = random.Random(0xA6A1E0)
    vectors += [[generator.getrandbits(32) for _ in range(3)] for _ in range(64)]
    rows = []
    for alias, _, address in wanted:
        for vector in vectors:
            for index, value in enumerate(vector):
                scope.vm.reg_write(getattr(reg, 'UC_ARM64_REG_Q' + str(index)), value)
            scope.invoke(alias, [0, 0, 0], [])
            result = [scope.vm.reg_read(getattr(reg, 'UC_ARM64_REG_Q' + str(i))) & 0xffffffff for i in range(3)]
            if vector != result:
                raise AssertionError('Original identity changed component bits')
            rows.append(dict(method=alias, rva=f'0x{address:X}', input=vector, result=result))
    fixture = destination(ROOT, ROOT / 'analysis/il2cpp/nested-hfa-identity-native-fixtures-v1.json')
    fixture.write_text(json.dumps(rows, indent=2) + '\n')
    report = dict(status='PASS_ORIGINAL_NESTED_HFA_IDENTITY_BOUNDARIES', methods=instructions,
                  cases=len(rows), checks=len(rows) * 3, fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                  abi_reference='https://github.com/ARM-software/abi-aa/blob/2025Q1/aapcs64/aapcs64.rst#5105homogeneous-aggregates',
                  scope='Three distinct metadata-linked original one-instruction RET functions. Three input and returned '
                        'scalar FP registers checked directly, including arbitrary float bit patterns and NaN payloads '
                        'without arithmetic. No runtime hooks, boxed receiver/constructor, other ABI shape or game parity claim.')
    destination(ROOT, ROOT / 'reports/native-nested-hfa-identity.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
