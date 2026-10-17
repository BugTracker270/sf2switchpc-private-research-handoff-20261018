"""Generate exact original CurrencyStruct field-copy fixtures, including padding."""
import hashlib
import json
import random
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS, ROOT, HEAP
from usb_boundary import destination
from unicorn import arm64_const as reg


def main():
    FUNCTIONS.update(currency_aggregate_set=(0xD3D370, 0xD3D378),
                     currency_aggregate_get=(0xD3D390, 0xD3D39C))
    scope = CapsuleScope()
    vm = scope.vm
    owner = HEAP + 0x30000
    rng = random.Random(0xD3D370)
    cases = checks = nonzero_padding = 0
    rows = []
    for index in range(1024):
        ints = [rng.getrandbits(32) for _ in range(3)]
        inited = index & 1
        padding = 0 if index < 16 else rng.getrandbits(24)
        words = [ints[0] | ints[1] << 32, ints[2] | inited << 32 | padding << 40]
        before = b'\xA5' * 24
        after = b'\x5A' * 24
        vm.mem_write(owner, before + b'\xCC' * 16 + after)
        scope.invoke('currency_aggregate_set', [owner, *words, 0], [])
        stored = struct.unpack('<QQ', vm.mem_read(owner + 0x18, 16))
        if tuple(words) != stored:
            raise AssertionError(f'Native setter differs at {index}')
        checks += 2
        if bytes(vm.mem_read(owner, 24)) != before or bytes(vm.mem_read(owner + 40, 24)) != after:
            raise AssertionError(f'Native setter changed outside field at {index}')
        checks += 2
        scope.invoke('currency_aggregate_get', [owner, 0], [])
        result = [vm.reg_read(reg.UC_ARM64_REG_X0), vm.reg_read(reg.UC_ARM64_REG_X1)]
        if result != words:
            raise AssertionError(f'Native getter differs at {index}')
        checks += 2
        nonzero_padding += padding != 0
        rows.append(dict(index=index, input_words=words, returned_words=result,
                         fields=ints + [inited], padding=padding))
        cases += 1
    fixture = destination(ROOT, ROOT / 'analysis/il2cpp/integer-aggregate-leaf-native-fixtures-v1.jsonl')
    fixture.write_text(''.join(json.dumps(row, separators=(',', ':')) + '\n' for row in rows), encoding='utf-8')
    report = dict(status='PASS_ORIGINAL_NATIVE_16BYTE_FIELD_COPY_FIXTURES', cases=cases, checks=checks,
                  nonzero_padding_cases=nonzero_padding, fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                  fixture=str(fixture.relative_to(ROOT)), game_function_mocks=0, text_modified=False,
                  calls=dict(scope.calls), executed_functions=dict(scope.visited),
                  native_text_sha256={name: hashlib.sha256(vm.mem_read(start, end-start)).hexdigest()
                                      for name, (start, end) in FUNCTIONS.items() if name.startswith('currency_aggregate_')},
                  scope='Original eight-byte setter and twelve-byte getter only; synthetic owner storage with guard bytes. Native copies preserve all 16 bytes including tail padding. Managed recovered comparisons must compare the four declared fields and expressly exclude padding-byte identity. No currency codec, class initialization, GC, null receiver, general integer aggregate ABI, or complete game claim.')
    destination(ROOT, ROOT / 'reports/integer-aggregate-leaf-native-fixtures.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
