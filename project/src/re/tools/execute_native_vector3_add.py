"""Observe the original three-register Vector3 addition ABI without runtime hooks."""
import hashlib
import json
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS, ROOT
from usb_boundary import destination
from unicorn import arm64_const as reg


def main():
    FUNCTIONS.clear()
    FUNCTIONS['add'] = (0x15D9380, 0x15D9390)
    scope = CapsuleScope()
    original = bytes(scope.vm.mem_read(0x15D9380, 16))
    if original.hex() != '0028231e2128241e4228251ec0035fd6':
        raise ValueError('Original Vector3 addition instructions changed')
    bits = [0, 0x80000000, 0x3F800000, 0xBF800000, 0x3EAAAAAB, 0x7F7FFFFF, 0x00800000, 0x80800000]
    rows = []
    for i in range(len(bits)):
        for j in range(len(bits)):
            a = [bits[(i+k) % len(bits)] for k in range(3)]
            b = [bits[(j+2*k) % len(bits)] for k in range(3)]
            for index, value in enumerate(a+b):
                scope.vm.reg_write(getattr(reg, 'UC_ARM64_REG_Q'+str(index)), value)
            scope.invoke('add', [0, 0], [])
            result = [scope.vm.reg_read(getattr(reg, 'UC_ARM64_REG_Q'+str(k))) & 0xFFFFFFFF for k in range(3)]
            rows.append(dict(a=a, b=b, result=result))
    fixture = destination(ROOT, ROOT / 'analysis/il2cpp/vector3-native-fixtures-v1.json')
    fixture.write_text(json.dumps(rows, indent=2)+'\n', encoding='utf-8')
    report = dict(status='PASS_ORIGINAL_VECTOR3_THREE_FP_REGISTER_OBSERVATIONS', cases=len(rows),
                  component_observations=3*len(rows), input_registers=['S0','S1','S2','S3','S4','S5'], result_registers=['S0','S1','S2'],
                  original_text_sha256=hashlib.sha256(original).hexdigest(), fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                  scope='Original four-instruction Vector3 addition, no executed runtime/game hooks. Finite inputs include signed zero, subnormals, extreme values and possible output overflow. No NaN-payload, other HFA shapes, stack spills or complete ABI certification.')
    destination(ROOT, ROOT / 'reports/native-vector3-add-abi.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
