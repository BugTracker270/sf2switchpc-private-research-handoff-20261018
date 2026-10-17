"""Execute only the original pointer field setter against isolated object bytes."""
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/python-unicorn-2.1.4'))
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X30, UC_ARM64_REG_PC


def main():
    raw = (ROOT / 'analysis/nso/main-uncompressed.nso').read_bytes()
    if hashlib.sha256(raw).hexdigest() != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original native input differs')
    rva, offset = 0x1520D00, 0x38
    code = raw[0x100 + rva:0x100 + rva + 8]
    if code.hex() != '011c00f9c0035fd6':
        raise ValueError('Original exact setter differs')
    vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    vm.mem_map(rva & ~0xFFF, 0x1000)
    vm.mem_write(rva, code)
    vm.mem_protect(rva & ~0xFFF, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    heap, stop = 0x10000000, 0x30000000
    vm.mem_map(heap, 0x1000)
    vm.mem_map(stop, 0x1000)
    writes = []
    vm.hook_add(UC_HOOK_MEM_WRITE, lambda vm, access, address, size, value, context: writes.append((address, size)))
    generator = random.Random(0x1520D00)
    pointers = [0, 1, 0x10000000, 0x7FFFFFFFFFFFFFFF] + [generator.getrandbits(64) for _ in range(60)]
    for pointer in pointers:
        before = bytes(generator.getrandbits(8) for _ in range(0x60))
        vm.mem_write(heap, before)
        writes.clear()
        vm.reg_write(UC_ARM64_REG_X0, heap)
        vm.reg_write(UC_ARM64_REG_X1, pointer)
        vm.reg_write(UC_ARM64_REG_X30, stop)
        vm.emu_start(rva, stop, count=3)
        if vm.reg_read(UC_ARM64_REG_PC) != stop or writes != [(heap + offset, 8)]:
            raise ValueError('Setter did not make exactly the reviewed store and return')
        after = bytes(vm.mem_read(heap, len(before)))
        if struct.unpack_from('<Q', after, offset)[0] != pointer:
            raise AssertionError('Reference pointer store differs')
        if after[:offset] + after[offset + 8:] != before[:offset] + before[offset + 8:]:
            raise AssertionError('Unrelated object bytes changed')
    report = dict(status='PASS_ORIGINAL_REFERENCE_FIELD_SETTER', rva=f'0x{rva:X}', field_offset=f'0x{offset:X}',
        cases=len(pointers), checks=2 * len(pointers), native_sha256=hashlib.sha256(code).hexdigest(),
        game_function_mocks=0, runtime_replacement_hooks=0, write_observation_hooks=1,
        text_modified=False, initialization_guards_modified=False,
        scope='Only the original two-instruction reference field setter executes. Arbitrary pointer payloads including null are stored into valid synthetic receiver bytes; an observational write hook checks exact address/width, and all unrelated receiver bytes are checked afterward. No runtime behavior is replaced. Pointer targets are opaque, with no GC, original class construction, caller, Unity or full-game parity claim.')
    destination(ROOT, ROOT / 'reports/private-access-native-store-v28.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
