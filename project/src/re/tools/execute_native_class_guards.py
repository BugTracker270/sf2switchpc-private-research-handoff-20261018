"""Check original class-init macro control flow at an explicit runtime boundary."""
import hashlib
import json
import struct
from execute_native_ai_leaves import ROOT, HEAP
from native_unwind_inventory import Image
from usb_boundary import destination
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn import arm64_const as reg

# Reviewed original sites, including an exception-path duplicate which ordinary
# linear listings omit. No generated CIL or recovered source supplies the oracle.
SITES = [
    (0x2222FC, 0x222310), (0x222390, 0x2223A4),
    (0x2223C0, 0x2223D4), (0x222404, 0x222418),
    (0x222444, 0x222458), (0x222498, 0x2224AC),
    (0x4A83EC, 0x4A8404), (0x4A84D8, 0x4A84F0),
    (0x4A8570, 0x4A8588), (0x4A85FC, 0x4A8610),
    (0x4A8620, 0x4A8634), (0x4A864C, 0x4A8664),
]
INITIALIZER = 0xB2E720


def main():
    image = Image((ROOT / 'analysis/nso/main-uncompressed.nso').read_bytes())
    cases = checks = runtime_calls = 0
    witnesses = []
    for start, skip in SITES:
        original = image.read(start, skip - start)
        words = list(struct.unpack('<' + 'I' * (len(original) // 4), original))
        if words[0] != 0x39448808 or words[2] != 0xB940D408:
            raise ValueError('Original class flag/finished offsets differ')
        immediate = words[4] & 0x3FFFFFF
        if immediate & (1 << 25):
            immediate -= 1 << 26
        if words[4] & 0xFC000000 != 0x94000000 or start + 16 + 4 * immediate != INITIALIZER:
            raise ValueError('Original class-init call differs')
        vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        page = start & ~0xFFF
        vm.mem_map(page, 0x2000)
        vm.mem_write(start, original)
        vm.mem_protect(page, 0x2000, UC_PROT_READ | UC_PROT_EXEC)
        vm.mem_map(INITIALIZER & ~0xFFF, 0x1000)
        vm.mem_map(HEAP, 0x2000)
        klass, slot, clobbered = HEAP + 0x100, HEAP + 0x1000, HEAP + 0x800
        vm.mem_write(slot, struct.pack('<Q', klass))
        if len(words) == 6:
            if words[5] & 0xFFC0001F != 0xF9400000:
                raise ValueError('Unexpected post-call class reload')
            source = (words[5] >> 5) & 31
            offset = ((words[5] >> 10) & 0xFFF) * 8
            vm.reg_write(getattr(reg, 'UC_ARM64_REG_X' + str(source)), slot - offset)
        state = {'calls': 0}

        def instruction(machine, address, size, _):
            if address == INITIALIZER:
                if machine.reg_read(reg.UC_ARM64_REG_X0) != klass:
                    raise AssertionError('Original initializer receives wrong class')
                state['calls'] += 1
                machine.mem_write(klass + 0xD4, struct.pack('<I', 1))
                machine.reg_write(reg.UC_ARM64_REG_X0, clobbered)
                machine.reg_write(reg.UC_ARM64_REG_PC, machine.reg_read(reg.UC_ARM64_REG_X30))
            elif not start <= address < skip:
                raise AssertionError(f'Unreviewed original instruction {address:#x}')

        vm.hook_add(UC_HOOK_CODE, instruction)
        for flags in [0, 1, 2, 3, 128, 129, 255]:
            for finished in [0, 1, 2, 0xFFFFFFFF]:
                vm.mem_write(klass + 0x122, bytes([flags]))
                vm.mem_write(klass + 0xD4, struct.pack('<I', finished))
                vm.reg_write(reg.UC_ARM64_REG_X0, klass)
                state['calls'] = 0
                vm.emu_start(start, skip, count=32)
                expected = int(bool(flags & 1) and finished == 0)
                expected_class = klass if len(words) == 6 or not expected else clobbered
                if (vm.reg_read(reg.UC_ARM64_REG_PC) != skip
                        or state['calls'] != expected
                        or vm.reg_read(reg.UC_ARM64_REG_X0) != expected_class):
                    raise AssertionError(f'Original macro differs at {start:#x}/{flags}/{finished}')
                cases += 1
                checks += 3
                runtime_calls += state['calls']
        if bytes(vm.mem_read(start, len(original))) != original:
            raise AssertionError('Original text modified')
        witnesses.append(dict(start_rva=start, skip_rva=skip,
                              original_text_sha256=hashlib.sha256(original).hexdigest()))
    report = dict(status='PASS_ORIGINAL_CLASS_GUARD_BRANCHES_AT_RUNTIME_BOUNDARY',
                  cases=cases, checks=checks, supplied_runtime_calls=runtime_calls,
                  macros=witnesses, text_modified=False,
                  scope='Original native flag tests, branches and optional class reloads only. '
                        'Synthetic class/slot memory; runtime initializer is an explicit supplied '
                        'boundary which marks completion and clobbers X0. This validates macro '
                        'recognition, not the initializer implementation, managed initialization '
                        'ordering, exceptions, threading or whole-method/source correctness.')
    destination(ROOT, ROOT / 'reports/native-class-guard-branches.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
