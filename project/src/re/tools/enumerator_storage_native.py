"""Bounded execution of the unchanged indirect List<ref> enumerator return body."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
sys.path.insert(0, str(ROOT / 'tools/python-unicorn-2.1.4'))
from usb_boundary import destination
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X8, UC_ARM64_REG_X30

SOURCE_HASH = 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968'
GET = 0x1585F60
CTOR = 0x11DD130
GET_BYTES = bytes.fromhex('1ffd00a9e90300aa1f0100f92a0c40f9e10309aa4a6140f9428d40f9e00308aa6c5cf117')
CTOR_BYTES = bytes.fromhex('010000f9281c40b9080c00b9c0035fd6')


def main():
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    digest = hashlib.file_digest(source.open('rb'), 'sha256').hexdigest()
    if digest != SOURCE_HASH:
        raise ValueError('Original source hash differs')
    with source.open('rb') as f:
        def read(rva, size):
            f.seek(0x100 + rva)
            return f.read(size)
        if read(GET, len(GET_BYTES)) != GET_BYTES or read(CTOR, len(CTOR_BYTES)) != CTOR_BYTES:
            raise ValueError('Native return/constructor body differs')
        caller_zero = read(0xC9F440, 8)
        caller_call = read(0xC9F4C8, 24)
        caller_consumers = [read(rva, 12) for rva in (0xC9F4F8, 0xC9F508, 0xC9F58C)]

    heap = 0x50000000
    stop = 0x60000000
    result = heap + 0x200
    mi = heap + 0x1000
    table1 = heap + 0x2000
    table2 = heap + 0x3000
    ctor_info = heap + 0x4000
    cases = []
    checks = 0
    for i, version in enumerate((0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff)):
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for rva, code in ((GET, GET_BYTES), (CTOR, CTOR_BYTES)):
            uc.mem_map(rva & ~0xfff, 0x1000)
            uc.mem_write(rva, code)
        uc.mem_map(heap, 0x10000)
        uc.mem_map(stop, 0x1000)
        list_ptr = heap + 0x6000 + i * 0x100
        uc.mem_write(result - 16, bytes([0xa5]) * 56)
        for address, value in ((mi + 0x18, table1), (table1 + 0xc0, table2), (table2 + 0x118, ctor_info)):
            uc.mem_write(address, struct.pack('<Q', value))
        uc.mem_write(list_ptr + 0x1c, struct.pack('<I', version))
        uc.reg_write(UC_ARM64_REG_X0, list_ptr)
        uc.reg_write(UC_ARM64_REG_X1, mi)
        uc.reg_write(UC_ARM64_REG_X8, result)
        uc.reg_write(UC_ARM64_REG_X30, stop)
        writes = []
        def observe(uc, access, address, size, value, user):
            writes.append((address, size))
        uc.hook_add(UC_HOOK_MEM_WRITE, observe)
        uc.emu_start(GET, stop, count=32)
        observed = bytes(uc.mem_read(result, 24))
        expected = struct.pack('<QIIQ', list_ptr, 0, version, 0)
        predicates = [observed == expected,
            bytes(uc.mem_read(result - 16, 16)) == bytes([0xa5]) * 16,
            bytes(uc.mem_read(result + 24, 16)) == bytes([0xa5]) * 16,
            uc.reg_read(UC_ARM64_REG_X0) == result,
            all(result <= address and address + size <= result + 24 for address, size in writes),
            {address + j - result for address, size in writes for j in range(size)} == set(range(24))]
        if not all(predicates):
            raise AssertionError(f'Native result mismatch in case {i}')
        checks += len(predicates)
        cases.append(dict(version_bits=f'0x{version:08X}', result_payload_sha256=hashlib.sha256(observed).hexdigest(),
            result_buffer_complete_24_byte_write=True, output_x0_is_buffer_address=True,
            x8_overwritten_by_constructor=uc.reg_read(UC_ARM64_REG_X8) != result, writes=len(writes)))

    report = dict(status='PASS_ORIGINAL_NATIVE_INDIRECT_ENUMERATOR_RETURN_ONLY', cases=len(cases), checks=checks,
        probe_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        native_source_sha256=digest, source_input=str(source.relative_to(ROOT)), code_unmodified=True,
        getenumerator_rva=f'0x{GET:X}', constructor_rva=f'0x{CTOR:X}',
        getenumerator_code_sha256=hashlib.sha256(GET_BYTES).hexdigest(), constructor_code_sha256=hashlib.sha256(CTOR_BYTES).hexdigest(),
        selected_caller='Nekki.SF2.Core.Fights.Fight.SetStage', caller_rva='0xC9F3F0',
        caller_zero_window_rva='0xC9F440', caller_zero_window_sha256=hashlib.sha256(caller_zero).hexdigest(),
        caller_call_window_rva='0xC9F4C8', caller_call_window_sha256=hashlib.sha256(caller_call).hexdigest(),
        caller_consumer_window_sha256=[hashlib.sha256(x).hexdigest() for x in caller_consumers],
        caller_static_observations=dict(zero_coverage='STP XZR,XZR at SP+0x10 plus STR XZR at SP+0x8 covers precisely SP+0x8..0x1F',
            hidden_return_buffer='X8=SP+0x8 immediately before BL GetEnumerator at 0xC9F4DC',
            consumer_receivers='X0=SP+0x8 before MoveNext, get_Current and Dispose',
            constructor_return='X0 remains the buffer address; this is not aggregate return bits in X0',
            callsite_recovery_requirement='Preserve incoming X8 buffer identity before the native call; X8 is overwritten inside the constructor'),
        synthetic_boundaries='Opaque list storage with supplied native version field, MethodInfo/context pointer tables and result memory. No original metadata initialization or game class method is executed. These two unchanged native bodies execute fully with no code/runtime replacement hooks; the write hook observes only.',
        caller_itself_executed=False, whole_game_execution=False, results=cases)
    path = destination(ROOT, ROOT / 'reports/enumerator-native-return-v31.json')
    path.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Native enumerator return PASS: {len(cases)} cases / {checks} checks; {path}')


if __name__ == '__main__':
    main()
