"""Execute original Boolean reader and converter at explicit initialized-runtime inputs."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
sys.path.insert(0, str(ROOT / 'tools/python-unicorn-2.1.4'))
from usb_boundary import destination
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as reg

SOURCE_HASH = 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968'
METHODS = {
    'readboolean': (0xF0D390, 148, 'a2c22a6bcf2d17e31452dd9f67a08c42b7b246e10cf3db95f8e6cac2a1fef722'),
    'toboolean': (0x89D060, 316, '5380a7ce418e5ad7e7423ae1f3114e9cd752d23949c0effd91e0f46ba8d3423d'),
}
HEAP, STACK, STOP = 0x50000000, 0x60000000, 0x70000000
CLASS_SLOT, CLASS, SELF, ARRAY = HEAP + 0x800, HEAP + 0x1000, HEAP + 0x2000, HEAP + 0x4000


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inputs():
    for value in range(256):
        yield f'byte-{value:02x}', bytes([value]), 0
    patterns = (
        ('ramp256', bytes(range(256))),
        ('mixed8', bytes([0, 1, 2, 127, 128, 255, 0, 254])),
        ('zeros17', bytes(17)),
        ('ones17', bytes([255]) * 17),
        ('permutation257', bytes((i * 197 + 31) & 255 for i in range(257))),
    )
    for name, data in patterns:
        for position in range(len(data)):
            yield f'{name}-at-{position}', data, position


def main():
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    if digest(source) != SOURCE_HASH:
        raise ValueError('Original source NSO differs')
    frames_path = ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl'
    frames = {}
    with frames_path.open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['rva'] in {m[0] for m in METHODS.values()}:
                if row['rva'] in frames:
                    raise ValueError('Ambiguous exact frame')
                frames[row['rva']] = row
    vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    with source.open('rb') as stream:
        for name, (address, size, expected_hash) in METHODS.items():
            if frames[address]['end_rva'] - address != size:
                raise ValueError('Exact original frame extent differs: ' + name)
            stream.seek(0x100 + address)
            body = stream.read(size)
            if hashlib.sha256(body).hexdigest() != expected_hash:
                raise ValueError('Exact original body differs: ' + name)
            vm.mem_map(address & ~0xFFF, 0x1000)
            vm.mem_write(address, body)
    for address, size in ((HEAP, 0x10000), (STACK, 0x10000), (STOP, 0x1000),
                          (0x3B86000, 0x1000), (0x3A36000, 0x1000), (0x397D000, 0x1000)):
        vm.mem_map(address, size)
    # Explicit supplied runtime state; no initialization function or guest code is replaced.
    vm.mem_write(0x3B86035, b'\x01')  # Reader metadata already initialized.
    vm.mem_write(0x3A36D00, b'\x01')  # BitConverter method metadata already initialized.
    vm.mem_write(0x397DCC0, struct.pack('<Q', CLASS_SLOT))
    vm.mem_write(CLASS_SLOT, struct.pack('<Q', CLASS))
    vm.mem_write(CLASS + 0x122, b'\x01')  # has_cctor.
    vm.mem_write(CLASS + 0xD4, struct.pack('<I', 1))  # cctor_finished.
    visited, writes, total_visits = [], [], Counter()

    def observe_code(machine, address, size, context):
        if not any(start <= address < start + length for start, length, _ in METHODS.values()):
            raise AssertionError(f'Unexpected original runtime/code dependency: {address:X}')
        visited.append(address)
        total_visits[address] += 1

    def observe_write(machine, access, address, size, value, context):
        writes.append((address, size, value))

    vm.hook_add(UC_HOOK_CODE, observe_code)
    vm.hook_add(UC_HOOK_MEM_WRITE, observe_write)
    fixtures, checks = [], 0
    caller_saved = (reg.UC_ARM64_REG_X19, reg.UC_ARM64_REG_X20, reg.UC_ARM64_REG_X21, reg.UC_ARM64_REG_X29)
    saved_values = [0x123450000 + i * 0x1111 for i in range(len(caller_saved))]
    for identity, data, position in inputs():
        object_bytes = bytearray(b'\xA5' * 0x40)
        struct.pack_into('<I', object_bytes, 0x14, position)
        struct.pack_into('<Q', object_bytes, 0x18, ARRAY)
        array_bytes = struct.pack('<QQQQ', HEAP + 0x6000, 0, 0, len(data)) + data
        array_guarded = b'\x5A' * 16 + array_bytes + b'\x5A' * 16
        vm.mem_write(SELF, bytes(object_bytes))
        vm.mem_write(ARRAY - 16, array_guarded)
        original_sp = STACK + 0x8000
        vm.reg_write(reg.UC_ARM64_REG_SP, original_sp)
        vm.reg_write(reg.UC_ARM64_REG_X30, STOP)
        vm.reg_write(reg.UC_ARM64_REG_X0, SELF)
        vm.reg_write(reg.UC_ARM64_REG_X1, 0)
        for register, value in zip(caller_saved, saved_values):
            vm.reg_write(register, value)
        visited.clear()
        writes.clear()
        vm.emu_start(METHODS['readboolean'][0], STOP, count=512)
        result = vm.reg_read(reg.UC_ARM64_REG_W0)
        position_after = struct.unpack('<I', bytes(vm.mem_read(SELF + 0x14, 4)))[0]
        expected_object = bytearray(object_bytes)
        struct.pack_into('<I', expected_object, 0x14, position + 1)
        heap_writes = [(a, s, v) for a, s, v in writes if not STACK <= a < STACK + 0x10000]
        predicates = (
            vm.reg_read(reg.UC_ARM64_REG_PC) == STOP,
            result in (0, 1) and result == int(data[position] != 0),
            position_after == position + 1,
            bytes(vm.mem_read(SELF, len(object_bytes))) == bytes(expected_object),
            bytes(vm.mem_read(ARRAY - 16, len(array_guarded))) == array_guarded,
            heap_writes == [(SELF + 0x14, 4, position + 1)],
            vm.reg_read(reg.UC_ARM64_REG_SP) == original_sp,
            [vm.reg_read(r) for r in caller_saved] == saved_values,
            visited.count(0xF0D400) == 1 and visited.count(0x89D060) == 1,
            0xF0D3D8 in visited and 0xF0D3E4 in visited and 0xF0D3EC not in visited,
            bytes(vm.mem_read(CLASS + 0x122, 1)) == b'\x01'
                and bytes(vm.mem_read(CLASS + 0xD4, 4)) == struct.pack('<I', 1),
        )
        if not all(predicates):
            raise AssertionError(f'Original Boolean reader mismatch: {identity}: {predicates}')
        checks += len(predicates)
        fixtures.append(dict(id=identity, bytes_hex=data.hex(), position_before=position,
                             returned_boolean=bool(result), position_after=position_after, outcome='return'))
    # Confirm loaded guest instructions remained exactly the original source bodies.
    for address, size, expected_hash in METHODS.values():
        if hashlib.sha256(bytes(vm.mem_read(address, size))).hexdigest() != expected_hash:
            raise AssertionError('Guest instructions were modified')
    fixture_path = destination(ROOT, ROOT / 'analysis/reconstruction/boolean-reader-reference/fixtures.jsonl')
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_text(''.join(json.dumps(row, separators=(',', ':')) + '\n' for row in fixtures), encoding='utf-8')
    report = dict(status='PASS_ORIGINAL_BOOLEAN_READER_RETURN_AND_POSITION_AT_INITIALIZED_RUNTIME_BOUNDARY',
        cases=len(fixtures), checks=checks, failures=0,
        native_source_sha256=SOURCE_HASH, native_source=str(source.relative_to(ROOT)),
        readboolean_code_sha256=METHODS['readboolean'][2], toboolean_code_sha256=METHODS['toboolean'][2],
        readboolean_rva='0xF0D390', readboolean_exact_fde_bytes=148,
        toboolean_rva='0x89D060', toboolean_exact_fde_bytes=316,
        fde_inventory_sha256=digest(frames_path), code_unmodified=True,
        fixture_path=str(fixture_path.relative_to(ROOT)), fixture_sha256=digest(fixture_path),
        probe_source_sha256=digest(Path(__file__)), all_256_single_byte_values=True,
        valid_positions_min=0, valid_positions_max=max(row['position_before'] for row in fixtures),
        native_guest_function_replacements=0, native_hooks_observe_only=True,
        original_converter_call_executed_per_case=True, class_constructor_request_branch_executed=False,
        supplied_runtime_boundaries=dict(reader_method_metadata_initialized=True,
            converter_method_metadata_initialized=True, bitconverter_has_cctor=1, bitconverter_cctor_finished=1,
            class_slot_and_global_pointers='Explicit supplied pointers, not original runtime initialization',
            receiver='Opaque storage with original native Position+0x14 and byte[]+0x18 input slots',
            byte_array='Supplied IL2CPP array header, length and payload; valid non-null inputs only'),
        executed_instruction_counts={hex(address): count for address, count in sorted(total_visits.items())},
        scope='Both unchanged original native bodies execute the complete return path with valid supplied byte arrays and positions. All 256 byte values, offsets0..256, exact Boolean normalization, post-Position, other storage, callee-saved registers and writes are checked. The original class guard observes supplied has_cctor=1 and cctor_finished=1; its constructor request branch is not executed. Metadata initialization, actual .cctor execution/effects, null/out-of-range exceptions, concurrent mutation, game initialization and whole-game behavior are outside this witness.')
    output = destination(ROOT, ROOT / 'reports/native-boolean-reader-v33.json')
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('status', 'cases', 'checks', 'failures', 'fixture_sha256')}))


if __name__ == '__main__':
    main()
