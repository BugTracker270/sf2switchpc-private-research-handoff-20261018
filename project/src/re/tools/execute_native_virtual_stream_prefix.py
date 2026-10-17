"""Run unchanged original virtual-call prefix and MemoryStream override locally."""
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
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as reg

SOURCE_SHA = 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968'
READER, READER_SIZE, PREFIX_END = 0x4A0D70, 956, 0x4A0E00
OVERRIDE, OVERRIDE_SIZE = 0x843E80, 224
READER_SHA = 'cfec6671b5b9a8788367f6b7a7b36378b9ea88bdeea69a33ab38bc3ed2a7a9b5'
OVERRIDE_SHA = '57b7b4efa4bb42ea002c751dc402dfadb2d17eeb1ca786f29c7a3b4ac8d7acad'
HEAP, STACK, STOP = 0x50000000, 0x60000000, 0x70000000
SELF, STREAM, CLASS, ARRAY, METHOD_INFO = [HEAP + n for n in (0x2000, 0x3000, 0x4000, 0x6000, 0x8000)]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def cases():
    for value in range(256):
        yield f'first-byte-{value:02x}', bytes([value, 0x82]), 0
        yield f'second-byte-{value:02x}', bytes([0x81, value]), 0
        yield f'one-byte-then-eof-{value:02x}', bytes([value]), 0
    patterns = (('empty', b''), ('mixed', bytes([0, 255, 1, 128, 127, 2, 3, 254])),
                ('ramp17', bytes(range(17))))
    for name, data in patterns:
        for position in range(len(data) + 3):
            yield f'{name}-position-{position}', data, position


def main():
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    raw = source.read_bytes()
    if digest(raw) != SOURCE_SHA:
        raise ValueError('Original source image differs')
    private_inventory = ROOT / 'analysis/reconstruction/virtual-stream-dispatch-v36/native-inventory.json'
    inventory = json.loads(private_inventory.read_text())
    exact = {int(row['rva'], 16): row for row in inventory['methods']}
    vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for address, size, expected in ((READER, READER_SIZE, READER_SHA), (OVERRIDE, OVERRIDE_SIZE, OVERRIDE_SHA)):
        if exact[address]['exact_frame']['end_rva'] - address != size or exact[address]['sha256'] != expected:
            raise ValueError('Original exact frame inventory differs')
        body = raw[0x100 + address:0x100 + address + size]
        if digest(body) != expected:
            raise ValueError('Original exact body differs')
        page = address & ~0xFFF
        mapped = ((address + size + 0xFFF) & ~0xFFF) - page
        vm.mem_map(page, mapped)
        vm.mem_write(address, body)
    for address, size in ((HEAP, 0x10000), (STACK, 0x10000), (STOP, 0x1000), (0x3A35000, 0x2000)):
        vm.mem_map(address, size)
    # These are explicit fixture inputs, not recovered runtime initialization.
    vm.mem_write(0x3A350D9, b'\x01')
    vm.mem_write(0x3A36B27, b'\x01')
    klass = bytearray(b'\xCC' * 0x300)
    struct.pack_into('<QQ', klass, 0x258, OVERRIDE, METHOD_INFO)
    vm.mem_write(CLASS, bytes(klass))
    vm.mem_write(METHOD_INFO, b'\xD3' * 32)
    visits, reads, writes, calls, returns = [], [], [], [], []
    total_visits = Counter()

    def code(machine, address, size, unused):
        if not (READER <= address < PREFIX_END or OVERRIDE <= address < OVERRIDE + OVERRIDE_SIZE):
            raise AssertionError(f'Unexpected guest code/runtime dependency: {address:x}')
        visits.append(address)
        total_visits[address] += 1
        if address == OVERRIDE:
            calls.append(dict(receiver=machine.reg_read(reg.UC_ARM64_REG_X0),
                              method_info=machine.reg_read(reg.UC_ARM64_REG_X1),
                              native_return_address=machine.reg_read(reg.UC_ARM64_REG_X30)))
        if address in (0x4A0DC8, 0x4A0DEC):
            returns.append(dict(address=address, bits=machine.reg_read(reg.UC_ARM64_REG_W0),
                                reader=machine.reg_read(reg.UC_ARM64_REG_X19),
                                stream=machine.reg_read(reg.UC_ARM64_REG_X20),
                                stack=machine.reg_read(reg.UC_ARM64_REG_SP)))

    vm.hook_add(UC_HOOK_CODE, code)
    vm.hook_add(UC_HOOK_MEM_READ, lambda m, a, at, size, v, u: reads.append((at, size)))
    vm.hook_add(UC_HOOK_MEM_WRITE, lambda m, a, at, size, v, u: writes.append((at, size, v)))
    fixtures, checks, eof_returns = [], 0, 0
    for identity, data, position in cases():
        owner = bytearray(b'\xA5' * 0x40)
        stream = bytearray(b'\x5A' * 0x50)
        struct.pack_into('<Q', stream, 0, CLASS)
        stream[0x35] = 0
        struct.pack_into('<I', stream, 0x1C, len(data))
        struct.pack_into('<I', stream, 0x20, len(data))
        struct.pack_into('<Q', stream, 0x28, ARRAY)
        struct.pack_into('<I', stream, 0x30, 0)
        struct.pack_into('<I', stream, 0x38, position)
        array = struct.pack('<QQQQ', HEAP + 0x9000, 0, 0, len(data)) + data
        guarded = b'\x6D' * 16 + array + b'\x6D' * 16
        vm.mem_write(SELF, bytes(owner))
        vm.mem_write(STREAM, bytes(stream))
        vm.mem_write(ARRAY - 16, guarded)
        vm.mem_write(STACK, b'\xB6' * 0x10000)
        original_sp = STACK + 0x8000
        vm.reg_write(reg.UC_ARM64_REG_SP, original_sp)
        for number in range(31):
            vm.reg_write(getattr(reg, f'UC_ARM64_REG_X{number}'), 0x123450000 + number * 0x101)
        vm.reg_write(reg.UC_ARM64_REG_X0, SELF)
        vm.reg_write(reg.UC_ARM64_REG_X1, STREAM)
        vm.reg_write(reg.UC_ARM64_REG_X30, STOP)
        visits.clear(); reads.clear(); writes.clear(); calls.clear(); returns.clear()
        vm.emu_start(READER, PREFIX_END, count=2048)
        values, expected_heap_writes, final_position = [], [], position
        for ordinal in range(2):
            if final_position < len(data):
                values.append(data[final_position])
                final_position += 1
                expected_heap_writes.append((STREAM + 0x38, 4, final_position))
            else:
                values.append(-1)
                eof_returns += 1
            if ordinal == 0:
                expected_heap_writes.extend(((SELF + 0x10, 1, (values[0] >> 7) & 1),
                                             (SELF + 0x11, 1, values[0] & 15)))
            else:
                expected_heap_writes.extend(((SELF + 0x12, 1, (values[1] >> 7) & 1),
                                             (SELF + 0x18, 8, values[1] & 127)))
        expected_owner = bytearray(owner)
        expected_owner[0x10:0x13] = bytes([(values[0] >> 7) & 1, values[0] & 15, (values[1] >> 7) & 1])
        struct.pack_into('<Q', expected_owner, 0x18, values[1] & 127)
        expected_stream = bytearray(stream)
        struct.pack_into('<I', expected_stream, 0x38, final_position)
        call_reads = [(at, size) for at, size in reads if at in (STREAM, CLASS + 0x258, CLASS + 0x260)]
        heap_writes = [(at, size, value) for at, size, value in writes if not STACK <= at < STACK + 0x10000]
        expected_calls = [dict(receiver=STREAM, method_info=METHOD_INFO, native_return_address=return_address)
                          for return_address in (0x4A0DC8, 0x4A0DEC)]
        predicates = (
            vm.reg_read(reg.UC_ARM64_REG_PC) == PREFIX_END,
            calls == expected_calls,
            [row['bits'] for row in returns] == [value & 0xFFFFFFFF for value in values],
            all(row['reader'] == SELF and row['stream'] == STREAM and row['stack'] == original_sp - 0x50 for row in returns),
            call_reads == [(STREAM, 8), (CLASS + 0x258, 8), (CLASS + 0x260, 8)] * 2,
            heap_writes == expected_heap_writes,
            bytes(vm.mem_read(SELF, len(owner))) == bytes(expected_owner),
            bytes(vm.mem_read(STREAM, len(stream))) == bytes(expected_stream),
            bytes(vm.mem_read(ARRAY - 16, len(guarded))) == guarded,
            bytes(vm.mem_read(CLASS, len(klass))) == bytes(klass),
            bytes(vm.mem_read(METHOD_INFO, 32)) == b'\xD3' * 32 and not any(METHOD_INFO <= at < METHOD_INFO + 32 for at, size in reads),
            all(visits.count(address) == 1 for address in (0x4A0DC4, 0x4A0DE8)),
        )
        if not all(predicates):
            raise AssertionError(f'Original virtual-call prefix mismatch: {identity}: {predicates}')
        checks += len(predicates)
        fixtures.append(dict(id=identity, bytes_hex=data.hex(), position_before=position,
                             original_returned_ints=values, position_after=final_position,
                             final=bool(expected_owner[0x10]), frame_type=expected_owner[0x11],
                             has_mask=bool(expected_owner[0x12]), length=values[1] & 127,
                             native_virtual_call_count=2, outcome='prefix_stop'))
    for address, size, expected in ((READER, READER_SIZE, READER_SHA), (OVERRIDE, OVERRIDE_SIZE, OVERRIDE_SHA)):
        if digest(bytes(vm.mem_read(address, size))) != expected:
            raise AssertionError('Original guest code changed')
    fixture_path = destination(ROOT, ROOT / 'analysis/reconstruction/virtual-stream-dispatch-v36/prefix-fixtures.jsonl')
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_text(''.join(json.dumps(row, separators=(',', ':')) + '\n' for row in fixtures))
    report = dict(status='PASS_UNCHANGED_NATIVE_STREAM_OVERRIDE_AND_VIRTUAL_READER_PREFIX',
                  cases=len(fixtures), checks=checks, failures=0, original_native_virtual_calls=len(fixtures) * 2,
                  original_native_override_entries=len(fixtures) * 2, eof_returns=eof_returns,
                  all_256_values_as_first_and_second_bytes=True,
                  native_source_sha256=SOURCE_SHA, reader_rva=hex(READER), reader_exact_fde_bytes=READER_SIZE,
                  reader_code_sha256=READER_SHA, prefix_stop=hex(PREFIX_END),
                  override_rva=hex(OVERRIDE), override_exact_fde_bytes=OVERRIDE_SIZE, override_code_sha256=OVERRIDE_SHA,
                  vtable_base=hex(0x128), virtual_slot=19, function_offset=hex(0x258), method_info_offset=hex(0x260),
                  observed_receiver_register='X0', observed_method_info_register='X1', returned_integer_register='W0',
                  metadata_signature='System.Int32 System.IO.Stream::ReadByte() instance virtual; System.IO.MemoryStream override',
                  fixture_path=str(fixture_path.relative_to(ROOT)), fixture_sha256=digest(fixture_path.read_bytes()),
                  native_inventory_sha256=digest(private_inventory.read_bytes()),
                  probe_source_sha256=digest(Path(__file__).read_bytes()),
                  original_instructions_unmodified=True, native_guest_functions_replaced=0, hooks_observe_only=True,
                  core_modified=False, managed_recovered_code_executed=False,
                  supplied_runtime_boundaries=dict(reader_metadata_flag='0x3A350D9=1', override_metadata_flag='0x3A36B27=1',
                      object_storage='Supplied reader and open MemoryStream field storage; instance constructors not invoked',
                      class_vtable='Supplied class pointer and slot19 pair; original runtime class initialization not executed',
                      method_info='Supplied opaque companion pointer observed unchanged at both override entries; override body does not dereference it',
                      arrays='Supplied IL2CPP header, length, payload and sentinel bytes; valid non-null positions, including EOF/beyond-length'),
                  scope=('Executes the original reader entry through both native virtual calls and header-field stores, stopping before the '
                         'extended-length branch at0x4A0E00. Both complete original MemoryStream.ReadByte return paths run, including EOF. '
                         'Exact slot loads, receiver/MethodInfo arguments, return bits, post-position, ordered heap writes, other object/array/class '
                         'storage and original code hashes are checked. This is bounded native evidence; it does not validate recovered CIL dispatch, '
                         'entire frame parsing, dynamic class/metadata initialization, null/closed/error paths, concurrency or full source portability.'))
    output = destination(ROOT, ROOT / 'reports/native-virtual-stream-prefix-v36.json')
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'cases', 'checks', 'failures', 'original_native_virtual_calls', 'eof_returns')}))


if __name__ == '__main__':
    main()
