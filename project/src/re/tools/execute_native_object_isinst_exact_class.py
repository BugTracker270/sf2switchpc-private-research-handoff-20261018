"""Original native exact-class subpath; no assignability replacement or Core edit.

Synthetic object/class storage establishes equality as a precondition. This does
not establish that any recovered caller satisfies it or implement a type system.
"""
import hashlib
import json
from pathlib import Path
import struct

from execute_native_ai_leaves import NativeScope, FUNCTIONS, ROOT, HEAP, STACK, STOP
from native_unwind_inventory import Image, fde
from usb_boundary import destination
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as reg

OBJECT = (0xB5B390, 0xB5B484)
ASSIGN = (0xB05920, 0xB05B7C)
IMAGE_SHA = 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968'
BODY_HASHES = {
    'object_isinst': '1b265abeee0dfb0991ffe2b237b6cf3f817a9a5071eb8787a2dc28b87d9cbec6',
    'class_assignable': '3cb95ce5d103a953c4db8d1a01c03eb5e0ca56c7162b58853ce0cc133d655d2e',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RejectedBoundary(RuntimeError):
    pass


class Scope(NativeScope):
    def __init__(self):
        self.entries = []
        self.reads = []
        self.writes = []
        self.boundaries = []
        super().__init__()
        self.vm.hook_add(UC_HOOK_MEM_READ, self.read)
        self.vm.hook_add(UC_HOOK_MEM_WRITE, self.write)

    def block(self, vm, address, size, context):
        if address in (0xB04F60, 0xB05B80):
            self.boundaries.append(address)
            raise RejectedBoundary(f'Unreviewed path stopped before {address:#x}')
        if address == ASSIGN[0]:
            self.entries.append({'target': vm.reg_read(reg.UC_ARM64_REG_X0),
                                 'object_class': vm.reg_read(reg.UC_ARM64_REG_X1),
                                 'return_address': vm.reg_read(reg.UC_ARM64_REG_X30)})
        return super().block(vm, address, size, context)

    def read(self, vm, access, address, size, value, context):
        if not STACK <= address < STACK + 0x100000:
            self.reads.append((address, size))

    def write(self, vm, access, address, size, value, context):
        if not STACK <= address < STACK + 0x100000:
            self.writes.append((address, size))

    def reset(self, x0, x1, noise):
        self.entries.clear()
        self.reads.clear()
        self.writes.clear()
        self.boundaries.clear()
        self.visited.clear()
        self.vm.reg_write(reg.UC_ARM64_REG_X0, x0)
        self.vm.reg_write(reg.UC_ARM64_REG_X1, x1)
        for index in range(2, 18):
            self.vm.reg_write(getattr(reg, f'UC_ARM64_REG_X{index}'), noise ^ index)
        for index in range(8):
            self.vm.reg_write(getattr(reg, f'UC_ARM64_REG_Q{index}'), (noise << 64) | index)
        saved = {index: noise ^ (index << 16) for index in (19, 20, 21, 29)}
        for index, value in saved.items():
            self.vm.reg_write(getattr(reg, f'UC_ARM64_REG_X{index}'), value)
        self.vm.reg_write(reg.UC_ARM64_REG_SP, STACK + 0x80000)
        self.vm.reg_write(reg.UC_ARM64_REG_X30, STOP)
        return saved


def main():
    FUNCTIONS.clear()
    FUNCTIONS.update(object_isinst=OBJECT, class_assignable=ASSIGN)
    scope = Scope()
    if hashlib.sha256(scope.raw).hexdigest() != IMAGE_SHA:
        raise ValueError('Original image differs')
    image = Image(scope.raw)
    inventory_path = ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl'
    inventory = json.loads((ROOT / 'reports/native-unwind-inventory.json').read_text(encoding='utf-8-sig'))
    if digest(inventory_path) != inventory['frames_file_sha256']:
        raise ValueError('Original frame inventory changed')
    frames = {}
    for line in inventory_path.read_text(encoding='utf-8').splitlines():
        row = json.loads(line)
        if row['rva'] in (OBJECT[0], ASSIGN[0]):
            frames[row['rva']] = row
    cache = {}
    for name, (start, end) in FUNCTIONS.items():
        row = frames[start]
        decoded = fde(image, row['fde_rva'], start, inventory['frame_start'],
                      image.segments[1][1] + image.segments[1][2], cache)
        if decoded != row or row['end_rva'] != end:
            raise ValueError('Original FDE bounds changed')
        if hashlib.sha256(image.read(start, end - start)).hexdigest() != BODY_HASHES[name]:
            raise ValueError('Original native body changed')

    rows = []
    checks = 0

    def check_run(kind, start, x0, x1, expected, noise, reads, entries):
        nonlocal checks
        saved = scope.reset(x0, x1, noise)
        scope.vm.emu_start(start, STOP, count=200)
        comparisons = {
            'returned_expected_identity_or_boolean': scope.vm.reg_read(reg.UC_ARM64_REG_X0) == expected,
            'returned_to_original_caller': scope.vm.reg_read(reg.UC_ARM64_REG_PC) == STOP,
            'stack_restored': scope.vm.reg_read(reg.UC_ARM64_REG_SP) == STACK + 0x80000,
            'callee_saved_preserved': all(scope.vm.reg_read(getattr(reg, f'UC_ARM64_REG_X{i}')) == v for i, v in saved.items()),
            'only_exact_expected_data_reads': scope.reads == reads,
            'no_nonstack_writes': not scope.writes,
            'original_assignability_call_inputs': scope.entries == entries,
            'no_other_runtime_boundary_entered': not scope.boundaries,
        }
        if not all(comparisons.values()):
            raise AssertionError((kind, comparisons, scope.reads, scope.entries))
        checks += len(comparisons)
        rows.append({'kind': kind, 'object_or_class': x0, 'target_class': x1,
                     'caller_noise': noise, 'comparisons': comparisons,
                     'original_data_reads': scope.reads, 'original_assignability_calls': scope.entries})

    obj = HEAP + 0x1000
    classes = (HEAP + 0x3000, HEAP + 0x5000)
    noises = (0, 0xDEADBEEF5A5AA5A5)
    flags = (0, 1, 2, 8, 0x40, 0x80, 0xFB)
    for klass in classes:
        for flag in flags:
            state = bytearray(b'\xA5' * 0x200)
            state[0x122] = flag
            scope.vm.mem_write(klass, bytes(state))
            scope.vm.mem_write(obj, struct.pack('<Q', klass) + b'\x5A' * 0x38)
            for noise in noises:
                check_run('ordinary_exact_class', OBJECT[0], obj, klass, obj, noise,
                          [(obj, 8), (klass + 0x122, 1)],
                          [{'target': klass, 'object_class': klass, 'return_address': 0xB5B3C0}])
    for target in (0, 1, 0xDEADBEEF5A5AA5A5):
        for noise in noises:
            check_run('null_object', OBJECT[0], 0, target, 0, noise, [], [])
    for klass in (*classes, 0xDEADBEEF5A5AA5A5):
        for noise in noises:
            check_run('direct_exact_class_no_class_reads', ASSIGN[0], klass, klass, 1, noise, [],
                      [{'target': klass, 'object_class': klass, 'return_address': STOP}])

    controls = []
    # These are rejection witnesses, never supplied runtime results. Stop at
    # the first instruction of the unreviewed Class::Init or import path.
    for label, flag, target, expected_boundary in (
            ('distinct_classes', 0, classes[1], 0xB04F60),
            ('import_flag_set', 4, classes[0], 0xB05B80)):
        scope.vm.mem_write(classes[0] + 0x122, bytes([flag]))
        scope.vm.mem_write(obj, struct.pack('<Q', classes[0]))
        scope.reset(obj, target, 0)
        try:
            scope.vm.emu_start(OBJECT[0], STOP, count=200)
        except RejectedBoundary:
            if scope.boundaries != [expected_boundary]:
                raise AssertionError('Control stopped at another boundary')
            controls.append({'kind': label, 'stopped_before': hex(expected_boundary),
                             'runtime_result_supplied': False, 'completed': False})
        else:
            raise AssertionError('Rejected control unexpectedly returned')
    for name, (start, end) in FUNCTIONS.items():
        if hashlib.sha256(scope.vm.mem_read(start, end - start)).hexdigest() != BODY_HASHES[name]:
            raise AssertionError('Original native text mutated')
    if digest(ROOT / 'analysis/nso/main-uncompressed.nso') != IMAGE_SHA:
        raise AssertionError('Original input file mutated')
    private = destination(ROOT, ROOT / 'analysis/reconstruction/object-isinst-exact-class/native-cases.json')
    private.parent.mkdir(parents=True, exist_ok=True)
    private.write_text(json.dumps(rows, indent=2) + '\n', encoding='utf-8')
    report = {
        'status': 'PASS_ORIGINAL_ORDINARY_EXACT_CLASS_SUBPATH_NO_REPLACEMENTS',
        'cases': len(rows), 'checks': checks, 'failures': 0,
        'ordinary_wrapper_cases': sum(r['kind'] == 'ordinary_exact_class' for r in rows),
        'null_object_cases': sum(r['kind'] == 'null_object' for r in rows),
        'direct_assignability_cases': sum(r['kind'] == 'direct_exact_class_no_class_reads' for r in rows),
        'rejected_controls': controls, 'runtime_replacement_calls': 0,
        'native_original_assignability_executed': True,
        'metadata_init_executed': False, 'com_winrt_executed': False,
        'original_body_sha256': BODY_HASHES, 'original_image_sha256': IMAGE_SHA,
        'exact_frame_ranges': {n: [hex(s), hex(e)] for n, (s, e) in FUNCTIONS.items()},
        'original_code_unmodified': True, 'original_input_unmodified': True,
        'private_cases': str(private.relative_to(ROOT)), 'private_cases_sha256': digest(private),
        'source_sha256': digest(Path(__file__)), 'core_modified': False,
        'caller_class_identity_proved': False, 'semantic_lowering_implemented': False,
        'general_assignability_recovered': False, 'full_clean_decompile_ready': False,
        'scope': 'The original ordinary Object::IsInst wrapper calls original Class::IsAssignableFrom with identical synthetic class pointers. The wrapper reads the object class and its ordinary/import flag; exact-class assignability itself reads no class storage and skips Class::Init. Exact nonstack reads and absence of nonstack writes are observed. Null objects and direct equal-pointer assignability are separate cases. Mismatched classes and import-flag fixtures stop before unreviewed runtime boundaries. No function or return replacement, general assignability, COM behavior, caller proof, recovered CIL execution or production semantic lowering. The shared guest loader presets seven unrelated initialization guard bytes; read tracing proves none is read by these subpaths.',
    }
    destination(ROOT, ROOT / 'reports/native-object-isinst-exact-class.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('status', 'cases', 'checks', 'runtime_replacement_calls')}))


if __name__ == '__main__':
    main()
