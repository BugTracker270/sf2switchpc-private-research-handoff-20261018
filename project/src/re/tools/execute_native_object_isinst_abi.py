"""Unchanged Object::IsInst wrapper at a supplied assignability boundary only."""
import hashlib
import json
from pathlib import Path
import struct

from execute_native_ai_leaves import NativeScope, FUNCTIONS, ROOT, HEAP, STACK, STOP
from usb_boundary import destination
from unicorn import arm64_const as reg

START, END = 0xB5B390, 0xB5B484
BOUNDARY = 0xB05920
BODY_SHA = '1b265abeee0dfb0991ffe2b237b6cf3f817a9a5071eb8787a2dc28b87d9cbec6'
IMAGE_SHA = 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968'


class Scope(NativeScope):
    def __init__(self):
        self.observed = []
        self.supplied_result = 0
        self.clobber = 0
        super().__init__()

    def block(self, vm, address, size, context):
        if address == BOUNDARY:
            self.observed.append(dict(target=vm.reg_read(reg.UC_ARM64_REG_X0),
                                      object_class=vm.reg_read(reg.UC_ARM64_REG_X1),
                                      return_address=vm.reg_read(reg.UC_ARM64_REG_X30)))
            # Explicitly authored runtime boundary: original assignability and
            # its metadata/COM/error effects do not execute in this experiment.
            for index in range(1, 18):
                vm.reg_write(getattr(reg, f'UC_ARM64_REG_X{index}'), self.clobber ^ index)
            for index in range(8):
                vm.reg_write(getattr(reg, f'UC_ARM64_REG_Q{index}'), (self.clobber << 64) | index)
            vm.reg_write(reg.UC_ARM64_REG_X0, self.supplied_result)
            vm.reg_write(reg.UC_ARM64_REG_PC, vm.reg_read(reg.UC_ARM64_REG_X30))
            return
        return super().block(vm, address, size, context)


def main():
    FUNCTIONS.clear()
    FUNCTIONS.update(object_isinst=(START, END))
    scope = Scope()
    if hashlib.sha256(scope.raw).hexdigest() != IMAGE_SHA:
        raise ValueError('Original native input changed')
    original = bytes(scope.vm.mem_read(START, END - START))
    if hashlib.sha256(original).hexdigest() != BODY_SHA:
        raise ValueError('Exact original 244-byte helper changed')
    obj, obj_class = HEAP + 0x1000, HEAP + 0x3000
    targets = (HEAP + 0x5000, HEAP + 0x7000)
    frame_sp = STACK + 0x80000
    saved = (0xA1A2A3A4A5A6A7A8, 0xB1B2B3B4B5B6B7B8, 0xC1C2C3C4C5C6C7C8)
    preserved_regs = (reg.UC_ARM64_REG_X19, reg.UC_ARM64_REG_X20, reg.UC_ARM64_REG_X29)
    noises = (0, 0xDEADBEEF5A5AA5A5)
    cases = checks = null_cases = ordinary_cases = boundary_calls = 0
    rows = []

    def run(label, object_pointer, target, flags, result, noise):
        nonlocal cases, checks, null_cases, ordinary_cases, boundary_calls
        scope.vm.mem_write(obj, struct.pack('<Q', obj_class) + b'\xA5' * 0x38)
        state = bytearray(b'\xA5' * 0x200)
        state[0x122] = flags
        scope.vm.mem_write(obj_class, bytes(state))
        before = bytes(scope.vm.mem_read(obj, 0x40)) + bytes(scope.vm.mem_read(obj_class, 0x200))
        scope.observed.clear()
        scope.supplied_result = result
        scope.clobber = noise
        scope.vm.reg_write(reg.UC_ARM64_REG_X0, object_pointer)
        scope.vm.reg_write(reg.UC_ARM64_REG_X1, target)
        for index in range(2, 18):
            scope.vm.reg_write(getattr(reg, f'UC_ARM64_REG_X{index}'), noise ^ index)
        for index in range(8):
            scope.vm.reg_write(getattr(reg, f'UC_ARM64_REG_Q{index}'), (noise << 64) | index)
        for register, value in zip(preserved_regs, saved):
            scope.vm.reg_write(register, value)
        scope.vm.reg_write(reg.UC_ARM64_REG_SP, frame_sp)
        scope.vm.reg_write(reg.UC_ARM64_REG_X30, STOP)
        scope.vm.emu_start(START, STOP, count=200)
        expected_calls = [] if object_pointer == 0 else [dict(target=target, object_class=obj_class, return_address=0xB5B3C0)]
        expected_result = object_pointer if object_pointer != 0 and result == 1 else 0
        comparisons = dict(
            returned_original_object_or_null=scope.vm.reg_read(reg.UC_ARM64_REG_X0) == expected_result,
            original_return_reached=scope.vm.reg_read(reg.UC_ARM64_REG_PC) == STOP,
            stack_restored=scope.vm.reg_read(reg.UC_ARM64_REG_SP) == frame_sp,
            x19_restored=scope.vm.reg_read(preserved_regs[0]) == saved[0],
            x20_restored=scope.vm.reg_read(preserved_regs[1]) == saved[1],
            x29_restored=scope.vm.reg_read(preserved_regs[2]) == saved[2],
            original_object_class_bytes_unchanged=before == bytes(scope.vm.mem_read(obj, 0x40)) + bytes(scope.vm.mem_read(obj_class, 0x200)),
            runtime_boundary_arguments_and_order=scope.observed == expected_calls)
        if not all(comparisons.values()):
            raise AssertionError((label, comparisons, scope.observed))
        cases += 1
        checks += len(comparisons)
        boundary_calls += len(scope.observed)
        null_cases += int(object_pointer == 0)
        ordinary_cases += int(object_pointer != 0)
        rows.append(dict(case=label, input_object_null=object_pointer == 0, flag=flags,
                         supplied_assignability=result if object_pointer else None,
                         caller_saved_noise=f'0x{noise:X}', comparisons=comparisons,
                         observed_runtime_boundary_calls=scope.observed))

    # Null object must not consult even an invalid target class. These cases run
    # the complete original wrapper without entering any supplied boundary.
    for target in (0, 1, 0xDEADBEEF5A5AA5A5, *targets):
        for noise in noises:
            run(f'null/{target:X}/{noise:X}', 0, target, 0, 0, noise)
    # Other flag bits deliberately vary; the import/WinRT bit remains clear.
    # Target/object classes are synthetic inputs. Compatibility is supplied,
    # never inferred from flags or implemented by a replacement type system.
    for flags in range(256):
        if flags & 4:
            continue
        for result in (0, 1):
            for target in targets:
                for noise in noises:
                    run(f'ordinary/{flags}/{result}/{target:X}/{noise:X}', obj, target, flags, result, noise)
    if bytes(scope.vm.mem_read(START, END - START)) != original:
        raise AssertionError('Original native code changed')
    if hashlib.sha256((ROOT / 'analysis/nso/main-uncompressed.nso').read_bytes()).hexdigest() != IMAGE_SHA:
        raise AssertionError('Original native source file changed')
    private = destination(ROOT, ROOT / 'analysis/reconstruction/object-isinst-abi-v40/native-cases.json')
    private.parent.mkdir(parents=True, exist_ok=True)
    private.write_text(json.dumps(rows, indent=2) + '\n', encoding='utf-8')
    report = dict(status='PASS_UNCHANGED_NATIVE_ISINST_WRAPPER_AT_EXPLICIT_ASSIGNABILITY_BOUNDARY',
        cases=cases, checks=checks, failures=0, null_object_cases_without_runtime_boundaries=null_cases,
        non_com_cases_with_supplied_assignability=ordinary_cases,
        ordinary_flag_patterns=128, synthetic_target_class_slots=2,
        supplied_boolean_results_per_fixture=2, caller_saved_noise_patterns=2,
        runtime_boundary_replacement_calls=boundary_calls,
        runtime_boundary=dict(address=hex(BOUNDARY), name='Class::IsAssignableFrom',
            contract='Observed original arguments X0 target class, X1 original object class; authored Boolean0/1 return. X1-X17 and V0-V7 are deliberately clobbered before returning to original caller.',
            results_supplied=True, original_implementation_executed=False),
        invalid_target_null_cases=6, input_x2_x17_and_v0_v7_varied=True,
        original_code_sha256=BODY_SHA, original_code_bytes=END - START, original_image_sha256=IMAGE_SHA,
        original_code_unmodified=True, source_file_unmodified=True,
        private_case_file_sha256=hashlib.sha256(private.read_bytes()).hexdigest(),
        proposal_report_sha256=hashlib.sha256((ROOT / 'reports/object-isinst-native-source-proposal-v40.json').read_bytes()).hexdigest(),
        probe_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        actual_assignability_executed=False, com_winrt_executed=False, native_errors_or_cleanup_executed=False,
        real_host_com_or_game_process_used=False, recovered_game_methods_invoked=0, core_modified=False,
        helper_semantics_recovered=False, full_clean_decompile_ready=False,
        scope='Complete unchanged244-byte Object::IsInst wrapper executes its null and ordinary non-COM paths in Unicorn guest memory. Null cases invoke no runtime replacement and include invalid target pointers. Ordinary cases explicitly supply Class::IsAssignableFrom Boolean results and observe exact reversed class arguments/order, object-or-null identity and frame preservation under varied extra inputs and caller-saved clobbers. Synthetic object/class memory is supplied. Original assignability, its metadata effects, imported COM/WinRT/QueryInterface/Release/assertion paths, real failure/unwinding and original game callers do not execute and are not claimed.')
    destination(ROOT, ROOT / 'reports/native-object-isinst-abi-v40.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key:report[key] for key in ('status','cases','checks','null_object_cases_without_runtime_boundaries','runtime_boundary_replacement_calls')}))


if __name__ == '__main__':
    main()
