"""Audit scoped runtime address parity and all three synthetic-source emission sites."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


gate_path = ROOT / 'reports/indirect-return-helper-v32.json'
gate = json.loads(gate_path.read_text())
negative_path = ROOT / 'reports/indirect-return-helper-v32-production-shape-failure.json'
negative = json.loads(negative_path.read_text())
source_path = ROOT / 'refs/Cpp2IL/Cpp2IL.Core/InstructionSets/NewArmV8InstructionSet.cs'
lock_path = ROOT / 'reports/cpp2il-hfa-experimental-lock.json'
lock = json.loads(lock_path.read_text())
patch_path = ROOT / lock['patch']
if digest(patch_path) != 'effbf13b420f98e3687780b7c0e78b39cfd3420068ca8802c1208be6ab92991a':
    raise ValueError('Expected immutable v32 experimental patch is no longer at this path')
relative_source = 'Cpp2IL.Core/InstructionSets/NewArmV8InstructionSet.cs'
before = subprocess.check_output(['git', '-C', str(ROOT / 'refs/Cpp2IL'), 'show', f'{lock["commit"]}:{relative_source}']).decode('utf-8')
block = re.split(r'(?m)^diff --git ', patch_path.read_text(encoding='utf-8').split(f'diff --git a/{relative_source} b/{relative_source}\n', 1)[1], maxsplit=1)[0]
old_lines, patch_lines = before.splitlines(keepends=True), block.splitlines(keepends=True)
rebuilt, old_at, patch_at = [], 0, 0
while patch_at < len(patch_lines):
    match = re.match(r'^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@', patch_lines[patch_at])
    if not match:
        patch_at += 1
        continue
    hunk_start = int(match.group(1)) - 1
    rebuilt.extend(old_lines[old_at:hunk_start])
    old_at, patch_at = hunk_start, patch_at + 1
    while patch_at < len(patch_lines) and not patch_lines[patch_at].startswith('@@ '):
        line = patch_lines[patch_at]
        if line[:1] in (' ', '-'):
            if old_at >= len(old_lines) or old_lines[old_at] != line[1:]:
                raise ValueError('Pinned upstream source does not match patch hunk')
            old_at += 1
        if line[:1] in (' ', '+'):
            rebuilt.append(line[1:])
        elif not line.startswith('-') and not line.startswith('\\ No newline'):
            raise ValueError('Unexpected patch hunk line')
        patch_at += 1
rebuilt.extend(old_lines[old_at:])
source = ''.join(rebuilt)
expected_source_hash = next(row['sha256'] for row in lock['files'] if row['path'] == relative_source)
serializations = {'UTF8_LF': source.encode('utf-8'), 'UTF8_CRLF': source.replace('\n', '\r\n').encode('utf-8')}
matching_serializations = [name for name, data in serializations.items()
                           if hashlib.sha256(data).hexdigest() == expected_source_hash]
if len(matching_serializations) != 1:
    raise ValueError('Reconstructed converter source hash differs from v32 snapshot lock')
snapshot_source_serialization = matching_serializations[0]
snapshot_source_hash = hashlib.sha256(serializations[snapshot_source_serialization]).hexdigest()
helper_path = ROOT / 'refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64IndirectReturns.cs'
helper = helper_path.read_text(encoding='utf-8-sig')
source_block = source.split('// Add return if the function', 1)[1].split('// fix branches', 1)[0]
flat = re.sub(r'\s+', ' ', source_block)
checks = []


def check(name, condition):
    checks.append(dict(name=name, passed=bool(condition)))


check('actual production and all 23 adapter guard checks pass',
      gate['status'] == 'PASS_EXACT_NATIVE_INDIRECT_RETURN_ADAPTER_AND_ATOMIC_REJECTIONS'
      and gate['checks'] == 23 and gate['failures'] == 0)
production = next(row for row in gate['tests'] if row['name'] == 'actual production converter binds reviewed return buffer')
check('actual production result is the original SP8 storage', production['passed'] and production['details']['destination'] == 'stack[8]')
check('runtime acceptance retains the strict instruction/address count guard',
      'instructions.Count != nativeAddresses.Count' in helper
      and digest(helper_path) == gate['helper_source_sha256'])
check('compiled Core matches recorded runtime gate',
      digest(ROOT / 'src/re/IndirectReturnProbe/bin/Release/net10.0/Cpp2IL.Core.dll') == gate['tool_core_sha256'])
check('synthetic void return has a paired non-native sentinel',
      'if (context.IsVoid) { addresses.Add(ulong.MaxValue); instructions.Add(new Instruction(index, OpCode.Return)); }' in flat)
check('every synthetic HFA return copy has a paired non-native sentinel',
      'foreach (var copy in LegacyArm64Hfa.Copies(LegacyArm64Hfa.ReturnBinding(context), true)) { addresses.Add(ulong.MaxValue); instructions.Add(new Instruction(instructions.Count, OpCode.Move, copy.Destination, copy.Source)); }' in flat)
check('synthetic nonvoid return has a paired non-native sentinel',
      '} addresses.Add(ulong.MaxValue); instructions.Add(new Instruction(instructions.Count, OpCode.Return, CallingConventions.ReturnRegister(context)));' in flat)
check('all fallback instruction emission sites accounted for',
      source_block.count('instructions.Add(') == 3 and source_block.count('addresses.Add(ulong.MaxValue)') == 3)
check('pre-fix negative production result remains preserved',
      negative['status'] == 'FAIL_INDIRECT_RETURN_ADAPTER_GUARDS'
      and any(not row['passed'] and row['name'] == production['name'] for row in negative['tests']))
passed = all(row['passed'] for row in checks)
report = dict(status='PASS_SCOPED_RUNTIME_PARITY_AND_SOURCE_SYNTHETIC_PAIR_AUDIT' if passed else 'FAIL_SYNTHETIC_PAIR_AUDIT',
    checks=len(checks), failures=sum(not row['passed'] for row in checks), tests=checks,
    helper_gate_sha256=digest(gate_path), preserved_negative_gate_sha256=digest(negative_path),
    converter_source_sha256=snapshot_source_hash, converter_source_origin='reconstructed from pinned upstream plus exact v32 experimental patch',
    converter_source_serialization=snapshot_source_serialization,
    v32_patch_sha256=digest(patch_path), v32_lock_sha256=digest(lock_path), helper_source_sha256=digest(helper_path),
    tool_core_sha256=gate['tool_core_sha256'], probe_source_sha256=digest(Path(__file__)),
    runtime_production_instruction_count=production['details']['production_instructions'],
    runtime_native_address_count_directly_observed=False,
    runtime_equal_address_count_proved_by_unchanged_strict_guard=production['passed'],
    native_source_span_bytes=production['details']['source_byte_length'], exact_caller_fde_bytes=552,
    native_last_decoded_rva=production['details']['last_native_rva'], native_last_decoded_operation=production['details']['last_native_operation'],
    synthetic_addresses_are_original_native_addresses=False, game_executed=False,
    scope='Actual SetStage production adapter acceptance proves list/address parity through the unchanged strict count guard; the address-list count was not separately exposed or measured. The source audit covers void fallback, each HFA return copy, and nonvoid fallback emission sites using non-native ulong.MaxValue sentinels. HFA/nonvoid fallback paths are statically audited here, not claimed as dynamically exercised. Original FDE is552bytes, while the metadata-neighbor source span560bytes includes trailing UDF padding that triggers the void fallback. No helper guard was relaxed, no game method executed and no source/runtime/game completion is certified.')
destination(ROOT, ROOT / 'reports/indirect-return-synthetic-parity-v32.json').write_text(json.dumps(report, indent=2) + '\n')
print(f'Synthetic parity audit: {len(checks) - report["failures"]}/{len(checks)} checks')
if not passed:
    raise SystemExit(1)
