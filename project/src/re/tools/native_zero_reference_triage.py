"""Distinguish invalid array casts from proven native nulls without altering recovery."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination
from v30_diagnostic_delta import read

RUN = 'nso-plain-frame-cfg-v35'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest_path = ROOT / f'reports/recovered-source-profile-project-build-{RUN}.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    assemblies = {}
    for assembly in ('Assembly-CSharp-firstpass', 'Assembly-CSharp'):
        diagnostics = read(RUN, assembly)
        candidates = [row for row in diagnostics if row['code'] == 'CS0030'
                      and re.fullmatch(r"Cannot convert type 'int' to '.*\[\]'", row['message'])]
        records = next(row['source_files'] for row in manifest['assemblies'] if row['assembly'] == assembly)
        base = ROOT / f'analysis/il2cpp/source-profile-project-build-{RUN}/{assembly}'
        indexed = {(ROOT / row['path']).relative_to(base).as_posix(): row for row in records}
        texts = {}
        for file in {row['file'] for row in candidates}:
            payload = (base / file).read_bytes()
            if len(payload) != indexed[file]['bytes'] or hashlib.sha256(payload).hexdigest() != indexed[file]['sha256']:
                raise ValueError('Original source changed')
            texts[file] = payload.decode('utf-8-sig').splitlines()
        categories = Counter()
        samples = []
        for row in candidates:
            lines = texts[row['file']]
            line = lines[row['line'] - 1]
            literal_zero = bool(re.search(r'\([^()\n]+\[\]\)\s*0\b', line))
            nearby_fallback = any('NoteDecompilerIssue("Unmanaged memory load:' in text
                                  for text in lines[max(0, row['line'] - 5):row['line']])
            category = ('literal_zero_near_unmanaged_load_diagnostic' if nearby_fallback
                        else 'literal_zero_requires_independent_CIL_and_native_proof') if literal_zero else 'nonzero_or_variable_array_cast_not_a_null_literal'
            categories[category] += 1
            if literal_zero and len(samples) < 12:
                samples.append(dict(file=row['file'], line=row['line'], category=category,
                                    source_sha256=indexed[row['file']]['sha256']))
        assemblies[assembly] = dict(canonical_all_diagnostics=len(diagnostics),
                                    exact_int_to_array_diagnostics=len(candidates), categories=dict(categories),
                                    candidate_source_files_hash_verified=len(texts), samples=samples)
    native_path = ROOT / 'analysis/nso/main-uncompressed.nso'
    native = native_path.read_bytes()
    if hashlib.sha256(native).hexdigest() != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original native binary differs')
    address = 0x4A0DB4
    words = struct.unpack_from('<IIIII', native, 0x100 + address)
    if words != (0xF9400288, 0xF9412D09, 0xF9413101, 0xAA1403E0, 0xD63F0120):
        raise ValueError('Original virtual slot read/call sequence differs')
    cil_path = ROOT / 'reports/recovered-reference-zero-triage-v36.json'
    cil = json.loads(cil_path.read_text())
    if cil['status'] != 'PASS_ACTUAL_ARRAY_ZERO_DIAGNOSTIC_FALLBACK_CORRELATION' or cil['checks'] < 4 or not any(row['original_slot_0x260'] for row in cil['witnesses']):
        raise ValueError('Actual unchanged CIL fallback correlation is missing')
    if cil['assembly_sha256'] != sha(ROOT / f'analysis/il2cpp/cpp2il-recovery-{RUN}/Assembly-CSharp-firstpass.dll'):
        raise ValueError('CIL report does not bind the current recovered DLL')
    emitter_path = ROOT / 'refs/Cpp2IL/Cpp2IL.Core/IlGenerator.cs'
    emitter = emitter_path.read_text(encoding='utf-8-sig')
    if 'expectedType is { IsValueType: false } && IsZeroConstant(operand)' not in emitter or 'operand is Immediate { Value: 0 }' not in emitter:
        raise ValueError('Existing exact zero/reference emission contract changed')
    report = dict(status='READ_ONLY_ARRAY_ZERO_TRIAGE_REJECTS_UNPROVEN_NULL_SUBSTITUTION',
                  recovery_run=RUN, assemblies=assemblies, source_modified=False, core_modified=False,
                  source_manifest_sha256=sha(manifest_path), emitter_sha256=sha(emitter_path),
                  existing_emitter=dict(file='refs/Cpp2IL/Cpp2IL.Core/IlGenerator.cs',
                                       exact_immediate_zero_with_reference_expected_type_already_emits_ldnull=True,
                                       typed_move_field_array_call_return_paths_supply_expected_type=True,
                                       unmanaged_memory_fallback_emits_diagnostic_then_ldc_i4_zero_conv_i=True),
                  selected_native=dict(method='BestHTTP.WebSocket.Frames.WebSocketFrameReader::Read',
                                       registered_rva='0x4A0D70', native_window_start=hex(address),
                                       native_window_sha256=hashlib.sha256(native[0x100 + address:0x100 + address + 20]).hexdigest(),
                                       class_load='LDR X8,[X20]', function_slot='LDR X9,[X8,#0x258]',
                                       companion_slot='LDR X1,[X8,#0x260]', receiver='MOV X0,X20', dispatch='BLR X9',
                                       literal_zero_instruction_in_window=False,
                                       metadata_slot_correlation='System.IO.Stream.ReadByte is virtual slot19; legacy vtable base0x128 yields0x258. The companion+8 read is consistent with the hidden MethodInfo pointer, not a proven null.'),
                  actual_cil=dict(report=str(cil_path.relative_to(ROOT)), sha256=sha(cil_path),
                                  checks=cil['checks'], array_fallbacks=len(cil['witnesses']),
                                  native_null_proven=False, game_methods_invoked=0),
                  proposal='Do not change these unmanaged-load diagnostic placeholders to ldnull. First prove the original virtual receiver/slot pair and preserve runtime dispatch; unknown loads must remain explicit failures. No scalar-zero-to-struct or Enumerator initialization is classified as a null reference.',
                  full_clean_decompile_ready=False, whole_game_source_ready=False, portable_game_ready=False,
                  limits='Array diagnostics provide certain reference-type targets. Nearby-source classifications are correlations only; the selected original native and unchanged CIL sequence is separately verified. No claim that all remaining reference casts share this cause, and no original method execution or null-emission correction is claimed.')
    destination(ROOT, ROOT / 'reports/native-zero-reference-triage-v36.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], assemblies=assemblies, actual_cil=report['actual_cil'])))


if __name__ == '__main__':
    main()
