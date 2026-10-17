"""Local design evidence only: exact Byte[] layout-init/allocation adjacency.

This does not load/build Core, rewrite IR/CIL, run the game, or implement a
replacement for Class::Init. Official common runtime source stays ignored/local.
"""
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import subprocess
import sys

import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination
from native_unwind_inventory import Image, cie, record

PRIVATE = ROOT / 'analysis/reference/byte-array-layout-fusion-v40'
ORIGINAL_SHA = 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968'
READER_SHA = 'cfec6671b5b9a8788367f6b7a7b36378b9ea88bdeea69a33ab38bc3ed2a7a9b5'
LAYOUT_SHA = '496575374643a8ca7a9f1181d685de0fa4ac68574a3cc50c315d52d74a4d7dd3'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8-sig'))


def fact(path):
    return dict(path=path.relative_to(ROOT).as_posix(), bytes=path.stat().st_size,
                sha256=digest(path))


def extract_source():
    provenance_path = ROOT / 'reports/unity-2018.1.9f1-archive-provenance.json'
    provenance = read_json(provenance_path.relative_to(ROOT))
    archive = ROOT / provenance['archive_path']
    if (provenance['source_revision'] if 'source_revision' in provenance else provenance['revision']) != '24bbd83e8b9e':
        raise ValueError('Wrong official revision')
    if (provenance['status'] != 'PASS_OFFICIAL_ARCHIVE_MD5_WITH_RECORDED_API_SIZE_DELTA'
            or provenance['local_sha256'] != 'ce666b2de60716cb5564b53317b56f0b82eddbea7afb3462ef51d5e121833c96'
            or digest(archive) != provenance['local_sha256']):
        raise ValueError('Verified local official archive changed')
    seven_zip = Path('C:/Program Files/7-Zip/7z.exe')
    expected_tool = read_json('reports/unity-2018.1.9f1-common-runtime-source.json')['seven_zip_sha256']
    if digest(seven_zip) != expected_tool:
        raise ValueError('Previously reviewed installed 7-Zip changed')
    listing = (ROOT / 'logs/unity-2018.1.9f1-archive-list.log').read_text(encoding='utf-8-sig')
    members = {line[7:] for line in listing.splitlines() if line.startswith('Path = ')}
    extracted, logs = [], []
    for name in ('Array.cpp', 'Array.h'):
        member = 'Editor\\Data\\il2cpp\\libil2cpp\\vm\\' + name
        if member not in members:
            raise ValueError('Exact archive member missing: ' + member)
        relative = PureWindowsPath(member)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unsafe selected member')
        output = destination(ROOT, PRIVATE / 'runtime-source' / name)
        output.parent.mkdir(parents=True, exist_ok=True)
        # Extract to stdout. Never execute installer or let archive paths select
        # destinations. Repeated runs must retain the same extracted bytes.
        result = subprocess.run([str(seven_zip), 'x', str(archive), '-so', member],
                                capture_output=True, timeout=120)
        logs.append(dict(member=member, exit_code=result.returncode,
                         stderr=result.stderr.decode('utf-8', errors='replace')))
        if result.returncode != 0 or not result.stdout:
            raise RuntimeError('Selected extraction failed')
        if output.exists():
            if output.read_bytes() != result.stdout:
                raise ValueError('Preserve changed existing source: ' + str(output))
        else:
            output.write_bytes(result.stdout)
        extracted.append(fact(output))
    destination(ROOT, PRIVATE / 'extraction.json').write_text(json.dumps(dict(
        archive=fact(archive), provenance=fact(provenance_path), seven_zip_sha256=expected_tool,
        files=extracted, logs=logs, installer_executed=False, installed=False), indent=2) + '\n')
    return extracted


def main():
    extracted = extract_source()
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    if digest(source) != ORIGINAL_SHA:
        raise ValueError('Original native image changed')
    image = Image(source.read_bytes())
    reader = image.read(0x4A0D70, 956)
    if hashlib.sha256(reader).hexdigest() != READER_SHA:
        raise ValueError('Original reader differs')
    if hashlib.sha256(image.read(0xB04F60, 140)).hexdigest() != LAYOUT_SHA:
        raise ValueError('Original layout helper differs')
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    instructions = list(decoder.disasm(reader, 0x4A0D70))
    if len(instructions) * 4 != len(reader):
        raise ValueError('Reader decoding incomplete')
    windows = []
    for i, insn in enumerate(instructions):
        if insn.mnemonic != 'bl' or insn.op_str.lower() != '#0xb04f60':
            continue
        next_call = next((j for j in range(i + 1, min(i + 8, len(instructions)))
                          if instructions[j].mnemonic in ('bl', 'blr')), None)
        if next_call is None:
            raise ValueError('No bounded following allocation call')
        rows = [dict(rva=hex(row.address), mnemonic=row.mnemonic, operands=row.op_str)
                for row in instructions[max(0, i - 3):next_call + 2]]
        windows.append(dict(layout_call_rva=hex(insn.address),
                            next_call_rva=hex(instructions[next_call].address),
                            next_call_target=instructions[next_call].op_str,
                            intervening=[dict(rva=hex(row.address), mnemonic=row.mnemonic,
                                              operands=row.op_str) for row in instructions[i + 1:next_call]],
                            private_instructions=rows))
    if len(windows) != 4 or len({row['next_call_target'] for row in windows}) != 1:
        raise ValueError('Expected four same-allocation-target windows')
    allocation = int(windows[0]['next_call_target'].removeprefix('#'), 0)
    frames = {}
    for line in (ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl').read_text().splitlines():
        row = json.loads(line)
        if row['rva'] in (allocation, 0xB04F60, 0x4A0D70):
            frames[row['rva']] = row
    if allocation not in frames:
        raise ValueError('Allocation target has no exact original FDE')
    frame = frames[allocation]
    unwind = {}
    for address, scope_frame in frames.items():
        at = scope_frame['fde_rva']
        _, region_start, region_length = next(segment for segment in image.segments
            if segment[1] <= at < segment[1] + segment[2])
        region_end = region_start + region_length
        context = cie(image, scope_frame['cie_rva'], region_start, region_end)
        cursor, end = record(image, at, region_start, region_end)
        link_at = cursor.position
        if link_at - cursor.number('I') != scope_frame['cie_rva']:
            raise ValueError('CIE backlink changed')
        start = cursor.encoded(context['pointer_encoding'])
        size = cursor.encoded(context['pointer_encoding'] & 15)
        if (start, start + size, end) != (address, scope_frame['end_rva'], scope_frame['fde_end_rva']):
            raise ValueError('Exact FDE range changed')
        augment_size = cursor.leb() if context['augmentation'].startswith('z') else None
        if augment_size is not None:
            cursor.take(augment_size)
        unwind[hex(address)] = dict(frame=scope_frame, augmentation=context['augmentation'],
            fde_augmentation_bytes=augment_size, lsda_encoding=context['lsda_encoding'],
            personality=context['personality'],
            plain_no_lsda=context['augmentation'] == 'zR' and augment_size == 0
                and context['lsda_encoding'] == 255 and context['personality'] is None)
    allocation_body = image.read(allocation, frame['end_rva'] - allocation)
    allocation_instructions = [dict(rva=hex(row.address), mnemonic=row.mnemonic, operands=row.op_str)
                               for row in decoder.disasm(allocation_body, allocation)]
    body_report = dict(status='PRIVATE_DESIGN_ONLY_ORIGINAL_NATIVE_AND_COMMON_SOURCE_INVENTORY',
        original_image_sha256=ORIGINAL_SHA, reader_sha256=READER_SHA, reader_bytes=len(reader),
        layout_helper_sha256=LAYOUT_SHA, reader_frame=frames.get(0x4A0D70), unwind=unwind, windows=windows,
        allocation=dict(rva=hex(allocation), end=hex(frame['end_rva']), bytes=len(allocation_body),
                        sha256=hashlib.sha256(allocation_body).hexdigest(), frame=frame,
                        instructions=allocation_instructions), extracted_source=extracted,
        native_executed=False, game_executed=False, core_edited=False, core_built=False)
    private_path = destination(ROOT, PRIVATE / 'native-and-source-inventory.json')
    private_path.write_text(json.dumps(body_report, indent=2) + '\n', encoding='utf-8')
    write_design(body_report, private_path)
    print(json.dumps(dict(status=body_report['status'], windows=len(windows),
                         allocation={key:body_report['allocation'][key] for key in ('rva','bytes','sha256')},
                         extracted_source=extracted, report=fact(private_path))))


def write_design(native, private_path):
    """Record observed evidence separately from unimplemented proof obligations."""
    array_path = PRIVATE / 'runtime-source/Array.cpp'
    array_source = array_path.read_text(encoding='utf-8-sig')
    specific = array_source.split('Il2CppArray* Array::NewSpecific(', 1)[1].split('Il2CppArray* Array::NewFull(', 1)[0]
    common_root = ROOT / 'tools/unity-2018.1.9f1/common-runtime-source/Editor/Data/il2cpp/libil2cpp'
    class_source = (common_root / 'vm/Class.cpp').read_text(encoding='utf-8-sig')
    class_init = class_source.split('bool Class::Init(Il2CppClass *klass)', 1)[1].split('Il2CppClass* Class::FromName', 1)[0]
    legacy = read_json('reports/class-layout-translation-contract-v37.json')
    metadata = read_json('reports/scalar-boxing-metadata-v30.json')
    byte, = [item for item in metadata['primitives'] if item['type'] == 'System.Byte']
    previous_array = read_json('reports/native-array-boundary.json')
    stage_path = ROOT / 'analysis/il2cpp/virtual-stream-stage-after-type-v36.txt'
    stage = stage_path.read_text(encoding='utf-8-sig')
    current_source = ROOT / 'analysis/il2cpp/source-profile-project-build-nso-virtual-companion-copy-v38/Assembly-CSharp-firstpass/BestHTTP/WebSocket/Frames/WebSocketFrameReader.cs'
    text = current_source.read_text(encoding='utf-8-sig')
    current_read = text.split('internal void Read(Stream stream)', 1)[1].split('internal void Assemble(', 1)[0]
    windows = native['windows']
    checks = []
    def check(name, ok):
        checks.append(dict(name=name, passed=bool(ok)))
        if not ok:
            raise ValueError(name)
    check('exact source NewSpecific invokes Class::Init before any size or allocator work',
          specific.index('Class::Init(klass);') < specific.index('if (n > IL2CPP_ARRAY_MAX_INDEX)') < specific.index('il2cpp_array_element_size(klass)'))
    nested = [row for row in native['allocation']['instructions'] if row['mnemonic'] == 'bl']
    check('first original allocation call is exact B04F60 before rank/length guards',
          nested[0]['rva'] == '0xb5fe68' and nested[0]['operands'] == '#0xb04f60')
    check('native NewSpecific retains incoming class through original X0 to nested init',
          native['allocation']['instructions'][5] == dict(rva='0xb5fe64', mnemonic='mov', operands='x19, x0'))
    check('allocation body matches existing separately scoped native array witness',
          native['allocation']['sha256'] == previous_array['original_text_sha256']
          and previous_array['status'] == 'PASS_NATIVE_ARRAY_HEADER_AND_OVERFLOW_BOUNDARIES')
    check('exact caller and allocator frames are zR with empty augmentation and no LSDA/personality',
          native['unwind']['0x4a0d70']['plain_no_lsda'] and native['unwind']['0xb5fe50']['plain_no_lsda'])
    check('initialized Class::Init source fast path skips cold initialization',
          'if (!klass->initialized)' in class_init and 'InitLocked(klass, lock);' in class_init and 'return true;' in class_init)
    check('exact original Byte metadata has no managed static constructor',
          byte['value_type'] and byte['native_size'] == 1 and not byte['has_static_constructor']
          and metadata['metadata_sha256'] == 'f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85')
    check('previous host metadata witness remains unimplemented evidence only',
          legacy['managed_translation_implemented'] is False and legacy['production_ready'] is False)
    candidates = []
    for number, (window, ir_init, ir_alloc, result, expected_length, register) in enumerate(zip(
            windows, (67, 123, 182, 213), (70, 126, 185, 216), ('v84', 'v79', 'v133', 'v183'),
            (2, 8, 4, None), ('x21', 'x21', 'x21', 'x22'))):
        between = window['intervening']
        check(f'window{number} has only two original register operations', len(between) == 2)
        check(f'window{number} restores exactly same saved klass and overwrites unused Boolean result',
              window['private_instructions'][2]['operands'] == 'x0, ' + register
              and between[1]['mnemonic'] == 'mov' and between[1]['operands'] == 'x0, ' + register
              and not re.search(r'\bx0\b|\bw0\b', between[0]['operands']))
        if expected_length is not None:
            check(f'window{number} has exact nonthrowing constant length',
                  between[0]['mnemonic'] == 'mov' and between[0]['operands'] == f'w1, #{expected_length}')
        else:
            check('variable window preserves native low32 mask; not initial contract candidate',
                  between[0]['mnemonic'] == 'and' and between[0]['operands'] == 'x1, x21, #0xffffffff')
        # This text predates the ABI correction. It is historical corroboration,
        # never the current production provenance or semantic readiness gate.
        matching = [line for line in stage.splitlines() if re.match(rf'^{ir_init} Call B04F60, {result}\b', line)]
        check(f'historical stage{ir_init} declares exact observed result once and never consumes it',
              len(matching) == 1 and len(re.findall(rf'\b{result}\b', stage)) == 1)
        candidates.append(dict(native_init_call=window['layout_call_rva'], native_allocation_call=window['next_call_rva'],
            historical_ir_init_index=ir_init, historical_ir_allocation_index=ir_alloc,
            length_constant=expected_length, native_result_overwritten=True,
            historical_result_unused=True, proposed_initial_candidate=expected_length is not None,
            current_full_metadata_identity_and_ir_proof_implemented=False))
    check('current unchanged Read source still contains four explicit layout diagnostics and four byte allocations',
          current_read.count('Method not found @B04F60') == 4 and current_read.count('new byte[') == 4)
    guards = [
        'NSO metadata24 opt-in, exact reviewed loaded-image identity and original helper/allocator FDE hashes; never resolve by helper name alone.',
        'Use actual app-owned System.Byte metadata identity from original mscorlib, exact SZARRAY shape/rank1, element size1 and absent original array/element .cctor. FullName alone is insufficient.',
        'The layout call must retain its reviewed ABI carrier and exactly one valid non-null class operand; allocation must be the original B5FE50 call already destined for NewArr on the same exact class origin.',
        'Prove the Boolean result unused by every deep operand, Phi, return, address, exceptional successor and copy; do not materialize true, null or a default result.',
        'Start with length2/8/4 windows. Preserve original length operand and every allocation-result use; exclude variable/truncated/negative/large lengths until separate allocation-width and overflow proof.',
        'Require unique available class definitions and exact same captured native klass value. Reject different metadata identities, mutable reloads, unknown origins, duplicate definitions and escapes.',
        'Validate original local CFG and native call ordering, unique straight-line path and no interior incoming edge. Only the two observed nonthrowing register preparations may lie between calls.',
        'Require equivalent native exception landing-pad/action scope for both outer-init and allocation sites, or an exact proof that neither has a caller cleanup/action. Preserve unrelated throw branches and do not infer this from missing recovered CIL EH.',
        'Capture proof while SSA and original native-call identity exist, before SsaForm.Remove. Consume it only for the unchanged matching allocation after ArrayRecovery produces NewArr; late emission must reject stale owner/type/result/length/call identity.',
        'Only remove the duplicate outer metadata-init operation as part of the exact matched allocation. No standalone helper replacement, global call deletion, RunClassConstructor, synthetic success or diagnostic suppression.',
        'Preserve original allocation fault propagation and postallocation effects. Do not catch OutOfMemory/Overflow/TypeLoad failures, return an empty array, substitute cached arrays or merge two allocations.',
        'Keep initialized/cold class evidence, host runtime array contract and managed constructor behavior separately measured. Runtime metadata statistics/GC/profiler/native stack traces are platform boundaries, not claimed identical implementations.',
    ]
    negatives = [
        'live Boolean branch/return/copy/address result', 'different class at allocation', 'same name from different assembly or app',
        'non-Byte element', 'reference/custom/generic/cctor-bearing element', 'multidimensional/bounded/non-SZARRAY shape',
        'null/unknown/ambiguous class', 'class definition after use or duplicate', 'class Phi with unknown incoming path',
        'intervening call/store/volatile read/array access or throwing arithmetic', 'interior branch into pure preparation or allocation',
        'one-sided or missing CFG edge', 'different EH landing pad/action or missing EH evidence',
        'unknown allocator address or stale resolved-name alias', 'changed helper/allocator/image bytes or FDE',
        'variable/negative/oversized/truncated length in initial constant-only scope', 'stale type/length/result/owner after capture',
        'original managed class-init request adjacent to metadata helper', 'cold metadata failure must reach no allocator',
        'allocation failure must reach no later store/call', 'separate allocations must retain fresh identity',
        'constructor canary must remain untouched by byte-array allocation', 'unmatched standalone Class::Init remains diagnostic',
    ]
    blockers = [
        'No production fusion/proof carrier exists. The three constant sites are static candidates, not accepted recoveries or runtime coverage.',
        'Actual v38 metadata class identity, complete deep-use/availability and matching allocation identity must be checked in production SSA and revalidated at emission; historical v36 text is corroboration only.',
        'The exact reader and allocator are now independently proved plain zR/empty-FDE-augmentation/no-LSDA frames. A production proof must bind those exact facts; other EH-bearing callers remain rejected. The nested layout helper has real cleanup, retained conceptually inside the allocation composition.',
        'Existing 512-case layout witness covers initialized path only. Existing 582-case array witness supplies initialized class, allocator and exception boundaries. Neither executes actual cold InitLocked or native cleanup.',
        'The prior TypeHandle canary witness is metadata observation, not NewArr execution. A separate host typed-byte-array/constructor-negative/failure-order contract is required; no build or runtime was run for this design.',
        'Original native allocator/GC/OOM/profiler behavior is outside current executable parity. NewArr is a host-runtime abstraction with specified allocation failure, not a promise to reproduce native process assertions or C++ stack traces.',
    ]
    evidence_paths = [
        'reports/class-layout-translation-contract-v37.json', 'reports/class-layout-runtime-source-v37.json',
        'reports/clr-type-metadata-boundary-v37.json', 'reports/scalar-boxing-metadata-v30.json',
        'reports/native-array-boundary.json', 'reports/class-layout-overflow-abi-production-ir-v37.json',
        'reports/recovered-source-profile-legacy-reference-check-nso-virtual-companion-copy-v38.json',
        'reports/compiler-diagnostic-delta-v38.json', 'analysis/il2cpp/virtual-stream-stage-after-type-v36.txt']
    report = dict(status='DESIGN_ONLY_DUPLICATE_METADATA_INIT_FUSION_WITH_PRODUCTION_BLOCKERS',
        evidence_checks=len(checks), evidence_tests=checks, evidence_failures=0,
        recommendation='Prefer exact duplicate-init/allocation fusion over a standalone TypeHandle-or-true Class::Init adapter. Initial production scope should be only the three proved constant Byte[] windows after all listed proof and EH gates exist.',
        inference='Array::NewSpecific itself invokes the same Class::Init before checks/allocation. On a valid exact class, the outer call makes the nested call take the initialized fast path. If the result is dead, only nonthrowing register preparation intervenes and EH scope agrees, the composed operation can retain one metadata initialization inside allocation. This is a conditional composition argument, not evidence that initialization has no effects.',
        candidates=candidates, initial_static_candidates=3, deferred_variable_candidates=1,
        native_allocator={key:native['allocation'][key] for key in ('rva','end','bytes','sha256')},
        original_reader_frame=native.get('reader_frame'), exact_unwind_evidence=native['unwind'], implementation_guards=guards,
        proposed_negative_fixture_families=negatives, proposed_fixtures_executed=0,
        production_blockers=blockers, private_inventory=fact(private_path),
        local_common_array_source=native['extracted_source'],
        evidence=[fact(ROOT / path) for path in evidence_paths] + [fact(current_source)],
        official_host_contract_sources=[dict(url='https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.newarr?view=net-10.0',
            supports='NewArr allocates a zero-based single-dimensional array, zeroes elements, and propagates allocation/negative-size failures.'),
            dict(url='https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf', section='III.4.20',
                 supports='Metadata-token element identity, int32/native-int length and managed array allocation contract; does not establish IL2CPP cold metadata equivalence.')],
        analysis_script_sha256=digest(Path(__file__)), core_edited=False, core_built=False,
        original_inputs_modified=False, native_executed=False, recovered_game_methods_invoked=0,
        helper_suppressed=False, helper_translation_implemented=False, fusion_implemented=False,
        production_ready=False, full_clean_decompile_ready=False, portable_game_ready=False)
    base = ROOT / 'reports/byte-array-layout-fusion-design-v40'
    destination(ROOT, base.with_suffix('.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    lines = ['# Byte-array layout/allocation fusion design', '', report['status'], '', report['recommendation'], '',
             report['inference'], '', 'Observed original caller windows:', '',
             '| Init call | Allocation call | Length | Initial candidate |', '|---|---|---|---|']
    lines += [f"| {item['native_init_call']} | {item['native_allocation_call']} | {item['length_constant'] if item['length_constant'] is not None else 'original low32 mask'} | {'yes' if item['proposed_initial_candidate'] else 'deferred'} |" for item in candidates]
    lines += ['', 'Exact allocator B5FE50..B5FFA4 (340 bytes) invokes B04F60 at B5FE68 before rank/initialized/length checks. The exact official 2018.1.9f1 Array.cpp agrees. Caller Boolean results are overwritten, and only two register instructions intervene. The original reader and allocator both have exact zR CIEs, empty FDE augmentation and no LSDA/personality; the metadata helper retains its own exception cleanup. Native code/source remain private and unchanged.', '',
              'The host [NewArr contract](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.newarr?view=net-10.0) and [ECMA-335 III.4.20](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) provide managed array allocation and zeroing semantics. They do not prove IL2CPP cold metadata behavior.', '', 'Required proof scope:', '']
    lines += ['- ' + item for item in guards]
    lines += ['', 'Production blockers:', ''] + ['- ' + item for item in blockers]
    lines += ['', f'{len(checks)} static evidence assertions passed. {len(negatives)} negative fixture families are proposed; none were executed. No Core edit/build, helper suppression, runtime substitution or native/game execution occurred. Full clean source and portability remain false.', '']
    destination(ROOT, base.with_suffix('.md')).write_text('\n'.join(lines), encoding='utf-8')


if __name__ == '__main__':
    main()
