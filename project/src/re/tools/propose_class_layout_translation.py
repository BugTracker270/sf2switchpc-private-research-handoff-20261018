"""Bounded host metadata contract proposal; no helper replacement or Core edits."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8-sig'))


def main():
    source_report = ROOT / 'reports/class-layout-runtime-source-v37.json'
    source = load(str(source_report.relative_to(ROOT)))
    clr_path = ROOT / 'reports/clr-type-metadata-boundary-v37.json'
    clr = load(str(clr_path.relative_to(ROOT)))
    primitives_path = ROOT / 'reports/scalar-boxing-metadata-v30.json'
    primitives = load(str(primitives_path.relative_to(ROOT)))
    byte, = [row for row in primitives['primitives'] if row['type'] == 'System.Byte']
    base = ROOT / 'tools/unity-2018.1.9f1/common-runtime-source/Editor/Data/il2cpp/libil2cpp'
    array_path = base / 'metadata/ArrayMetadata.cpp'
    allocation_path = base / 'vm/MetadataAlloc.cpp'
    pool_path = base / 'utils/MemoryPool.cpp'
    array, allocation, pool = [path.read_text(encoding='utf-8-sig') for path in (array_path, allocation_path, pool_path)]
    stage_path = ROOT / 'analysis/il2cpp/virtual-stream-stage-after-type-v36.txt'
    stage = stage_path.read_text(encoding='utf-8-sig')
    calls = [dict(call_index=int(match[1]), helper='0xb04f60', typed_class='System.Byte[]') for match in
             re.finditer(r'^(\d+) Call B04F60, [^\r\n]*?Il2CppClass<System\.Byte\[\]>', stage, re.MULTILINE)]
    checks = []
    def check(name, ok):
        checks.append(dict(name=name, passed=bool(ok)))
    check('exact one-argument Boolean metadata helper proof remains valid', source['status'] == 'PASS_EXACT_COMMON_RUNTIME_CLASS_INIT_BOOL_ABI_AND_EFFECTS'
          and source['failures'] == 0 and source['abi']['return_type'] == 'bool' and source['abi']['normal_result'] is True
          and source['abi']['explicit_arguments'] == 1 and not source['abi']['void_return_supported'])
    check('CLR witness passes and binds exact source report', clr['status'] == 'PASS_HOST_METADATA_OBSERVATION_WITH_CCTOR_CANARIES'
          and clr['failures'] == 0 and clr['checks'] == 60 and clr['original_il2cpp_source_report_sha256'] == sha(source_report))
    check('forty measured pre-control observations leave both constructors untouched', clr['pre_control_metadata_observations'] == 40
          and clr['cctor_runs_before_positive_controls'] == {'counted': 0, 'throwing': 0})
    check('explicit controls prove counted and throwing constructor canaries', clr['cctor_runs_after_positive_controls'] == {'counted': 1, 'throwing': 1})
    check('all CLR observations are retained separately from native execution', clr['metadata_observation_count'] == 44
          and not clr['candidate_translation_implemented'] and not clr['original_game_code_executed'])
    check('original Byte element metadata has no managed constructor', byte['value_type'] and not byte['has_static_constructor']
          and byte['instance_size'] == 17 and byte['native_size'] == 1
          and primitives['metadata_sha256'] == 'f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85')
    check('common array factory uses zeroed class storage and array identity',
          'MetadataCalloc(1, sizeof(Il2CppClass)' in array and 'klass->parent = il2cpp_defaults.array_class;' in array
          and 'klass->byval_arg.type = IL2CPP_TYPE_SZARRAY;' in array and 'klass->has_cctor' not in array)
    check('metadata allocation zeroing is backed by shipped implementation', 's_MetadataMemoryPool->Calloc(count, size)' in allocation
          and 'void* MemoryPool::Calloc(size_t count, size_t size)' in pool and 'memset(ret, 0, count * size)' in pool)
    check('actual frozen caller has typed Byte-array class candidates', {67, 123}.issubset({row['call_index'] for row in calls}))
    check('all implementation/promotion flags remain false', source['managed_translation_implemented'] is False
          and clr['candidate_translation_implemented'] is False and not source['core_edited'] and not clr['core_edited'])
    eligible_contract = [
        'Initially admit only the exact resolved System.Byte[] SZARRAY type from original metadata at the reviewed B04F60 calls; resolve actual assembly/type identity, rank and element identity rather than FullName alone.',
        'Require the exact original helper/FDE/hash/source identity and one klass input; preserve its Boolean result and ordering. Incoming X1 and other raw ABI registers are not extra managed parameters.',
        'Require a valid non-null exact known class/type representation, original Byte metadata without .cctor and a host Byte[] type with no array/element initializer. Reject open/generic/custom/reference-element/multidimensional/bounded arrays and other classes in this first candidate.',
        'A possible host operation is obtaining the exact runtime type handle/type metadata, then returning true only on normal completion. The witness measures TypeHandle/GetTypeFromHandle and metadata reflection; it does not implement a replacement helper or authorize eliminating the metadata-readiness effect.',
        'Do not invoke RuntimeHelpers.RunClassConstructor, instantiate an element or use managed .cctor as a substitute. Keep the separate native Runtime::ClassInit semantic request separate and ordered.',
        'Validate actual emitted CIL/callsite state and constructor-counter negatives before promotion; preserve diagnostics for unsupported types/failure states instead of producing a default result or silently swallowing exceptions.',
    ]
    unresolved = [
        'The proposed operation is an inferred host-runtime adaptation, not a recovered original C# method. No production translation exists, and no exact native cold initialization-to-CLR equivalence is claimed.',
        'Native null assertion/termination, metadata allocation failure, recursive setup failure, locking and cleanup/unwind are not mapped to CLR failures. Do not assume unconditional success from the observed normal true return.',
        'The common array factory/source zero-initialization model is source evidence; the actual target runtime array-class factory and a concrete cold Byte[] heap initialization were not executed in this witness.',
        'The four frozen typed raw-call candidates are static inventory only. Actual future callsite/provenance/registered alias and result/side-effect ordering gates remain unimplemented.',
        'The host CLR metadata probe deliberately invokes counted/throwing .cctor only in separate positive controls after forty metadata observations. This does not permit .cctor execution in a translated layout operation.',
        'Other primitive arrays, Boolean/Char with original constructor metadata, custom classes, reference-element arrays, generics and unknown metadata require separate eligibility/equivalence evidence.',
    ]
    report = dict(status='PASS_BOUNDED_CLASS_LAYOUT_TRANSLATION_CONTRACT_EVIDENCE' if all(row['passed'] for row in checks) else 'FAIL_CLASS_LAYOUT_TRANSLATION_CONTRACT_EVIDENCE',
        checks=len(checks), failures=sum(not row['passed'] for row in checks), tests=checks,
        first_candidate_type='System.Byte[]', candidate_origin='INFERRED_HOST_RUNTIME_ADAPTATION_NOT_IMPLEMENTED',
        proposed_eligibility_and_operation=eligible_contract, unresolved=unresolved,
        source_report_sha256=sha(source_report), clr_witness_sha256=sha(clr_path),
        original_byte_metadata_sha256=sha(primitives_path), frozen_typed_stage_sha256=sha(stage_path),
        typed_raw_call_candidates=calls, candidate_count=len(calls), candidate_count_is_runtime_coverage=False,
        additional_common_source_hashes={str(path.relative_to(ROOT)):sha(path) for path in (array_path, allocation_path, pool_path)},
        probe_source_sha256=sha(Path(__file__)), core_edited=False, core_built=False,
        helper_suppressed=False, managed_translation_implemented=False, eligibility_implemented=False,
        actual_native_cold_class_executed=False, original_game_method_executed=False,
        production_ready=False, full_clean_decompile_ready=False)
    base_report = ROOT / 'reports/class-layout-translation-contract-v37'
    destination(ROOT, base_report.with_suffix('.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    lines = ['# Bounded class-layout translation contract', '', report['status'], '',
             'The first proposed candidate is the exact resolved System.Byte[] type. Normal native Class::Init returns true; its metadata/layout effect and failures must remain distinct from managed .cctor. No translation or eligibility implementation exists.', '',
             'Evidence: 15 exact-source/native checks; initialized native path 512 cases / 3,584 checks; separate host CLR witness 60 checks / 44 observations. Forty metadata observations occurred before deliberate constructor positive controls and left counted/throwing .cctor canaries untouched.', '',
             'Proposed contract:', '']
    lines += ['- ' + text for text in eligible_contract]
    lines += ['', 'Unresolved before production acceptance:', ''] + ['- ' + text for text in unresolved]
    lines += ['', 'Unity source remains local and ignored; the public patch contains original probes/reports only. No Core changes or helper removal occurred.', '']
    destination(ROOT, base_report.with_suffix('.md')).write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'checks', 'failures', 'candidate_count', 'managed_translation_implemented')}))
    if report['failures']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
