"""Sanitized report for the v36 codec scope correction and remaining callback gap."""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def main():
    def read(relative):
        return json.loads((ROOT / relative).read_text(encoding='utf-8-sig'))

    def sha(relative):
        return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()

    initial_path = 'reports/recovered-value-this-nso-virtual-dispatch-v36-initial-failure.json'
    initial = read(initial_path)
    final_path = 'reports/recovered-value-this-nso-virtual-dispatch-v36.json'
    final = read(final_path)
    diagnosis_path = 'reports/value-this-clr-diagnosis-nso-virtual-dispatch-v36.json'
    diagnosis = read(diagnosis_path)
    native_path = 'analysis/reconstruction/value-this-regression-v36/native-callback-inventory.json'
    native = read(native_path)
    stage_report_path = 'reports/value-this-callback-stage-v36.json'
    stage_report = read(stage_report_path)
    stage_path = stage_report['private_stage_path'].replace('\\', '/')
    stage = read(stage_path)
    rows = {row['address']: row for row in native['instructions']}
    expected = {
        0x7A9088: ('ldr', 'x0, [x8, #8]'),
        0x7A908C: ('cbz', 'x0, #0x7a90b4'),
        0x7A90A8: ('ldr', 'x8, [x0]'),
        0x7A90AC: ('ldp', 'x9, x1, [x8, #0x198]'),
        0x7A90B0: ('blr', 'x9'),
        0x7A90B4: ('mov', 'w0, w20'),
    }
    if any((rows[address]['mnemonic'], rows[address]['operands']) != instruction for address, instruction in expected.items()):
        raise ValueError('Exact original native callback witness differs')
    call, = stage['calls']
    receiver_definition, = call['receiver_chain'][0]['definitions']
    receiver_is_unique_static_field = (receiver_definition['Index'] == 116 and receiver_definition['opcode'] == 'Move'
        and receiver_definition['operands'][1]['kind'] == 'FieldReference'
        and '<Instance>k__BackingField' in receiver_definition['operands'][1]['description'])
    checks = {
        'initial_failure_preserved': initial['cases'] == 0 and initial['status'] == 'RECOVERY_EXECUTION_LIMITATION_CONFIRMED',
        'one_case_actual_clr_diagnosis_returned_without_import_exception': diagnosis['diagnostic_invocations_returned'] == 1 and diagnosis['diagnostic_return_matches_one_native_fixture'] and diagnosis['invocation_exception'] is None,
        'same_immutable_cil_before_and_after_scope_correction': initial['cil_sha256'] == diagnosis['cil_sha256'] == final['cil_sha256'],
        'same_immutable_assembly_before_and_after_scope_correction': initial['assembly_sha256'] == diagnosis['assembly_sha256'] == final['assembly_sha256'],
        'full_original_absent_detector_subset_passed': final['status'] == 'PASS_ACTUAL_RECOVERED_VALUE_THIS_CODEC_VS_ORIGINAL_NATIVE' and final['cases'] == 342 and final['checks'] == 2052 and final['failure_count'] == 0 and final['lazy_initialization_cases'] == final['already_initialized_cases'] == 171,
        'single_exact_null_branch_scope_proof_and_boundary_checks': final['exact_null_getter_boundary_proved'] and final['null_boundary_checks'] == 342 and final['analysis_only_forced_null_branch'] == dict(offset=379, taken_successor=389, excluded_successor=384),
        'all_four_scope_controls_passed': len(final['scope_guard_controls']) == 4 and all(row['passed'] for row in final['scope_guard_controls']),
        'only_active_callback_helper_excluded': final['blocked_calls'] == [] and final['unreachable_helper_calls'] == 1 and len(final['scope_excluded_helpers']) == 1 and final['scope_excluded_helpers'][0]['offset'] == 200,
        'active_callback_explicitly_unrecovered_unexecuted': not final['active_detector_callback_recovered'] and not final['active_detector_callback_executed'],
        'native_result_x0_immediately_overwritten_before_read': rows[0x7A90B4]['register_reads'] == ['w20'] and rows[0x7A90B4]['register_writes'] == ['w0'],
        'one_unique_typed_static_field_receiver_definition_observed': receiver_is_unique_static_field and not call['receiver_chain'][0]['local']['parameter_root'],
        'raw_callback_result_has_unique_definition_and_no_top_level_use': call['result_definition_count'] == 1 and call['result_top_level_uses'] == 0,
    }
    if not all(checks.values()):
        raise ValueError('Diagnosis report contract failed: ' + str([name for name, ok in checks.items() if not ok]))
    report = dict(status='PASS_V36_CODEC_NULL_SCOPE_CORRECTION_WITH_ACTIVE_CALLBACK_GAP_RETAINED', checks=len(checks), evidence_checks=checks,
        recovery_run='nso-virtual-dispatch-v36', core_sha256=stage_report['core_sha256'], assembly_sha256=final['assembly_sha256'], cil_sha256=final['cil_sha256'],
        probe_source_sha256=final['probe_source_sha256'], original_fixture_sha256=final['fixture_sha256'],
        initial_failure_report=initial_path, initial_failure_report_sha256=sha(initial_path), one_case_diagnosis_report=diagnosis_path, one_case_diagnosis_sha256=sha(diagnosis_path),
        final_codec_report=final_path, final_codec_report_sha256=sha(final_path),
        original_native_body=dict(start='0x7A8F20', end='0x7A9128', bytes=520, sha256=native['body_sha256']),
        original_native_callback=dict(receiver_static_load='0x7A9088', null_branch='0x7A908C', object_class_load='0x7A90A8', paired_slot_load='0x7A90AC', indirect_call='0x7A90B0', next_x0_overwrite='0x7A90B4', function_slot='0x198', methodinfo_slot='0x1A0', metadata_slot=7, target='CodeStage.AntiCheat.Detectors.ActDetectorBase.OnCheatingDetected', target_returns_void=True),
        private_native_path=native_path, private_native_sha256=sha(native_path), private_stage_path=stage_path, private_stage_sha256=sha(stage_path),
        next_bounded_proposal=[
            'Retain the existing virtual proof and pure class/function/companion window; never restore failed-proof ordinary-call fallback.',
            'For an exact void target only, require the raw X0 result to have one unique definition and no direct or deep operand use, including store addresses, Phi inputs, throws and indirect targets; reject ambiguous or escaping results.',
            'Extend the immutable receiver witness only to a unique available typed SSA reference value from a verified field/getter producer, keeping its exact producer/root identity through all copies and emitter validation. Require fresh cone dominance, no redefinition or address escape, same receiver for class dereference, and same reference at call emission.',
            'Do not reload the static getter at call time: the original saved reference is the receiver. Retain all earlier field reads, null/running/mismatch guards and callback effects.',
            'Add rejection fixtures for used void raw result, duplicate/non-dominating/escaping/changed producer, same-type replacement, stale proof and class-to-call semantic effects before any production promotion.',
        ], core_modified=False, recovered_cil_or_source_edited=False, active_callback_recovered=False, active_callback_executed=False,
        full_clean_decompile_ready=False, scope='The exact null-bound regression is valid and now executes all342 original cases. This does not recover or execute the active detector callback. Native callback identity and immediate X0 overwrite are original-code evidence; generalized deep liveness and non-parameter receiver proof remain unimplemented future work.')
    destination(ROOT, ROOT / 'reports/value-this-regression-diagnosis-v36.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    destination(ROOT, ROOT / 'reports/value-this-regression-diagnosis-v36.md').write_text(
        '# v36 codec regression diagnosis\n\n'
        'The original v36 CIL passes all342 absent-detector fixtures (2052 comparisons,342 boundary checks). '
        'The initial failure was a scope-analysis mismatch: syntactic reachability included the active-only unresolved callback. '
        'A one-case unchanged-method invocation ruled out CLR import rejection. The corrected probe pins the exact getter/body, '
        'proves the single null branch, checks four controls and leaves the callback diagnostic in place.\n\n'
        'The callback remains unresolved: metadata slot7 returns void and its receiver is a unique static-field SSA value rather than a parameter. '
        'Native BLR0x7A90B0 is immediately followed by MOV W0,W20 at0x7A90B4, proving its raw X0 result is dead locally. '
        'Future recovery needs deep raw-result liveness and immutable producer/root provenance; no Core change or active-callback execution is claimed.\n\n'
        'The initial failure, original CIL and detailed native/SSA evidence remain on the USB. Full clean decompilation remains incomplete.\n', encoding='utf-8')
    print(json.dumps(dict(status=report['status'], checks=len(checks))))


if __name__ == '__main__':
    main()
