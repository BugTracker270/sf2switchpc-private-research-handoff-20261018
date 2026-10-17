"""Bind v36 virtual dispatch evidence without promoting its blocked actual prefix."""
import argparse
import datetime
import json
from pathlib import Path
import re

from summarize_indirect_return_recovery import ROOT, REGRESSIONS, sha, read, brief, compiler
from summarize_class_guard_load_recovery import source_manifest, source_rows
from usb_boundary import destination

RUN = 'nso-virtual-dispatch-v36'
BASELINE = 'nso-plain-frame-cfg-v35'
ASSEMBLIES = {'Assembly-CSharp-firstpass', 'Assembly-CSharp'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--active-session', action='append', default=[])
    args = parser.parse_args()
    paths = {
        'invocation': f'logs/cpp2il-{RUN}-result.json',
        'source_snapshot': 'reports/virtual-dispatch-source-snapshot-v36.json',
        'review': 'reports/virtual-dispatch-independent-source-review-v36.json',
        'synthetic_contract': 'reports/virtual-dispatch-contract-v36.json',
        'native_prefix': 'reports/native-virtual-stream-prefix-v36.json',
        'production_stages': 'reports/virtual-stream-production-ir-v36.json',
        'actual_prefix': f'reports/recovered-virtual-stream-prefix-{RUN}.json',
        'actual_prefix_baseline': f'reports/recovered-virtual-stream-prefix-{BASELINE}.json',
        'raw_guards': 'reports/raw-classinit-lowering-guards-v36.json',
        'phi_guards': 'reports/class-metadata-phi-production-v36.json',
        'constructor_contract': 'reports/legacy-class-init-lowering-v36-regression.json',
        'codec_initial_failure': f'reports/recovered-value-this-{RUN}-initial-failure.json',
        'candidate_lock': 'reports/cpp2il-hfa-experimental-lock-virtual-dispatch-v36.json',
        'batch': f'reports/recovery-regression-{RUN}.json',
        'syntax': f'analysis/il2cpp/cil-audit-{RUN}/summary.json',
        'stack': f'reports/cil-stack-audit-{RUN}.json',
        'compiler_before': f'reports/recovered-source-profile-legacy-reference-check-{BASELINE}.json',
        'compiler_after': f'reports/recovered-source-profile-legacy-reference-check-{RUN}.json',
        'project_compiler': f'reports/recovered-source-profile-project-build-{RUN}.json',
        'diagnostic_delta': 'reports/compiler-diagnostic-delta-v36.json',
    }
    data = {name: read(path) for name, path in paths.items()}
    evidence = {name: brief(path) for name, path in paths.items()}
    invocation, snapshot = data['invocation'], data['source_snapshot']
    core = invocation.get('tool_assembly_sha256', {}).get('Cpp2IL.Core.dll')
    output = ROOT / f'analysis/il2cpp/cpp2il-recovery-{RUN}'
    dlls = sorted(output.glob('*.dll'))
    dll_hashes = {path.name: sha(path) for path in dlls}
    gates = []
    def gate(name, passed, scope, state=None):
        gates.append(dict(name=name, passed=bool(passed), state=state or ('PASS' if passed else 'PENDING_OR_FAIL'), scope=scope))
    sources = snapshot.get('sources', [])
    frozen_review = read(snapshot.get('source_review_snapshot', '__missing__'))
    reviewed = {row['path'].replace('\\', '/'): row['sha256'] for row in frozen_review.get('reviewed_sources', [])}
    expected_sources = {row['path'].replace('\\', '/'): row['sha256'] for row in sources}
    gate('immutable_invocation_and_six_reviewed_source_snapshots', invocation.get('exit_code') == 0
         and invocation.get('legacy_hfa_recovery') is True and re.fullmatch('[0-9a-f]{64}', str(core))
         and snapshot.get('status') == 'PASS_IMMUTABLE_V36_REVIEWED_SOURCE_CAPTURE'
         and snapshot.get('core_sha256') == core == frozen_review.get('stable_tested_core_sha256')
         and len(sources) == len(reviewed) == 6 and expected_sources == reviewed
         and snapshot.get('recovery_invocation_sha256') == evidence['invocation']['report_sha256']
         and all((ROOT / row['snapshot_path']).is_file() and sha(ROOT / row['snapshot_path']) == row['sha256'] for row in sources)
         and bool(snapshot.get('source_review_snapshot')) and sha(ROOT / snapshot['source_review_snapshot']) == snapshot.get('source_review_sha256')
         and bool(snapshot.get('recovery_invocation_snapshot')) and sha(ROOT / snapshot['recovery_invocation_snapshot']) == snapshot.get('recovery_invocation_sha256')
         and bool(snapshot.get('manifest_path')) and sha(ROOT / snapshot['manifest_path']) == snapshot.get('manifest_sha256'),
         'Frozen source/review/invocation snapshots bind the completed build without relying on later live Core binaries or source changes.')
    gate('independent_source_review_scope', frozen_review.get('source_review_only') is True
         and frozen_review.get('status') == 'SOURCE_REVIEW_NO_ADDITIONAL_BLOCKER_FULL_RECOVERY_GATES_PENDING'
         and len(frozen_review.get('findings_resolved', [])) == 5 and frozen_review.get('full_clean_decompile_ready') is False,
         'Six reviewed files and resolved proof/emitter issues; this review alone never certifies actual execution or complete recovery.')
    contract = data['synthetic_contract']
    gate('real_production_emitter_synthetic_218_checks_99_clr_cases', contract.get('status') == 'PASS_NATIVE_VIRTUAL_WITNESS_AND_REAL_EMITTER_CLR_CONTRACT'
         and contract.get('checks') == 218 and contract.get('cases') == 99 and not contract.get('fatal')
         and contract.get('core_sha256') == core
         and contract.get('binary_sha256') == invocation.get('source_binary_sha256')
         and contract.get('metadata_sha256') == invocation.get('source_metadata_sha256')
         and contract.get('helper_source_sha256') == reviewed.get('refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64VirtualDispatch.cs')
         and contract.get('emitter_source_sha256') == reviewed.get('refs/Cpp2IL/Cpp2IL.Core/IlGenerator.cs')
         and contract.get('instruction_source_sha256') == reviewed.get('refs/Cpp2IL/Cpp2IL.Core/ISIL/Instruction.cs')
         and all(row.get('status') == 'PASS' for row in contract.get('tests', []))
         and contract.get('emitter_tests_are_synthetic') is True and contract.get('actual_recovered_runtime_performed') is False
         and contract.get('game_methods_executed') == 0 and contract.get('host_fixture_member_substitutions') == 1
         and contract.get('emitted_call_opcodes_rewritten_by_probe') == 0
         and contract.get('probe_source_sha256') == sha(ROOT / 'src/re/VirtualDispatchContractProbe/Program.cs'),
         'Actual production proof/emitter, explicit authored host member boundary and CLR override/direct/null effects. These 99 cases do not execute a recovered game caller.')
    native = data['native_prefix']
    fixture = ROOT / native.get('fixture_path', '__missing__')
    native_image = ROOT / 'analysis/nso/main-uncompressed.nso'
    gate('unchanged_native_802_cases_9624_checks', native.get('status') == 'PASS_UNCHANGED_NATIVE_STREAM_OVERRIDE_AND_VIRTUAL_READER_PREFIX'
         and native.get('cases') == 802 and native.get('checks') == 9624 and native.get('failures') == 0
         and native.get('original_native_virtual_calls') == native.get('original_native_override_entries') == 1604
         and native.get('original_instructions_unmodified') is True and native.get('native_guest_functions_replaced') == 0
         and native.get('hooks_observe_only') is True and native.get('managed_recovered_code_executed') is False
         and native.get('native_source_sha256') == sha(native_image)
         and fixture.is_file() and native.get('fixture_sha256') == sha(fixture)
         and native.get('probe_source_sha256') == sha(ROOT / 'src/re/tools/execute_native_virtual_stream_prefix.py'),
         'Unchanged reader prefix and original MemoryStream override at supplied object/vtable/initialized-metadata boundaries; no recovered caller, constructor, null/error path or whole frame parser execution.')
    stages = data['production_stages']
    gate('actual_full_pipeline_and_final_emitter_input_14', stages.get('status') == 'PASS_SCOPED_NATIVE_VIRTUAL_PROOF_THROUGH_PRODUCTION_EMITTER_INPUT'
         and stages.get('checks') == 14 and stages.get('core_sha256') == core
         and stages.get('accepted_original_call_indices') == [26, 36]
         and stages.get('unresolved_original_indirect_indices') == [195, 231]
         and stages.get('recovered_game_methods_invoked') == 0 and stages.get('recovered_cil_or_source_modified') is False
         and all((ROOT / row['path']).is_file() and sha(ROOT / row['path']) == row['sha256'] for row in stages.get('evidence', {}).values())
         and stages.get('evidence', {}).get('contract', {}).get('sha256') == evidence['synthetic_contract']['report_sha256']
         and stages.get('evidence', {}).get('native', {}).get('sha256') == evidence['native_prefix']['report_sha256'],
         'Actual original receiver proof survives full production analysis and final emitter validation at two sites; two later indirect calls stay unresolved.')
    actual = data['actual_prefix']
    baseline_prefix = data['actual_prefix_baseline']
    baseline_dll = ROOT / f'analysis/il2cpp/cpp2il-recovery-{BASELINE}/Assembly-CSharp-firstpass.dll'
    gate('actual_baseline_nonvirtual_opcode_limitation_retained', baseline_prefix.get('status') == 'RECOVERY_EXECUTION_LIMITATION_CONFIRMED'
         and baseline_prefix.get('recovery_run') == BASELINE and baseline_dll.is_file()
         and baseline_prefix.get('assembly_sha256') == sha(baseline_dll)
         and baseline_prefix.get('actual_callvirt_sites') == 0 and baseline_prefix.get('actual_direct_readbyte_sites') == 2
         and baseline_prefix.get('runtime_performed') is False and baseline_prefix.get('runtime_cases') == 0
         and baseline_prefix.get('cil_or_source_modified') is False and baseline_prefix.get('native_report_sha256') == evidence['native_prefix']['report_sha256'],
         'The unchanged prior DLL emitted two direct calls at native virtual sites and was never executed as recovered parity. Current opcode correction does not remove other execution blockers.')
    actual_binding = (actual.get('status') == 'ACTUAL_VIRTUAL_PREFIX_CORRELATED_EXECUTION_LIMITATIONS'
        and actual.get('recovery_run') == RUN and actual.get('assembly_sha256') == dll_hashes.get('Assembly-CSharp-firstpass.dll')
        and actual.get('native_report_sha256') == evidence['native_prefix']['report_sha256']
        and actual.get('fixture_sha256') == native.get('fixture_sha256') and actual.get('native_evidence_bound') is True
        and actual.get('native_fixture_cases') == 802 and actual.get('actual_prefix_cfg_shape_proven') is True
        and actual.get('actual_native_virtual_identity_preserved') is True
        and actual.get('actual_callvirt_sites') == 2 and actual.get('actual_direct_readbyte_sites') == 0
        and actual.get('cil_or_source_modified') is False and actual.get('call_opcodes_rewritten') == 0
        and actual.get('member_substitutions') == actual.get('tokens_remapped') == actual.get('dynamic_clones') == 0
        and not actual.get('fatal') and actual.get('probe_source_sha256') == sha(ROOT / 'src/re/RecoveredVirtualStreamPrefixProbe/Program.cs'))
    gate('actual_current_dll_callvirt_correlation', actual_binding,
         'Read-only current original CIL: two exact Stream.ReadByte callvirt sites, zero direct-call substitutions. Its opcode/member correlation is separate from execution eligibility.')
    blockers = actual.get('helper_zero_placeholders', [])
    limitation_recorded = actual_binding and actual.get('runtime_eligible') is False and actual.get('runtime_performed') is False \
        and actual.get('runtime_cases') == actual.get('actual_game_methods_invoked') == 0 \
        and len(blockers) == 1 and blockers[0].get('paired_method_info_offset_0x260') is True \
        and blockers[0].get('local_type') == 'System.Byte[]' and len(actual.get('unresolved_prefix_calls', [])) == 1 \
        and len(actual.get('execution_limitations', [])) >= 3
    gate('actual_prefix_runtime_execution', limitation_recorded,
         'LIMITATION: one live MethodInfo companion-load diagnostic becomes a native-int zero/Byte[] placeholder. Actual runtime is blocked (zero cases); no diagnostic removal, token substitution or cloned execution is counted.',
         state='LIMITATION' if limitation_recorded else 'PENDING_OR_FAIL')
    for name, count, core_key in (('raw_guards', 31, 'core_sha256'), ('phi_guards', 73, 'core_sha256'), ('constructor_contract', 120, 'core_assembly_sha256')):
        report = data[name]
        gate(name, str(report.get('status', '')).startswith('PASS') and report.get('checks') == count and report.get(core_key) == core,
             'Current compiled Core regression; original ABI/origin and real CLR .cctor contracts retain their own scope.')
    regressions, additional_missing = {}, []
    for name in REGRESSIONS + ['scalars', 'enumerator', 'boolean-reader']:
        suffix = '-with-identities' if name == 'nested-tween' else ''
        path = f'reports/recovered-{name}-{RUN}{suffix}.json'
        report = read(path)
        if not report:
            additional_missing.append(path)
        bound = {key:value for key, value in report.items() if isinstance(value, str)
                 and (key == 'assembly_sha256' or key.endswith('_assembly_sha256') or key == 'firstpass_sha256')}
        passed = report.get('recovery_run') == RUN and str(report.get('status', '')).startswith('PASS') \
            and not report.get('fatal') and report.get('failure_count', 0) == 0 \
            and bool(bound) and all(value in dll_hashes.values() for value in bound.values())
        if name == 'enumerator':
            passed = passed and report.get('successful_cases') == 5 and report.get('production_cil_or_source_modified') is False
        else:
            passed = passed and report.get('checks', 0) > 0
        if name == 'boolean-reader':
            passed = passed and report.get('cases') == 811 and report.get('checks') == 3244 \
                and report.get('cil_or_source_edited') is False and report.get('tokens_remapped') == 0 \
                and report.get('native_case_binding', {}).get('all_native_cases_executed') is True
        if name == 'value-this':
            controls = report.get('scope_guard_controls', [])
            passed = passed and report.get('cases') == 342 and report.get('checks') == 2052 \
                and report.get('exact_null_getter_boundary_proved') is True and report.get('null_boundary_checks') == 342 \
                and report.get('cil_or_source_edited') is False and report.get('tokens_remapped') == 0 \
                and report.get('active_detector_callback_recovered') is False and report.get('active_detector_callback_executed') is False \
                and len(controls) == 4 and all(row.get('passed') is True for row in controls) \
                and {row.get('control') for row in controls} == {'exact_original_null_getter_branch',
                    'non_null_detector_rejected_without_invocation', 'altered_getter_copy_rejected_without_execution',
                    'altered_branch_copy_rejected_without_execution'} \
                and report.get('probe_source_sha256') == sha(ROOT / 'src/re/RecoveredValueThisProbe/Program.cs')
        regressions[name] = dict(report=path, report_sha256=sha(ROOT / path) if report else None, recorded_dll_hashes=bound,
                                status=report.get('status'), cases=report.get('cases'), checks=report.get('checks'),
                                fatal=report.get('fatal'), scope=report.get('scope'))
        gate('recovered_' + name, passed, 'Current-run unchanged recovered CIL at the original fixture/member/native boundaries; DLL hashes are recorded explicitly.')
    initial_codec = data['codec_initial_failure']
    gate('codec_initial_failure_preserved_and_scope_explicit', initial_codec.get('status') == 'RECOVERY_EXECUTION_LIMITATION_CONFIRMED'
         and initial_codec.get('recovery_run') == RUN and initial_codec.get('cases') == initial_codec.get('checks') == 0
         and initial_codec.get('assembly_sha256') == dll_hashes.get('Assembly-CSharp-firstpass.dll')
         and bool(initial_codec.get('fatal')) and len(initial_codec.get('blocked_calls', [])) == 1,
         'The first strict-syntactic failure remains preserved. The corrected probe executes only the original null-detector fixture boundary; the active-detector virtual callback is still unresolved and unexecuted.')
    candidate = data['candidate_lock']
    candidate_patch = ROOT / candidate.get('patch', '__missing__')
    candidate_artifact = dict(report=paths['candidate_lock'], report_sha256=evidence['candidate_lock']['report_sha256'],
        status=candidate.get('status'), patch=candidate.get('patch'), patch_sha256=candidate.get('sha256'),
        patch_hash_verified=candidate_patch.is_file() and sha(candidate_patch) == candidate.get('sha256'), promoted=False)
    gate('separate_unpromoted_candidate_patch', candidate.get('status') == 'EXPERIMENTAL_SAVED_NOT_PROMOTED'
         and candidate_artifact['patch_hash_verified'] is True
         and candidate.get('patch', '').replace('\\', '/') == 'src/re/tool-patches/cpp2il-sf2-hfa-experimental-virtual-dispatch-v36.patch',
         'A separate complete candidate patch is retained with its identity. It does not replace the earlier accepted experimental patch or establish production recovery readiness.')
    batch = data['batch']
    expected_batch = {'syntax', 'stack', 'scalar-direct', 'scalar-isolated', 'vector', 'boolean', 'nested-tween',
        'type-token', 'constructor', 'currency-scalars', 'aggregate-leaves', 'leaf-accessor',
        'static-getter', 'exception-factory', 'primitive-box', 'value-this-codec', 'indirect-enumerator', 'boolean-reader'}
    gate('all_18_scoped_regression_invocations', batch.get('status') == 'PASS_SCOPED_RECOVERY_REGRESSIONS'
         and batch.get('recovery_run') == RUN and len(batch.get('probes', [])) == 18
         and {row.get('suffix') for row in batch.get('probes', [])} == expected_batch
         and all(row.get('exit_code') == 0 for row in batch.get('probes', [])),
         'All eighteen established bounded invocations completed successfully; actual blocked Stream-prefix execution is not part of that PASS count.')
    syntax, stack = data['syntax'], data['stack']
    syntax_rows = syntax.get('assemblies', [])
    gate('syntax_44', len(dlls) == len(syntax_rows) == 44 and {row.get('file') for row in syntax_rows} == set(dll_hashes)
         and Path(syntax.get('source_directory', '')).resolve() == output.resolve()
         and all(row.get('malformed_il') == 0 for row in syntax_rows), 'Encoding syntax only; unresolved helpers/type errors can remain.')
    gate('stack_44', stack.get('status') == 'PASS_STACK_DEPTH_AND_HEADERS_ONLY' and stack.get('recovery_run') == RUN
         and stack.get('assembly_count') == 44 and all(stack.get(key) == 0 for key in ('understated_max_stack', 'stack_flow_failures', 'helper_types_without_base')),
         'Stack/header consistency only; neither CLR operand typing nor actual prefix runtime is certified.')
    source_integrity = {}
    hash_cache = {}
    for key in ('compiler_before', 'compiler_after', 'project_compiler'):
        report = data[key]
        rows = source_rows(report)
        expected_run = BASELINE if key == 'compiler_before' else RUN
        experiment = 'source-profile-project-build' if key == 'project_compiler' else 'source-profile-legacy-reference-check'
        prefix = f'analysis/il2cpp/source-profile-project-build-{expected_run}/'
        manifest = source_manifest(report)
        gate(key + '_complete_profiles', report.get('recovery_run') == expected_run and report.get('experiment') == experiment
             and {row.get('assembly') for row in rows} == ASSEMBLIES
             and all(row.get('export_exit_code') == row.get('restore_exit_code') == 0
                     and isinstance(row.get('build_exit_code'), int) and isinstance(row.get('unique_compiler_diagnostic_lines'), int) for row in rows),
             'Both complete exported-source assembly builds are recorded with original compiler failures intact.')
        failures, verified = [], 0
        if manifest and not args.active_session:
            for assembly, files in manifest.items():
                for relative, digest in files.items():
                    if not relative.replace('\\', '/').startswith(prefix):
                        failures.append(dict(path=relative, reason='wrong run/profile source path'))
                        continue
                    path = destination(ROOT, ROOT / relative)
                    if relative not in hash_cache:
                        hash_cache[relative] = sha(path) if path.is_file() else None
                    if hash_cache[relative] != digest:
                        failures.append(dict(path=relative, reason='actual source hash differs'))
                    else:
                        verified += 1
        source_integrity[key] = dict(verified_files=verified, failures=failures,
                                    verification_deferred_for_active_work=bool(args.active_session))
        gate(key + '_all_source_files_unchanged', bool(manifest) and verified > 0 and not failures,
             'Every source file in the complete recorded profile manifest is independently read and hash-verified; sources are never rewritten by this summary.')
    gate('both_current_compiler_profiles_use_identical_source', source_manifest(data['compiler_after']) is not None
         and source_manifest(data['compiler_after']) == source_manifest(data['project_compiler']),
         'Ordinary host-reference and matching legacy-reference compilers use exactly the same complete source-file/hash inventory.')
    before, after = compiler(BASELINE), compiler(RUN)
    old = {row['assembly']:row['unique_compiler_diagnostic_lines'] for row in before}
    counts = {row['assembly']:row['unique_compiler_diagnostic_lines'] for row in after}
    delta = {name:counts[name] - old[name] for name in ASSEMBLIES if name in old and name in counts}
    comparison = data['diagnostic_delta']
    comparisons = comparison.get('assemblies', {})
    gate('canonical_diagnostic_delta_and_unchanged_sources', comparison.get('status') == 'PASS_CANONICAL_COMPLETE_SOURCE_COMPILER_COMPARISON'
         and comparison.get('before_run') == BASELINE and comparison.get('after_run') == RUN
         and comparison.get('source_modified') is False and comparison.get('core_modified') is False
         and set(comparisons) == set(old) == set(counts) == ASSEMBLIES
         and comparison.get('compiler_diagnostic_delta') == delta
         and all(row.get('before_unique') == old[name] and row.get('after_unique') == counts[name] and row.get('delta') == delta[name]
                 and set(row.get('source_integrity', {})) == {BASELINE, RUN}
                 and all(part.get('matching_reference_source_manifest_unchanged') is True
                         and part.get('diagnostic_source_files_hash_verified', 0) > 0 for part in row['source_integrity'].values()) for name, row in comparisons.items()),
         'Authoritative before/after totals and canonical diagnostic deltas include cascades; they are not completion percentages or independent missing-method counts.')
    missing = [path for path in paths.values() if not (ROOT / path).exists()] + additional_missing
    passed = all(row['passed'] for row in gates)
    status = 'SCOPED_VIRTUAL_DISPATCH_VALIDATED_ACTUAL_PREFIX_EXECUTION_LIMITATION_REMAINS' if passed else (
        'IN_PROGRESS' if missing or args.active_session else 'VIRTUAL_DISPATCH_VALIDATION_LIMITATION_CONFIRMED')
    report = dict(status=status, recovery_run=RUN, baseline_run=BASELINE,
        updated=datetime.datetime.now(datetime.timezone.utc).isoformat(), recovery_core_sha256=core,
        evidence=evidence, gates=gates, failed_gates=[row['name'] for row in gates if not row['passed']],
        limitation_gates=[row['name'] for row in gates if row['state'] == 'LIMITATION'], missing_reports=missing,
        assembly_hashes=dll_hashes, recovered_regressions=regressions, complete_source_integrity=source_integrity,
        summary_tool_sha256=sha(Path(__file__)), unpromoted_candidate=candidate_artifact,
        codec_boundary=dict(original_failure=evidence['codec_initial_failure'],
            corrected_scope='Original null-detector fixtures only; exact pure getter and null branch must be proved before excluding the active-only callback diagnostic.',
            active_detector_callback_recovered=False, active_detector_callback_executed=False),
        compiler_before=before, compiler_after=after, compiler_diagnostic_line_delta=delta,
        source_compiler_results={key:source_rows(data[key]) for key in ('compiler_before', 'compiler_after', 'project_compiler')},
        actual_prefix_runtime_performed=actual.get('runtime_performed'), actual_prefix_runtime_cases=actual.get('runtime_cases'),
        actual_prefix_opcode_comparison=dict(before=dict(callvirt=baseline_prefix.get('actual_callvirt_sites'),
            direct=baseline_prefix.get('actual_direct_readbyte_sites')), after=dict(callvirt=actual.get('actual_callvirt_sites'),
            direct=actual.get('actual_direct_readbyte_sites'))),
        actual_prefix_structural_failures=[row for row in actual.get('structural_checks', []) if row.get('Status') != 'PASS'],
        actual_prefix_execution_limitations=actual.get('execution_limitations', []), actual_prefix_remaining_placeholders=blockers,
        active_sessions=args.active_session, full_clean_decompile_ready=False, whole_game_source_ready=False, portable_game_ready=False,
        limits='The two actual callvirt sites are structurally correlated, while actual prefix runtime remains blocked by a live MethodInfo companion-load diagnostic/native-int-zero placeholder. '
               'Native initialized-runtime fixtures, synthetic real-emitter CLR cases, actual production IR, read-only current CIL and full-source compilers have distinct scopes. '
               'No actual prefix runtime cases or full-game execution are claimed. Later indirect calls, class-layout metadata effects, missing exception recovery and complete source compilation remain unresolved.')
    base = ROOT / 'reports/virtual-dispatch-source-recovery-v36'
    destination(ROOT, base.with_suffix('.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    lines = ['# Virtual dispatch recovery checkpoint', '', status, '',
        'Both actual Stream.ReadByte sites retain callvirt. Actual prefix execution remains blocked by a live MethodInfo diagnostic; zero runtime cases ran. Full clean decompilation and portable game source remain incomplete.', '',
        '| Complete matching-reference source check | Firstpass diagnostics | Main diagnostics |', '|---|---:|---:|']
    for name, rows in ((BASELINE, before), (RUN, after)):
        totals = {row['assembly']:row['unique_compiler_diagnostic_lines'] for row in rows}
        lines.append(f"| {name} | {totals.get('Assembly-CSharp-firstpass', 'pending')} | {totals.get('Assembly-CSharp', 'pending')} |")
    lines += ['', f"Required evidence gates: {sum(row['passed'] for row in gates)}/{len(gates)}; actual prefix runtime is explicitly LIMITATION.", '',
              f"Established regression invocations: {sum(row.get('exit_code') == 0 for row in batch.get('probes', []))}/18 successful. Failed required gates: {', '.join(report['failed_gates']) or 'none'}.", '',
              'Separate measured scopes: 218 synthetic contract checks / 99 authored CLR cases; 802 unchanged native cases / 9,624 checks; two unchanged actual CIL callvirt sites. None substitutes for executing the blocked actual prefix.', '',
              'The codec probe retains its initial syntactic failure, then checks unchanged recovered CIL in 342 original null-detector cases / 2,052 checks with four boundary controls. Its active-detector virtual callback remains unresolved and unexecuted.', '',
              f"Unpromoted candidate: `{candidate_artifact['patch']}`; SHA-256 `{candidate_artifact['patch_sha256']}`. The accepted earlier patch remains separate.", '', report['limits'], '']
    destination(ROOT, base.with_suffix('.md')).write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'failed_gates', 'missing_reports', 'limitation_gates', 'compiler_after', 'compiler_diagnostic_line_delta')}))


if __name__ == '__main__':
    main()
