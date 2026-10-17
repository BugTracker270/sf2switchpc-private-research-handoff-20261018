"""Bind v33 scheduling, native/recovered reader, regression and complete-source evidence."""
import argparse
import datetime
import json
import re
from pathlib import Path

from summarize_indirect_return_recovery import ROOT, REGRESSIONS, sha, read, brief, compiler
from usb_boundary import destination

RUN = 'nso-class-guard-load-v33'
BASELINE = 'nso-enumerator-return-v32'
SOURCE = ROOT / 'refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64AllocationPattern.cs'
EXPECTED_READER = 'a2c22a6bcf2d17e31452dd9f67a08c42b7b246e10cf3db95f8e6cac2a1fef722'
EXPECTED_CONVERTER = '5380a7ce418e5ad7e7423ae1f3114e9cd752d23949c0effd91e0f46ba8d3423d'


def source_rows(data):
    return [{key: row.get(key) for key in ('assembly', 'export_exit_code', 'restore_exit_code',
            'build_exit_code', 'unique_compiler_diagnostic_lines')} for row in data.get('assemblies', [])]


def source_manifest(data):
    result = {}
    for row in data.get('assemblies', []):
        files = row.get('source_files', [])
        manifest = {item.get('path'): item.get('sha256') for item in files}
        if not manifest or len(manifest) != len(files) or not all(
                isinstance(path, str) and re.fullmatch('[0-9a-f]{64}', str(value)) for path, value in manifest.items()):
            return None
        result[row['assembly']] = manifest
    return result if len(result) == 2 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-name', default=RUN)
    parser.add_argument('--active-session', action='append', default=[])
    args = parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+', args.run_name):
        parser.error('Only lowercase run identifiers are allowed')
    run = args.run_name
    paths = {
        'recovery_invocation': f'logs/cpp2il-{run}-result.json',
        'native_scheduling': 'reports/class-guard-scheduling-v33.json',
        'static_candidates': 'reports/class-guard-scheduling-scale-v33.json',
        'raw_guards': 'reports/raw-classinit-lowering-guards-v33.json',
        'actual_ir_survey': 'reports/raw-classinit-stage-survey-v33.json',
        'actual_ir_native_correlation': 'reports/raw-classinit-native-correlation-v33.json',
        'remaining_getsafe_limits': 'reports/class-guard-get-safe-residual-v33.json',
        'native_reader': 'reports/native-boolean-reader-v33.json',
        'actual_reader_baseline': f'reports/recovered-boolean-reader-{BASELINE}.json',
        'actual_reader': f'reports/recovered-boolean-reader-{run}.json',
        'actual_enumerator': f'reports/recovered-enumerator-{run}.json',
        'regression_batch': f'reports/recovery-regression-{run}.json',
        'syntax': f'analysis/il2cpp/cil-audit-{run}/summary.json',
        'stack': f'reports/cil-stack-audit-{run}.json',
        'compiler_before': f'reports/recovered-source-profile-legacy-reference-check-{BASELINE}.json',
        'compiler_after': f'reports/recovered-source-profile-legacy-reference-check-{run}.json',
        'project_export_compiler': f'reports/recovered-source-profile-project-build-{run}.json',
    }
    reports = {key: read(path) for key, path in paths.items()}
    evidence = {key: brief(path) for key, path in paths.items()}
    output = ROOT / f'analysis/il2cpp/cpp2il-recovery-{run}'
    dlls = sorted(output.glob('*.dll')) if output.exists() else []
    dll_hashes = {path.name: sha(path) for path in dlls}
    invocation = reports['recovery_invocation']
    core_hash = invocation.get('tool_assembly_sha256', {}).get('Cpp2IL.Core.dll')
    source_hash = sha(SOURCE) if SOURCE.exists() else None
    native_path = ROOT / 'analysis/nso/main-uncompressed.nso'
    native_hash = sha(native_path) if native_path.exists() else None
    gates = []

    def gate(name, passed, scope):
        gates.append(dict(name=name, passed=bool(passed), scope=scope))

    native = reports['native_scheduling']; scale = reports['static_candidates']
    gate('native_scheduling_58', native.get('status') == 'PASS_BOUNDED_32BIT_CLASS_GUARD_SCHEDULING_RECOGNITION'
         and native.get('checks') == 58 and native.get('source_sha256') == source_hash,
         'Actual matcher source, exact native frames and conservative scheduling/receiver/effect rejection fixtures.')
    gate('static_candidates_289_only', scale.get('status') == 'PASS_FROZEN_V32_VS_V33_EXACT_FDE_STATIC_GUARD_CANDIDATE_SCAN'
         and scale.get('v32_source_sha256') == '619639e8e6f0cd092b1815365c1223f50e261758cb8db5635cbd79dbc1f1691f'
         and scale.get('v33_source_sha256') == source_hash and scale.get('original_native_sha256') == native_hash
         and scale.get('v32_candidates') == 39586 and scale.get('v33_candidates') == 39875
         and scale.get('new_candidates') == 289 and len(scale.get('added', [])) == 289
         and scale.get('removed_candidates') == 0,
         'Frozen-v32 versus current matcher static instruction-window candidates only; not integrated/runtime recovery counts.')
    raw = reports['raw_guards']; survey = reports['actual_ir_survey']; correlation = reports['actual_ir_native_correlation']
    gate('immutable_recovery_invocation', invocation.get('exit_code') == 0 and invocation.get('legacy_hfa_recovery') is True
         and re.fullmatch('[0-9a-f]{64}', str(core_hash))
         and invocation.get('source_binary_sha256') == raw.get('binary_sha256')
         and invocation.get('source_metadata_sha256') == raw.get('metadata_sha256'),
         'Recorded completed v33 invocation binds the exact tool, binary and metadata; later shared Core rebuilds do not alter this provenance.')
    gate('run_bound_raw_31', raw.get('status') == 'PASS_RAW_CLASS_INIT_ABI_UNUSED_RESULT_AND_DEEP_USE_GUARDS'
         and raw.get('checks') == 31 and raw.get('core_sha256') == core_hash
         and survey.get('core_sha256') == core_hash
         and raw.get('metadata_sha256') == survey.get('metadata_sha256')
         and raw.get('binary_sha256') == survey.get('binary_sha256'),
         'Actual ABI/dead-result guards and production-stage observations use the exact Core recorded for this recovery invocation.')
    correlated = correlation.get('methods', [])
    scheduling = correlation.get('scheduling_gate', {})
    gate('actual_ir_native_request_correlation', survey.get('status') == 'READ_ONLY_RAW_CLASS_INIT_STAGE_OBSERVATIONS'
         and len(survey.get('methods', [])) == 3 and survey.get('managed_aliases_at_helper') == []
         and correlation.get('status') == 'PASS_ACTUAL_CLASS_INIT_TARGETS_WITHOUT_FALSE_METHODINFO_ALIAS'
         and correlation.get('survey_sha256') == evidence['actual_ir_survey']['report_sha256']
         and correlation.get('original_native_sha256') == native_hash
         and correlation.get('recovered_managed_requests') == 5 and correlation.get('remaining_raw_requests') == 1
         and sorted(row.get('original_native_class_init_calls', -1) for row in correlated) == [1, 2, 3]
         and all(row.get('original_calls_already_absent_before_metadata_resolution') == 0
                 and row.get('surviving_raw_isil_calls') == row.get('original_native_class_init_calls') for row in correlated)
         and scheduling.get('status') == 'PASS_ORIGINAL_SCHEDULED_FIELD_LOADS_PRESERVED_AND_RAW_GUARDS_REMOVED'
         and set(scheduling.get('reader_original_input_field_loads_before_class_request', [])) == {'_bytes', '<Position>k__BackingField'}
         and scheduling.get('proven_callers_without_raw_class_flags') == ['BinaryReaderNekki::ReadBoolean']
         and sorted(row.get('addend', -1) for row in scheduling.get('unload_remaining_raw_class_flags', [])) == [0xD4, 0x122],
         'Original reader loads survive before its semantic request; all six native requests survive, five lower and one remains raw. Unload alternate-entry flags remain explicit.')
    witness = reports['native_reader']
    fixture_path = ROOT / 'analysis/reconstruction/boolean-reader-reference/fixtures.jsonl'
    fixture_hash = sha(fixture_path) if fixture_path.exists() else None
    gate('native_reader_811_8921', witness.get('status') == 'PASS_ORIGINAL_BOOLEAN_READER_RETURN_AND_POSITION_AT_INITIALIZED_RUNTIME_BOUNDARY'
         and witness.get('cases') == 811 and witness.get('checks') == 8921 and witness.get('failures') == 0
         and witness.get('native_source_sha256') == native_hash and witness.get('code_unmodified') is True
         and witness.get('readboolean_code_sha256') == EXPECTED_READER and witness.get('toboolean_code_sha256') == EXPECTED_CONVERTER
         and witness.get('fixture_sha256') == fixture_hash and witness.get('native_guest_function_replacements') == 0
         and witness.get('class_constructor_request_branch_executed') is False,
         'Both unchanged original native bodies; supplied already-initialized runtime, valid byte arrays/positions only. Original .cctor and exceptions do not execute.')
    actual = reports['actual_reader']
    baseline = reports['actual_reader_baseline']
    baseline_dll = ROOT / f'analysis/il2cpp/cpp2il-recovery-{BASELINE}/Assembly-CSharp.dll'
    gate('actual_reader_v32_negative_retained', baseline.get('status') == 'RECOVERY_EXECUTION_LIMITATION_CONFIRMED'
         and baseline.get('recovery_run') == BASELINE and baseline.get('cases') == 0 and baseline.get('checks') == 0
         and 'Unexpected reader instruction: ldstr' in (baseline.get('fatal') or '')
         and baseline.get('fixture_sha256') == fixture_hash and baseline_dll.exists()
         and baseline.get('assembly_sha256') == sha(baseline_dll),
         'Actual unchanged v32 body is rejected structurally before runtime; no baseline diagnostic body is presented as native parity.')
    binding = actual.get('native_case_binding', {})
    actual_probe = ROOT / 'src/re/RecoveredBooleanReaderProbe/Program.cs'
    gate('actual_direct_reader_811', actual.get('status') == 'PASS_ACTUAL_RECOVERED_BOOLEAN_READER_VS_ORIGINAL_NATIVE'
         and actual.get('recovery_run') == run and actual.get('cases') == 811 and actual.get('checks') == 3244
         and actual.get('failure_count') == 0 and not actual.get('fatal')
         and actual.get('fixture_sha256') == fixture_hash
         and actual.get('native_report_sha256') == evidence['native_reader']['report_sha256']
         and actual.get('assembly_sha256') == dll_hashes.get('Assembly-CSharp.dll')
         and actual.get('cil_or_source_edited') is False and actual.get('tokens_remapped') == 0 and actual.get('dynamic_clones') == 0
         and actual.get('original_constructor_calls') == 1 and actual.get('original_conversion_calls') == 1
         and actual_probe.exists() and actual.get('probe_source_sha256') == sha(actual_probe)
         and len(actual.get('structural_checks', [])) >= 2 and all(row.get('passed') is True for row in actual.get('structural_checks', []))
         and binding.get('native_cases') == 811 and binding.get('native_failures') == 0 and binding.get('native_guest_function_replacements') == 0
         and binding.get('fixture_cases') == 811 and binding.get('actual_executed_cases') == 811
         and all(binding.get(key) is True for key in ('native_evidence_bound', 'fixture_case_binding', 'all_native_cases_executed'))
         and binding.get('single_byte_value_count') == 256 and binding.get('valid_position_count') == 257
         and binding.get('valid_positions_min') == 0 and binding.get('valid_positions_max') == 256,
         'Direct unchanged recovered method on its actual type; uninitialized-instance/two-field setup is explicit. Real CLR converter and exact BitConverter constructor request remain, with no token remap or clone. Original native runtime/.cctor remains a separate boundary.')
    enum = reports['actual_enumerator']
    enum_cases = enum.get('runtime_cases', [])
    gate('actual_enumerator_5', enum.get('status') == 'PASS_ACTUAL_RECOVERED_ENUMERATOR_CALLER_FRAGMENTS'
         and enum.get('recovery_run') == run and enum.get('successful_cases') == 5 and len(enum_cases) == 5
         and enum.get('assembly_sha256') == dll_hashes.get('Assembly-CSharp.dll')
         and enum.get('production_cil_or_source_modified') is False
         and all(row.get('passed') is True and row.get('original_local_indices_retained') is True
                 and row.get('injected_default_or_initobj') is False and row.get('return_store_retargeted') is False for row in enum_cases),
         'Original caller fragment/local identities, explicit host List<object> boundaries; not complete SetStage/EH behavior.')
    regressions = {}
    newest_dll = max((path.stat().st_mtime for path in dlls), default=float('inf'))
    for name in REGRESSIONS:
        suffix = '-with-identities' if name == 'nested-tween' else ''
        relative = f'reports/recovered-{name}-{run}{suffix}.json'
        data = read(relative); entry = brief(relative)
        hashes = {key: value for key, value in data.items() if isinstance(value, str)
                  and (key == 'assembly_sha256' or key.endswith('_assembly_sha256') or key == 'firstpass_sha256')}
        bound = all(value in dll_hashes.values() for value in hashes.values())
        fresh = bool(data) and (ROOT / relative).stat().st_mtime >= newest_dll
        passed = data.get('recovery_run') == run and str(data.get('status', '')).startswith('PASS')
        passed = passed and data.get('checks', 0) > 0 and bound and fresh and not data.get('fatal') and data.get('failure_count', 0) == 0
        if name == 'nested-tween':
            pairs = data.get('initialization_pair_counts', {})
            passed = passed and data.get('cases') == 64 and data.get('identity_cases') == 240 and data.get('identity_checks') == 720 \
                and data.get('initializer_boundary_checks', 0) >= 155 and data.get('initializer_effect_count') == 1 \
                and data.get('initializer_nondefault_marker') == 0x51F2A17 \
                and data.get('throwing_initializer_requests') == 2 and data.get('throwing_initializer_effect_count') == 1 \
                and pairs.get('RecoveredNestedTweenCaller') == 1 and pairs.get('RecoveredNestedTweenCallerThrowingBoundary') == 1
        entry.update(current_dll_hash_binding=bound, fresh_after_dlls=fresh, recorded_assembly_hashes=hashes)
        regressions[name] = entry
        gate('recovered_' + name, passed, 'Existing bounded production CIL regression; retain its report-specific token/input/storage scope.')
    syntax = reports['syntax']; stack = reports['stack']; syntax_rows = syntax.get('assemblies', [])
    gate('syntax_44', len(dlls) == 44 and len(syntax_rows) == 44
         and {row.get('file') for row in syntax_rows} == set(dll_hashes)
         and all(row.get('malformed_il') == 0 for row in syntax_rows), 'CIL syntax only; helpers/unimplemented behavior can remain.')
    gate('stack_44', stack.get('status') == 'PASS_STACK_DEPTH_AND_HEADERS_ONLY'
         and stack.get('recovery_run') == run and stack.get('assembly_count') == 44
         and all(stack.get(key) == 0 for key in ('understated_max_stack', 'stack_flow_failures', 'helper_types_without_base')),
         'Stack/header checks only, not full CLR type verification.')
    batch = reports['regression_batch']
    batch_suffixes = {'syntax', 'stack', 'scalar-direct', 'scalar-isolated', 'vector', 'boolean', 'nested-tween',
                      'type-token', 'constructor', 'currency-scalars', 'aggregate-leaves', 'leaf-accessor',
                      'static-getter', 'exception-factory', 'primitive-box', 'value-this-codec', 'indirect-enumerator', 'boolean-reader'}
    gate('complete_scoped_regression_batch_18', batch.get('status') == 'PASS_SCOPED_RECOVERY_REGRESSIONS'
         and batch.get('recovery_run') == run and batch.get('include_enumerator') is True and batch.get('include_boolean_reader') is True
         and len(batch.get('probes', [])) == 18 and {row.get('suffix') for row in batch.get('probes', [])} == batch_suffixes
         and all(row.get('exit_code') == 0 for row in batch.get('probes', [])),
         'All 18 bounded runner invocations passed; individual evidence scopes and actual DLL bindings remain independently required above.')
    source_sets = {key: source_rows(reports[key]) for key in ('compiler_before', 'compiler_after', 'project_export_compiler')}
    for key, rows in source_sets.items():
        gate(key + '_both_assemblies', {row['assembly'] for row in rows} == {'Assembly-CSharp-firstpass', 'Assembly-CSharp'}
             and all(row.get('export_exit_code') == 0 and row.get('restore_exit_code') == 0
                     and isinstance(row.get('build_exit_code'), int) and isinstance(row.get('unique_compiler_diagnostic_lines'), int) for row in rows),
             'Complete source compiler outcomes, including failures; diagnostic lines are not independent root causes or completion percentages.')
    ordinary_manifest = source_manifest(reports['project_export_compiler'])
    matching_manifest = source_manifest(reports['compiler_after'])
    gate('same_source_manifest_for_both_compiler_profiles', ordinary_manifest is not None and ordinary_manifest == matching_manifest,
         'Both current compiler profiles record identical complete source-file/hash inventories; compiler outputs retain separate reference contracts.')
    before, after = compiler(BASELINE), compiler(run)
    previous = {row['assembly']: row['unique_compiler_diagnostic_lines'] for row in before}
    deltas = {row['assembly']: row['unique_compiler_diagnostic_lines'] - previous[row['assembly']]
              for row in after if row['assembly'] in previous}
    missing = [path for path in paths.values() if not (ROOT / path).exists()]
    missing += [entry['report'] for entry in regressions.values() if not (ROOT / entry['report']).exists()]
    passed = all(row['passed'] for row in gates)
    status = 'SCOPED_CLASS_GUARD_LOAD_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE' if passed else (
        'IN_PROGRESS' if missing or args.active_session else 'CLASS_GUARD_LOAD_VALIDATION_LIMITATION_CONFIRMED')
    result = dict(status=status, recovery_run=run, updated=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        evidence=evidence, gates=gates, failed_gates=[row['name'] for row in gates if not row['passed']], missing_reports=missing,
        recovered_regressions=regressions, assembly_hashes=dll_hashes, recovery_core_sha256=core_hash,
        compiler_before=before, compiler_after=after, compiler_diagnostic_line_delta=deltas,
        source_compiler_results=source_sets, static_new_candidates=scale.get('new_candidates'),
        static_candidates_are_runtime_coverage=False, active_sessions=args.active_session,
        full_clean_decompile_ready=False, whole_game_source_ready=False, portable_game_ready=False,
        limits='Static candidate counts, native initialized-runtime execution, actual IR, recovered CIL at explicit host boundaries, syntax/stack and full-source compilation have distinct scopes. '
               'Native Boolean constructor requests do not execute in its supplied initialized state. No original game .cctor/game initialization is claimed. '
               'UnloadDependencies alternate-entry class flags, GetAssetBundleSafe cold/reload paths and one raw Phi request remain unresolved. '
               'Full game behavior, full clean source and platform ports remain incomplete.')
    base = ROOT / 'reports/class-guard-load-source-recovery-v33'
    destination(ROOT, base.with_suffix('.json')).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    lines = ['# Scheduled class-guard recovery', '', status, '', 'Full clean decompilation and portable game source remain incomplete.', '',
             f"Static additional candidate windows: {scale.get('new_candidates', 'pending')}; these are not recovered/runtime method counts.", '',
             '| Complete legacy-reference source check | Firstpass diagnostics | Main diagnostics |', '|---|---:|---:|']
    for label, rows in ((BASELINE, before), (run, after)):
        counts = {row['assembly']: row['unique_compiler_diagnostic_lines'] for row in rows}
        lines.append(f"| {label} | {counts.get('Assembly-CSharp-firstpass', 'pending')} | {counts.get('Assembly-CSharp', 'pending')} |")
    lines += ['', '| Required bounded gate | Result |', '|---|---|']
    lines += [f"| {row['name']} | {'PASS' if row['passed'] else 'PENDING / FAIL'} |" for row in gates]
    lines += ['', result['limits'], '']
    destination(ROOT, base.with_suffix('.md')).write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({key: result[key] for key in ('status', 'failed_gates', 'missing_reports', 'compiler_after', 'compiler_diagnostic_line_delta')}))


if __name__ == '__main__':
    main()
