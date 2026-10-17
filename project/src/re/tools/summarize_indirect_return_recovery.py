"""Strict scoped indirect-return evidence summary; failed source builds stay failed."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination

ROOT = Path(__file__).resolve().parents[3]
RUN = 'nso-enumerator-return-v32'
BASELINE = 'nso-static-getter-v31b'
REGRESSIONS = [
    'aggregate-leaves', 'boolean-setter', 'constructor', 'currency-scalars',
    'exception-factory', 'leaf-accessor', 'nested-tween', 'primitive-box',
    'scalars-isolated', 'static-getter', 'type-handle-token', 'value-this', 'vector3',
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(relative):
    path = ROOT / relative
    return json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}


def brief(relative):
    data = read(relative)
    return dict(report=relative, report_sha256=sha(ROOT / relative) if data else None,
                **{k: v for k, v in data.items() if v is None or isinstance(v, (str, int, bool, float))})


def compiler(run):
    data = read(f'reports/recovered-source-profile-legacy-reference-check-{run}.json')
    return [{key: row.get(key) for key in ('assembly', 'build_exit_code', 'unique_compiler_diagnostic_lines')}
            for row in data.get('assemblies', [])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-name', default=RUN)
    parser.add_argument('--active-session', action='append', default=[])
    args = parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+', args.run_name):
        parser.error('Only lowercase run identifiers are allowed')
    run = args.run_name
    inputs = {
        'production_adapter_guards': 'reports/indirect-return-helper-v32.json',
        'original_native_return': 'reports/enumerator-native-return-v31.json',
        'native_cleanup_tail': 'reports/indirect-return-tail-provenance-v32.json',
        'prototype_only': 'reports/enumerator-pipeline-v32-native-prototype.json',
        'actual_baseline': f'reports/recovered-enumerator-{BASELINE}.json',
        'actual_recovered_enumerator': f'reports/recovered-enumerator-{run}.json',
        'raw_class_init_guards': 'reports/raw-classinit-lowering-guards-v32.json',
        'raw_class_init_survey': 'reports/raw-classinit-stage-survey-v32-after.json',
        'raw_class_init_native_correlation': 'reports/raw-classinit-native-correlation-v32-after.json',
        'class_constructor_contract': 'reports/legacy-class-init-lowering-v32-regression.json',
        'exact_fde_api': 'reports/exact-body-range-and-closed-enumerator-v32.json',
        'native_cfg_recognition': 'reports/cfg-initialization-recognition-v31.json',
        'syntax': f'analysis/il2cpp/cil-audit-{run}/summary.json',
        'stack': f'reports/cil-stack-audit-{run}.json',
        'compiler_before': f'reports/recovered-source-profile-legacy-reference-check-{BASELINE}.json',
        'compiler_after': f'reports/recovered-source-profile-legacy-reference-check-{run}.json',
    }
    reports = {key: read(path) for key, path in inputs.items()}
    evidence = {key: brief(path) for key, path in inputs.items()}
    gates = []

    def gate(name, ok, scope):
        gates.append(dict(name=name, passed=bool(ok), scope=scope))

    helper = reports['production_adapter_guards']
    helper_path = ROOT / 'refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64IndirectReturns.cs'
    gate('production_adapter_23', helper.get('status') == 'PASS_EXACT_NATIVE_INDIRECT_RETURN_ADAPTER_AND_ATOMIC_REJECTIONS'
         and helper.get('checks') == 23 and helper.get('failures') == 0
         and helper_path.exists() and helper.get('helper_source_sha256') == sha(helper_path),
         'Actual production conversion plus atomic negative copied-IR guards; not game execution.')
    native = reports['original_native_return']
    image_path = ROOT / 'analysis/nso/main-uncompressed.nso'
    native_hash = sha(image_path) if image_path.exists() else None
    gate('original_native_6_cases_36_checks', native.get('status') == 'PASS_ORIGINAL_NATIVE_INDIRECT_ENUMERATOR_RETURN_ONLY'
         and native.get('cases') == 6 and native.get('checks') == 36 and native.get('code_unmodified') is True
         and native.get('native_source_sha256') == native_hash,
         'Two unchanged native bodies and supplied opaque runtime tables; SetStage itself was not executed.')
    tail = reports['native_cleanup_tail']
    gate('native_cleanup_tail', str(tail.get('status', '')).startswith('PASS') and tail.get('checks', 0) >= 5,
         'Original FDE-backed cleanup/Dispose address provenance, separate from emitted CIL.')
    baseline = reports['actual_baseline']
    gate('baseline_execution_failure_retained', baseline.get('status') == 'RECOVERY_EXECUTION_LIMITATION_CONFIRMED'
         and baseline.get('successful_cases') == 0 and baseline.get('recovery_run') == BASELINE,
         'Prior actual source fragments fail; no counterfactual store-retarget control is promoted.')
    actual = reports['actual_recovered_enumerator']
    output_dir = ROOT / f'analysis/il2cpp/cpp2il-recovery-{run}'
    dlls = sorted(output_dir.glob('*.dll')) if output_dir.exists() else []
    dll_hashes = {p.name: sha(p) for p in dlls}
    main_dll = output_dir / 'Assembly-CSharp.dll'
    actual_cases = actual.get('runtime_cases', [])
    gate('actual_recovered_caller_fragments', actual.get('status') == 'PASS_ACTUAL_RECOVERED_ENUMERATOR_CALLER_FRAGMENTS'
         and actual.get('recovery_run') == run and actual.get('successful_cases') == 5 and len(actual_cases) == 5
         and actual.get('production_cil_or_source_modified') is False and actual.get('member_boundary_count') == 5
         and actual.get('assembly_sha256') == dll_hashes.get('Assembly-CSharp.dll')
         and all(row.get('passed') is True and row.get('original_local_indices_retained') is True
                 and row.get('injected_default_or_initobj') is False and row.get('return_store_retargeted') is False for row in actual_cases)
         and {row.get('element_count') for row in actual_cases if not row.get('version_mutation')} == {0, 1, 3, 8}
         and sum(row.get('version_mutation') is True for row in actual_cases) == 1,
         'Original caller byte fragments/local identities with five explicit host List<object> member boundaries; harness loop is not whole SetStage.')
    raw = reports['raw_class_init_guards']; survey = reports['raw_class_init_survey']; correlation = reports['raw_class_init_native_correlation']
    gate('raw_class_init_31', raw.get('status') == 'PASS_RAW_CLASS_INIT_ABI_UNUSED_RESULT_AND_DEEP_USE_GUARDS'
         and raw.get('checks') == 31, 'Exact ABI capture, dead result and deep-use rejection fixtures.')
    gate('raw_class_init_survey_binding', survey.get('status') == 'READ_ONLY_RAW_CLASS_INIT_STAGE_OBSERVATIONS'
         and len(survey.get('methods', [])) == 3 and survey.get('managed_aliases_at_helper') == []
         and survey.get('core_sha256') == raw.get('core_sha256')
         and correlation.get('survey_sha256') == evidence['raw_class_init_survey']['report_sha256'],
         'Three actual caller-stage observations linked to their native correlation report.')
    correlated_methods = correlation.get('methods', [])
    gate('native_class_requests_preserved', correlation.get('status') == 'PASS_ACTUAL_CLASS_INIT_TARGETS_WITHOUT_FALSE_METHODINFO_ALIAS'
         and correlation.get('recovered_managed_requests') == 5 and correlation.get('remaining_raw_requests') == 1
         and sorted(row.get('original_native_class_init_calls', -1) for row in correlated_methods) == [1, 2, 3]
         and all(row.get('original_calls_already_absent_before_metadata_resolution') == 0
                 and row.get('surviving_raw_isil_calls') == row.get('original_native_class_init_calls') for row in correlated_methods)
         and correlation.get('original_native_sha256') == native_hash,
         'All six original native requests survive; five typed requests lower, one ambiguous origin remains raw.')
    contract = reports['class_constructor_contract']
    gate('class_constructor_effect_contract', contract.get('status') == 'PASS_LEGACY_CLASS_INIT_TYPED_LOWERING_AND_CLR_CONTRACT'
         and contract.get('cases') == 80 and contract.get('checks') == 120,
         'Host .cctor side effects, once/concurrent semantics and throwing contract; not original game .cctor execution.')
    bounds = reports['exact_fde_api']; cfg = reports['native_cfg_recognition']
    gate('bounds_api_regression', str(bounds.get('status', '')).startswith('PASS') and bounds.get('checks', 0) >= 15,
         'Bounds-only original address proof; no generic layout classifier or alias changes.')
    gate('cfg_matcher_regression', cfg.get('status') == 'PASS_SCOPED_CFG_INITIALIZATION_RECOGNITION' and cfg.get('checks') == 26,
         'Bounded native initialization witnesses and conservative mutation rejection.')

    regressions = {}
    latest_dll_time = max((p.stat().st_mtime for p in dlls), default=float('inf'))
    for name in REGRESSIONS:
        suffix = '-with-identities' if name == 'nested-tween' else ''
        relative = f'reports/recovered-{name}-{run}{suffix}.json'
        data = read(relative); entry = brief(relative)
        hashes = {key: value for key, value in data.items() if isinstance(value, str)
                  and (key == 'assembly_sha256' or key.endswith('_assembly_sha256') or key == 'firstpass_sha256')}
        binding_ok = all(value in dll_hashes.values() for value in hashes.values())
        fresh = bool(data) and (ROOT / relative).stat().st_mtime >= latest_dll_time
        passed = data.get('recovery_run') == run and str(data.get('status', '')).startswith('PASS') and data.get('checks', 0) > 0
        passed = passed and binding_ok and fresh and not data.get('fatal') and data.get('failure_count', 0) == 0
        if name == 'nested-tween':
            pairs = data.get('initialization_pair_counts', {})
            passed = passed and data.get('cases') == 64 and data.get('identity_cases') == 240 and data.get('identity_checks') == 720 \
                and data.get('initializer_boundary_checks', 0) >= 155 and data.get('initializer_effect_count') == 1 \
                and data.get('initializer_nondefault_marker') == 0x51F2A17 \
                and data.get('throwing_initializer_requests') == 2 and data.get('throwing_initializer_effect_count') == 1 \
                and pairs.get('RecoveredNestedTweenCaller') == 1 and pairs.get('RecoveredNestedTweenCallerThrowingBoundary') == 1
        entry.update(assembly_hash_binding=hashes, current_assembly_hashes_match=binding_ok, fresh_after_dlls=fresh,
                     binding_scope='assembly hashes plus exact run and fresh report' if hashes else 'exact run, fresh report and recorded method/slice hashes; no whole-assembly hash supplied by this probe')
        regressions[name] = entry
        gate('recovered_' + name, passed, 'Scoped existing production CIL regression; retain its individual token/input/storage boundaries.')
    audit = reports['syntax']; stack = reports['stack']
    syntax_rows = audit.get('assemblies', [])
    gate('syntax_44_assemblies', len(syntax_rows) == 44 and len(dlls) == 44
         and {row.get('file') for row in syntax_rows} == set(dll_hashes)
         and all(row.get('malformed_il') == 0 for row in syntax_rows),
         'CIL syntax only; diagnostic helpers and unimplemented behavior may remain.')
    gate('stack_44_assemblies', stack.get('status') == 'PASS_STACK_DEPTH_AND_HEADERS_ONLY' and stack.get('recovery_run') == run
         and stack.get('assembly_count') == 44 and all(stack.get(key) == 0 for key in ('understated_max_stack', 'stack_flow_failures', 'helper_types_without_base')),
         'Stack depth/header checks; not full CLR type verification or gameplay.')
    before = compiler(BASELINE); after = compiler(run)
    required_assemblies = {'Assembly-CSharp-firstpass', 'Assembly-CSharp'}
    for label, rows in [('before', before), ('after', after)]:
        gate('both_source_compiler_counts_' + label, {row['assembly'] for row in rows} == required_assemblies
             and all(isinstance(row['build_exit_code'], int) and isinstance(row['unique_compiler_diagnostic_lines'], int) for row in rows),
             'Complete two-assembly source checks, including failures; counts are diagnostic lines and cascades, not completion percentages.')
    valid = all(row['passed'] for row in gates)
    missing = [path for path in inputs.values() if not (ROOT / path).exists()]
    missing += [entry['report'] for entry in regressions.values() if not (ROOT / entry['report']).exists()]
    status = 'SCOPED_INDIRECT_RETURN_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE' if valid else (
        'IN_PROGRESS' if missing or args.active_session else 'INDIRECT_RETURN_VALIDATION_LIMITATION_CONFIRMED')
    result = dict(status=status, updated=datetime.datetime.now(datetime.timezone.utc).isoformat(), recovery_run=run,
                  evidence=evidence, gates=gates, failed_gates=[row['name'] for row in gates if not row['passed']], missing_reports=missing,
                  recovered_regressions=regressions, compiler_before=before, compiler_after=after,
                  actual_recovered_cases=actual.get('successful_cases'), actual_structural_checks=actual.get('structural_checks'), actual_runtime_checks=actual.get('runtime_checks'),
                  cil_assemblies_audited=len(syntax_rows), syntax_valid=next(row['passed'] for row in gates if row['name'] == 'syntax_44_assemblies'),
                  stack_status=stack.get('status', 'NOT_STARTED'), native_cases=native.get('cases'), native_checks=native.get('checks'),
                  prototype_is_production_evidence=False, active_sessions=args.active_session, assembly_hashes=dll_hashes,
                  whole_game_source_ready=False, full_clean_decompile_ready=False, portable_game_ready=False,
                  limits='Original native execution, copied-IR prototypes, actual recovered CIL at explicit host boundaries, syntax/stack checks and whole-source compilation have distinct scopes. '
                         'The reviewed 24-byte reference-enumerator SRET binding is one pinned native caller/body/metadata family, not general generic layout or ARM64 ABI completion. '
                         'Raw class initialization retains semantic constructor requests only under exact ABI/dead-result/type-origin proof; one ambiguous origin remains unresolved. '
                         'Caller fragments preserve original local indices, input/member instructions and stores; harness looping and host List<object> are explicit boundaries. '
                         'They do not execute all of SetStage, combat, native runtime/.cctor bodies, save logic, or whole-game behavior. '
                         'Full clean source and all ports remain incomplete; compiler diagnostic counts include cascades.')
    base = ROOT / 'reports/indirect-return-source-recovery-v32'
    destination(ROOT, base.with_suffix('.json')).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    lines = ['# Reviewed indirect-return recovery', '', status, '', 'Full clean decompilation and portable game source remain incomplete.', '',
             f"Actual recovered caller fragments: {actual.get('successful_cases', 'pending')}/5 cases; "
             f"{actual.get('structural_checks', 'pending')} structural and {actual.get('runtime_checks', 'pending')} runtime checks.", '',
             '| Complete source check | Firstpass diagnostic lines | Main diagnostic lines |', '|---|---:|---:|']
    for label, rows in [(BASELINE, before), (run, after)]:
        counts = {row['assembly']: row['unique_compiler_diagnostic_lines'] for row in rows}
        lines.append(f"| {label} | {counts.get('Assembly-CSharp-firstpass', 'pending')} | {counts.get('Assembly-CSharp', 'pending')} |")
    lines += ['', '| Required scoped gate | Result |', '|---|---|']
    lines += [f"| {row['name']} | {'PASS' if row['passed'] else 'PENDING / FAIL'} |" for row in gates]
    lines += ['', 'Evidence remains separated:', '',
              '- Original ARM64 bodies: unchanged native buffer-return execution and FDE/call-site provenance.',
              '- Copied-IR experiment: explanatory prototype, never promoted to a production execution pass.',
              '- Actual production CIL: original caller fragments with explicit host member/input/local boundaries.',
              '- Whole-source builds: complete compiler results remain separate from scoped runtime success.', '', result['limits'], '']
    destination(ROOT, base.with_suffix('.md')).write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({key: result[key] for key in ('status', 'failed_gates', 'compiler_after', 'missing_reports')}))


if __name__ == '__main__':
    main()
