"""Bind ordinary plain-frame recovery to immutable builds and scoped evidence."""
import argparse
import datetime
import json
import re
from pathlib import Path

from summarize_indirect_return_recovery import ROOT, REGRESSIONS, sha, read, brief, compiler
from summarize_class_guard_load_recovery import source_manifest, source_rows
from usb_boundary import destination

RUN = 'nso-plain-frame-cfg-v35'
BASELINE = 'nso-class-origin-phi-v34'
PROVENANCE = 'reports/plain-frame-build-provenance-v35.json'
REVIEW = 'reports/plain-frame-ordinary-cfg-independent-review-v35.json'
SOURCES = [
    'refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64ValueThisThunks.cs',
    'refs/Cpp2IL/Cpp2IL.Core/InstructionSets/NewArmV8InstructionSet.cs',
    'refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64CfgInitializationPattern.cs',
]


def capture_provenance():
    """Capture once, while compiled outputs and reviewed inputs still agree."""
    target = ROOT / PROVENANCE
    if target.exists():
        return
    invocation_path = f'logs/cpp2il-{RUN}-result.json'
    invocation = read(invocation_path)
    review = read(REVIEW)
    core = invocation.get('tool_assembly_sha256', {}).get('Cpp2IL.Core.dll')
    expected = {row['path']: row['sha256'] for row in review.get('reviewed_sources', [])}
    if invocation.get('exit_code') != 0 or not re.fullmatch('[0-9a-f]{64}', str(core)):
        raise ValueError('Completed recovery invocation is required before capture')
    for path in ('refs/Cpp2IL/Cpp2IL.Core/bin/Release/net10.0/Cpp2IL.Core.dll',
                 'refs/Cpp2IL/Cpp2IL/bin/Release/net10.0/Cpp2IL.Core.dll'):
        if sha(ROOT / path) != core:
            raise ValueError('Current output differs from immutable recovery Core')
    snapshots = []
    for relative in SOURCES:
        source = ROOT / relative
        digest = sha(source)
        if expected.get(relative) != digest:
            raise ValueError('Reviewed production source changed: ' + relative)
        snapshot = destination(ROOT, ROOT / 'analysis/reference/plain-frame-v35' / source.name)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        if snapshot.exists() and snapshot.read_bytes() != source.read_bytes():
            raise ValueError('Refusing to replace immutable production source snapshot')
        snapshot.write_bytes(source.read_bytes())
        snapshots.append(dict(source=relative, snapshot=str(snapshot.relative_to(ROOT)), sha256=digest))
    result = dict(status='PASS_RECORDED_REVIEWED_SOURCE_AND_RECOVERY_BUILD_BINDING',
                  recovery_run=RUN, core_sha256=core, sources=snapshots,
                  invocation_sha256=sha(ROOT / invocation_path), review_sha256=sha(ROOT / REVIEW))
    destination(ROOT, target).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-provenance', action='store_true')
    args = parser.parse_args()
    if args.capture_provenance:
        capture_provenance()
    paths = {
        'invocation': f'logs/cpp2il-{RUN}-result.json',
        'provenance': PROVENANCE,
        'review': REVIEW,
        'plain_range': 'reports/plain-frame-range-guards-v35.json',
        'general_range_regression': 'reports/exact-body-range-and-closed-enumerator-v35.json',
        'cfg_regression': 'reports/cfg-initialization-recognition-v35.json',
        'ordinary_native_correlation': 'reports/plain-frame-ordinary-native-correlation-v35.json',
        'actual_getsafe_cil': f'reports/recovered-class-phi-{RUN}.json',
        'raw_guards': 'reports/raw-classinit-lowering-guards-v35.json',
        'phi_guards': 'reports/class-metadata-phi-production-v35.json',
        'constructor_contract': 'reports/legacy-class-init-lowering-v35-regression.json',
        'scheduling': 'reports/class-guard-scheduling-v35.json',
        'batch': f'reports/recovery-regression-{RUN}.json',
        'syntax': f'analysis/il2cpp/cil-audit-{RUN}/summary.json',
        'stack': f'reports/cil-stack-audit-{RUN}.json',
        'compiler_before': f'reports/recovered-source-profile-legacy-reference-check-{BASELINE}.json',
        'compiler_after': f'reports/recovered-source-profile-legacy-reference-check-{RUN}.json',
        'project_compiler': f'reports/recovered-source-profile-project-build-{RUN}.json',
        'diagnostic_delta': 'reports/compiler-diagnostic-delta-v35.json',
    }
    data = {key: read(path) for key, path in paths.items()}
    evidence = {key: brief(path) for key, path in paths.items()}
    invocation = data['invocation']
    core = invocation.get('tool_assembly_sha256', {}).get('Cpp2IL.Core.dll')
    dlls = sorted((ROOT / f'analysis/il2cpp/cpp2il-recovery-{RUN}').glob('*.dll'))
    hashes = {p.name: sha(p) for p in dlls}
    gates = []

    def gate(name, passed, scope):
        gates.append(dict(name=name, passed=bool(passed), scope=scope))

    provenance = data['provenance']
    snapshots = provenance.get('sources', [])
    reviewed = {row['path']: row['sha256'] for row in data['review'].get('reviewed_sources', [])}
    gate('immutable_review_build_binding', invocation.get('exit_code') == 0
         and invocation.get('legacy_hfa_recovery') is True
         and re.fullmatch('[0-9a-f]{64}', str(core))
         and provenance.get('status') == 'PASS_RECORDED_REVIEWED_SOURCE_AND_RECOVERY_BUILD_BINDING'
         and provenance.get('recovery_run') == RUN
         and provenance.get('core_sha256') == core and len(snapshots) == 3
         and {s.get('source') for s in snapshots} == set(SOURCES) == set(reviewed)
         and provenance.get('invocation_sha256') == evidence['invocation']['report_sha256']
         and provenance.get('review_sha256') == evidence['review']['report_sha256']
         and all(s['sha256'] == reviewed.get(s['source']) and (ROOT / s['snapshot']).is_file()
                 and sha(ROOT / s['snapshot']) == s['sha256'] for s in snapshots),
         'Reviewed source snapshots and immutable completed invocation, independent of future shared builds.')
    review = data['review']
    gate('independent_source_review', review.get('no_additional_blocking_source_issue_found') is True
         and review.get('source_review_only') is True
         and review.get('compatibility_scope', {}).get('new_ordinary_extension_excludes_eh_bearing_frames') is True
         and review.get('compatibility_scope', {}).get('legacy_selected_zPLR_bodies') == 12,
         'Source inspection only; the older selected route retains twelve unverified exception-bearing bodies.')
    plain = data['plain_range']
    tests = plain.get('tests', [])
    gate('plain_frame_api_and_parser', str(plain.get('status', '')).startswith('PASS')
         and len(tests) >= 26 and all(t.get('status') == 'PASS' for t in tests)
         and plain.get('loaded_core_sha256') == core
         and plain.get('source_binary_sha256') == invocation.get('source_binary_sha256')
         and plain.get('source_metadata_sha256') == invocation.get('source_metadata_sha256'),
         'Real exact ranges, malformed in-memory parser fixtures, opt-in, cached negative queries and alias invariance.')
    bounds = data['general_range_regression']; cfg = data['cfg_regression']
    gate('old_bounds_15', bounds.get('status') == 'PASS_ORIGINAL_POINTER_FDE_RANGE_API_AND_CLOSED_ENUMERATOR_EVIDENCE'
         and bounds.get('checks') == 15 and bounds.get('loaded_core_sha256') == core,
         'Existing exact-range and closed-reference Enumerator evidence, without broadening indirect-return recovery.')
    gate('unchanged_native_cfg_26', cfg.get('status') == 'PASS_SCOPED_CFG_INITIALIZATION_RECOGNITION'
         and cfg.get('checks') == 26 and len(cfg.get('tests', [])) == 26
         and all(t.get('status') == 'PASS' for t in cfg['tests']),
         'Unchanged bounded native matcher and mutation negatives; production integration requires its own correlation.')
    for key, count, hash_key in (('raw_guards', 31, 'core_sha256'),
                                  ('phi_guards', 73, 'core_sha256'),
                                  ('constructor_contract', 120, 'core_assembly_sha256')):
        report = data[key]
        gate(key, str(report.get('status', '')).startswith('PASS')
             and report.get('checks') == count and report.get(hash_key) == core,
             'Current production Core; ABI/provenance and real CLR constructor effects retain their distinct scopes.')
    scheduling = data['scheduling']
    gate('unchanged_scheduling_58', str(scheduling.get('status', '')).startswith('PASS')
         and scheduling.get('checks') == 58,
         'Existing bounded scheduling recognizer positive and negative fixtures.')
    correlation = data['ordinary_native_correlation']
    selected = correlation.get('selected', [])
    gate('new_ordinary_production_correlation', correlation.get('status') == 'PASS_PLAIN_FRAME_ORDINARY_NATIVE_AND_PRODUCTION_ISIL_CORRELATION'
         and correlation.get('core_sha256') == core and correlation.get('checks') == 4
         and correlation.get('binary_sha256') == invocation.get('source_binary_sha256')
         and correlation.get('metadata_sha256') == invocation.get('source_metadata_sha256')
         and correlation.get('plain_parser_report_sha256') == evidence['plain_range']['report_sha256']
         and correlation.get('value_this_source_sha256') == reviewed.get(SOURCES[0])
         and correlation.get('instruction_set_source_sha256') == reviewed.get(SOURCES[1])
         and correlation.get('cfg_matcher_source_sha256') == reviewed.get(SOURCES[2])
         and correlation.get('core_source_edited_by_probe') is False
         and correlation.get('ir_rewritten_by_probe') is False and correlation.get('guest_execution_performed') is False
         and len(selected) == correlation.get('accepted_ordinary_bodies', 0) > 0
         and all(row.get('cie_augmentation') == 'zR' and row.get('raw_bytes_equal_original') is True
                 and row.get('newly_accepted_cfg_guards')
                 and row.get('original_native_constructor_requests', 0) == row.get('actual_managed_constructor_requests', -1) > 0
                 and row.get('remaining_raw_requests') == row.get('remaining_class_flag_loads') == 0
                 and row.get('raw_effect_sequence_equal') is True
                 and row.get('baseline_exclusion_requires_exact_native_witness_and_single_load') is True
                 and row.get('non_scaffolding_raw_effects', 0) > 0
                 and row.get('typed_semantic_call_sites_preserved') is True for row in selected),
         'New ordinary path must be exercised and correlated with original native requests/effects; unsupported reloads and EH remain explicit.')
    cil = data['actual_getsafe_cil']; cil_after = cil.get('after', {})
    gate('actual_unchanged_getsafe_cil', cil.get('status') == 'PASS_ACTUAL_GETSAFE_CLASS_INITIALIZER_CIL_CORRELATION'
         and cil.get('recovery_run') == RUN and cil.get('baseline_run') == 'nso-class-guard-load-v33'
         and cil.get('checks') == 13 and cil.get('assembly_sha256') == hashes.get('Assembly-CSharp-firstpass.dll')
         and (cil_after.get('ConstructorRequests'), cil_after.get('RawHelperDiagnostics'),
              cil_after.get('PostConstructorFieldReloads'), cil_after.get('RawClassFlagDiagnostics')) == (3, 0, 2, 4)
         and cil.get('recovered_cil_or_source_modified') is False and cil.get('tokens_remapped') == 0
         and cil.get('game_methods_invoked') == cil.get('class_initializers_invoked') == 0
         and cil.get('whole_method_executed') is False,
         'Actual current DLL retains three exact constructor requests and required field reloads; four unsupported flags remain. Inspection only, not whole-method execution.')
    regressions = {}
    for name in REGRESSIONS + ['scalars', 'enumerator', 'boolean-reader']:
        suffix = '-with-identities' if name == 'nested-tween' else ''
        path = f'reports/recovered-{name}-{RUN}{suffix}.json'
        report = read(path)
        bound = {k: v for k, v in report.items() if isinstance(v, str)
                 and (k == 'assembly_sha256' or k.endswith('_assembly_sha256') or k == 'firstpass_sha256')}
        passed = report.get('recovery_run') == RUN and str(report.get('status', '')).startswith('PASS')
        passed = passed and not report.get('fatal') and report.get('failure_count', 0) == 0
        passed = passed and bool(bound) and all(v in hashes.values() for v in bound.values())
        if name == 'enumerator':
            passed = passed and report.get('successful_cases') == 5 and report.get('production_cil_or_source_modified') is False
        else:
            passed = passed and report.get('checks', 0) > 0
        if name == 'boolean-reader':
            passed = passed and report.get('cases') == 811 and report.get('checks') == 3244
            passed = passed and report.get('cil_or_source_edited') is False and report.get('tokens_remapped') == 0
            passed = passed and report.get('native_case_binding', {}).get('all_native_cases_executed') is True
        regressions[name] = dict(report=path, sha256=sha(ROOT / path) if report else None, recorded_assembly_hashes=bound)
        gate('recovered_' + name, passed, 'Unchanged current-run recovered CIL; original fixture/member/native boundaries remain in force.')
    batch = data['batch']
    expected = {'syntax', 'stack', 'scalar-direct', 'scalar-isolated', 'vector', 'boolean', 'nested-tween',
                'type-token', 'constructor', 'currency-scalars', 'aggregate-leaves', 'leaf-accessor',
                'static-getter', 'exception-factory', 'primitive-box', 'value-this-codec', 'indirect-enumerator', 'boolean-reader'}
    gate('complete_regression_batch_18', batch.get('status') == 'PASS_SCOPED_RECOVERY_REGRESSIONS'
         and batch.get('recovery_run') == RUN and len(batch.get('probes', [])) == 18
         and {r.get('suffix') for r in batch.get('probes', [])} == expected
         and all(r.get('exit_code') == 0 for r in batch.get('probes', [])), 'All scoped invocations completed; this is not gameplay coverage.')
    syntax = data['syntax']; stack = data['stack']; rows = syntax.get('assemblies', [])
    gate('syntax_44', len(dlls) == len(rows) == 44 and {r.get('file') for r in rows} == set(hashes)
         and Path(syntax.get('source_directory', '')).resolve() == (ROOT / f'analysis/il2cpp/cpp2il-recovery-{RUN}').resolve()
         and all(r.get('malformed_il') == 0 for r in rows), 'CIL encoding only; not full type or logic verification.')
    gate('stack_44', stack.get('status') == 'PASS_STACK_DEPTH_AND_HEADERS_ONLY'
         and stack.get('recovery_run') == RUN and stack.get('assembly_count') == 44
         and all(stack.get(k) == 0 for k in ('understated_max_stack', 'stack_flow_failures', 'helper_types_without_base')),
         'Stack/header consistency only; native cleanup and runtime type validity are separate.')
    for key in ('compiler_before', 'compiler_after', 'project_compiler'):
        rows = source_rows(data[key])
        expected_run = BASELINE if key == 'compiler_before' else RUN
        expected_experiment = 'source-profile-project-build' if key == 'project_compiler' else 'source-profile-legacy-reference-check'
        prefix = f'analysis/il2cpp/source-profile-project-build-{expected_run}/'
        gate(key + '_both_assemblies', {r.get('assembly') for r in rows} == {'Assembly-CSharp-firstpass', 'Assembly-CSharp'}
             and data[key].get('recovery_run') == expected_run and data[key].get('experiment') == expected_experiment
             and all(r.get('export_exit_code') == r.get('restore_exit_code') == 0
                     and isinstance(r.get('build_exit_code'), int) and isinstance(r.get('unique_compiler_diagnostic_lines'), int) for r in rows)
             and all(row.get('source_files') and all(item.get('path', '').replace('\\', '/').startswith(prefix)
                                                    for item in row['source_files']) for row in data[key].get('assemblies', [])),
             'Both complete source builds are recorded, including failure; no methods are stubbed to obtain a build.')
    manifest = source_manifest(data['compiler_after'])
    gate('identical_source_both_profiles', manifest is not None and manifest == source_manifest(data['project_compiler']),
         'Matching and host reference checks use exactly the same exported source files.')
    before = compiler(BASELINE); after = compiler(RUN)
    old = {row['assembly']: row['unique_compiler_diagnostic_lines'] for row in before}
    delta = {row['assembly']: row['unique_compiler_diagnostic_lines'] - old[row['assembly']]
             for row in after if row['assembly'] in old}
    comparison = data['diagnostic_delta']; comparisons = comparison.get('assemblies', {})
    counts = {row['assembly']: row['unique_compiler_diagnostic_lines'] for row in after}
    gate('canonical_compiler_delta_and_source_integrity', comparison.get('status') == 'PASS_CANONICAL_COMPLETE_SOURCE_COMPILER_COMPARISON'
         and comparison.get('before_run') == BASELINE and comparison.get('after_run') == RUN
         and comparison.get('source_modified') is False and comparison.get('core_modified') is False
         and set(comparisons) == set(old) == set(counts) == {'Assembly-CSharp-firstpass', 'Assembly-CSharp'}
         and all(row.get('before_unique') == old[name] and row.get('after_unique') == counts[name]
                 and row.get('delta') == delta[name]
                 and set(row.get('source_integrity', {})) == {BASELINE, RUN}
                 and all(integrity.get('matching_reference_source_manifest_unchanged') is True
                         and integrity.get('diagnostic_source_files_hash_verified', 0) > 0
                         for integrity in row['source_integrity'].values()) for name, row in comparisons.items()),
         'Both authoritative totals and unchanged diagnostic source hashes are independently rechecked; diagnostic deltas include cascades.')
    missing = [p for p in paths.values() if not (ROOT / p).exists()]
    passed = all(g['passed'] for g in gates)
    result = dict(status='SCOPED_PLAIN_FRAME_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE' if passed else 'IN_PROGRESS' if missing else 'PLAIN_FRAME_VALIDATION_LIMITATION_CONFIRMED',
                  recovery_run=RUN, updated=datetime.datetime.now(datetime.timezone.utc).isoformat(), evidence=evidence,
                  recovery_core_sha256=core, assembly_hashes=hashes, gates=gates,
                  failed_gates=[g['name'] for g in gates if not g['passed']], missing_reports=missing,
                  regressions=regressions, compiler_before=before, compiler_after=after, compiler_diagnostic_line_delta=delta,
                  full_clean_decompile_ready=False, whole_game_source_ready=False, portable_game_ready=False,
                  limits='Only the new ordinary extension requires an exact plain zR frame with empty FDE augmentation. The older selected route still contains twelve zPLR bodies with unverified exception semantics. Bounds do not recover cleanup, personalities, action tables or exception edges. Unsupported cold/reload shapes remain explicit. Scope-bound parser, constructor, native/IR and runtime evidence are separate; no global method-recovery percentage is inferred. Both complete game source assemblies must compile and undergo behavioral verification before any clean-decompile or portable-game claim.')
    base = ROOT / 'reports/plain-frame-source-recovery-v35'
    destination(ROOT, base.with_suffix('.json')).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    lines = ['# Ordinary plain-frame recovery', '', result['status'], '',
             'Full clean decompilation and portable source remain incomplete.', '',
             '| Complete matching-reference source check | Firstpass diagnostics | Main diagnostics |', '|---|---:|---:|']
    for run, rows in ((BASELINE, before), (RUN, after)):
        counts = {row['assembly']: row['unique_compiler_diagnostic_lines'] for row in rows}
        lines.append(f"| {run} | {counts.get('Assembly-CSharp-firstpass', 'pending')} | {counts.get('Assembly-CSharp', 'pending')} |")
    lines += ['', f"Required gates: {sum(g['passed'] for g in gates)}/{len(gates)} passed.", '', result['limits'], '']
    destination(ROOT, base.with_suffix('.md')).write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('status', 'failed_gates', 'missing_reports', 'compiler_after', 'compiler_diagnostic_line_delta')}))


if __name__ == '__main__':
    main()
