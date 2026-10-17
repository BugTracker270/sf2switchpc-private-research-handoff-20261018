"""Bind frozen v40 signature evidence; executable helper semantics stay missing."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination

RUN = 'nso-object-isinst-abi-v40'
BASE = 'nso-assembly-leaf-getter-v39'
CORE = '14232d46ca291ffb67944705e94ec5460bc8ee70c3df88ee3ef27e77b6e736d6'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--added-diagnostics-review')
    args = parser.parse_args()
    evidence, gates = {}, []

    def gate(name, passed, pending=False):
        gates.append({'name': name, 'status': 'PASS' if passed else 'PENDING' if pending else 'FAIL'})

    def read(name, relative, status=None):
        p = ROOT / relative
        d = json.loads(p.read_text(encoding='utf-8-sig'))
        evidence[name] = {'path': relative, 'sha256': sha(p), 'status': d.get('status')}
        if status:
            gate(name + '_status', d.get('status') == status)
        return d

    invocation = read('invocation', f'logs/cpp2il-{RUN}-result.json')
    gate('completed_exact_core_invocation', invocation['exit_code'] == 0 and invocation['tool_assembly_sha256']['Cpp2IL.Core.dll'] == CORE)
    output = ROOT / 'analysis/il2cpp' / ('cpp2il-recovery-' + RUN)
    assemblies = {p.name: sha(p) for p in sorted(output.glob('*.dll'))}
    gate('all44_output_assemblies', len(assemblies) == 44)
    snapshot = read('sources', 'reports/object-isinst-abi-v40-source-snapshot.json', 'PASS_IMMUTABLE_COMPLETE_CANDIDATE_SOURCE_CAPTURE')
    gate('41_frozen_sources_and_manifest_match_invocation', snapshot['source_count'] == 41 and len(snapshot['sources']) == 41
        and snapshot['core_sha256'] == CORE and snapshot['recovery_invocation_sha256'] == evidence['invocation']['sha256']
        and all(sha(ROOT / s['snapshot_path']) == s['sha256'] for s in snapshot['sources'])
        and sha(ROOT / snapshot['manifest_path']) == snapshot['manifest_sha256'])
    binaries = read('binaries', 'reports/object-isinst-abi-v40-tool-binary-snapshot.json', 'PASS_IMMUTABLE_INVOCATION_TOOL_BINARIES')
    gate('three_frozen_invocation_binaries', len(binaries['files']) == 3
        and binaries['recovery_invocation_sha256'] == evidence['invocation']['sha256']
        and all(sha(ROOT / f['path']) == f['sha256'] == invocation['tool_assembly_sha256'][Path(f['path']).name] for f in binaries['files']))
    candidate = read('candidate', 'reports/cpp2il-hfa-experimental-lock-object-isinst-abi-v40.json', 'EXPERIMENTAL_SAVED_NOT_PROMOTED')
    source_map = {s['path'].replace('\\', '/').removeprefix('refs/Cpp2IL/'): s['sha256'] for s in snapshot['sources']}
    gate('complete41_candidate_binds_frozen_source', candidate['changed_or_new_tool_paths'] == 41 and candidate['source_inventory_coverage_verified']
        and {s['path'].replace('\\', '/'): s['sha256'] for s in candidate['files']} == source_map
        and sha(ROOT / candidate['patch']) == candidate['sha256'] == snapshot['candidate_patch_sha256']
        and evidence['candidate']['sha256'] == snapshot['candidate_lock_sha256'])
    # The invocation owner records a separate frozen reverse check receipt.
    reverse_receipt = ROOT / 'reports/object-isinst-abi-v40-frozen-reverse-check.json'
    reverse = read('frozen_reverse_check', str(reverse_receipt.relative_to(ROOT)))
    gate('frozen_reverse_apply_check', reverse['exit_code'] == 0 and reverse['patch_sha256'] == candidate['sha256']
        and reverse['manifest_sha256'] == snapshot['manifest_sha256'])
    review = read('source_review', 'reports/object-isinst-abi-independent-source-review-v40.json')
    gate('seven_reviewed_source_paths_match_frozen_core', review['core_sha256'] == CORE and len(review['reviewed_sources']) == 7
        and all(source_map[s['path'].replace('\\', '/').removeprefix('refs/Cpp2IL/')] == s['sha256'] for s in review['reviewed_sources']))
    contract = read('contract', 'reports/object-isinst-abi-contract-v40.json', 'PASS_EXACT_OBJECT_ISINST_ABI_ONLY_CONTRACT')
    gate('57_independent_signature_contract_checks', contract['checks'] == 57 and contract['fatal'] is None and contract['core_sha256'] == CORE
        and all(t['status'] == 'PASS' for t in contract['tests']) and not contract['semantic_isinst_recovered'])
    production = read('production', 'reports/object-isinst-abi-production-v40.json', 'PASS_ORIGINAL_ISINST_ABI_ONLY_PRODUCTION_DATAFLOW_AND_DIAGNOSTICS')
    gate('41_original_caller_stage_checks', production['checks'] == 41 and production['fatal'] is None and production['core_sha256'] == CORE
        and all(t['passed'] for t in production['tests']) and production['expected_after_calls'] == 28
        and production['expected_after_operand_count'] == 4 and len(production['other_callers']) == 5
        and not production['class_input_emission']['emitted_class_input_evaluation_recovered'])
    native = read('native_wrapper', 'reports/native-object-isinst-abi-v40.json', 'PASS_UNCHANGED_NATIVE_ISINST_WRAPPER_AT_EXPLICIT_ASSIGNABILITY_BOUNDARY')
    gate('1034_wrapper_cases_at_explicit_supplied_boundary', native['cases'] == 1034 and native['checks'] == 8272 and native['failures'] == 0
        and native['runtime_boundary_replacement_calls'] == 1024 and native['null_object_cases_without_runtime_boundaries'] == 10
        and not native['actual_assignability_executed'] and not native['com_winrt_executed'] and native['original_code_unmodified'])
    fresh = read('fresh_output', f'reports/recovered-object-isinst-abi-{RUN}.json', 'PASS_FRESH_ABI_ONLY_CIL_CORRELATION_WITH_EXPLICIT_UNRECOVERED_SCAFFOLD_LIMITATIONS')
    gate('41_fresh_output_checks_bind_completed_invocation', fresh['checks'] == 41 and fresh['fatal'] is None and all(t['passed'] for t in fresh['tests'])
        and fresh['expected_core_sha256'] == CORE and fresh['invocation_report_sha256'] == evidence['invocation']['sha256']
        and fresh['production_report_sha256'] == evidence['production']['sha256']
        and sha(ROOT / 'src/re/RecoveredObjectIsInstAbiProbe/Program.cs') == fresh['source_sha256']
        and sha(ROOT / fresh['private_evidence']) == fresh['private_evidence_sha256']
        and not fresh['core_dependency_loaded'] and fresh['recovered_game_methods_invoked'] == 0 and not fresh['original_cil_modified'])
    gate('complete_constructor_alignment_only_dead_store_and_unused_local_changes', fresh['constructor_alignment']['matched_rows'] == 3064
        and fresh['constructor_alignment']['bijective_used_locals'] == 506 and fresh['constructor_alignment']['branches'] == 342
        and fresh['constructor_alignment']['removed_dead_zero_stores'] == 4 and fresh['constructor_alignment']['removed_unused_object_locals'] == 14
        and fresh['constructor_alignment']['relocated_operand_kinds'] == {'InlineString': 38}
        and fresh['constructor_alignment']['all_other_opcodes_operands_raw_bytes_and_control_preserved'])
    gate('actual_noop_diagnostic_and_implicit_null_limits_retained', len(fresh['diagnostic_helpers']) == 2
        and all(h['body_bytes_hex'] == '2A' and h['no_throw_or_log'] and not h['recovered_runtime_effects'] for h in fresh['diagnostic_helpers'])
        and len(fresh['implicit_result_boundary']) == 2
        and all(h['distinct_unassigned_object_results'] == 28 and h['implicit_initlocals_null']
            and h['no_op_issue_helper_does_not_stop_result_read'] for h in fresh['implicit_result_boundary'])
        and fresh['existing_implicit_defaults_unresolved'] and fresh['array_forced_analysis_does_not_match_full_output_body_recovery']
        and not fresh['semantic_isinst_recovered'] and not fresh['emitted_helper_return_semantics_recovered'])
    regression = read('regressions', f'reports/recovery-regression-{RUN}.json', 'PASS_SCOPED_RECOVERY_REGRESSIONS')
    gate('18_existing_bounded_regression_jobs', len(regression['probes']) == 18 and all(p['exit_code'] == 0 for p in regression['probes']))
    syntax = read('syntax', f'analysis/il2cpp/cil-audit-{RUN}/summary.json')
    gate('44_syntactic_audits_only', len(syntax['assemblies']) == 44 and all(not a['malformed_il'] for a in syntax['assemblies']))
    stack = read('stack', f'reports/cil-stack-audit-{RUN}.json', 'PASS_STACK_DEPTH_AND_HEADERS_ONLY')
    gate('44_stack_depth_headers_only', stack['assembly_count'] == 44 and stack['understated_max_stack'] == 0 and stack['stack_flow_failures'] == 0)
    census = read('diagnostic_scaffolds', f'reports/diagnostic-scaffolds-{RUN}.json', 'OBSERVED_DIAGNOSTIC_SCAFFOLDS_FULL_SOURCE_NOT_READY')
    gate('whole_output_diagnostic_scaffold_limits_explicit', census['assembly_count'] == 44 and census['all44_injected_helpers_are_bare_returns']
        and census['invocation_sha256'] == evidence['invocation']['sha256'] and census['recovery_core_sha256'] == CORE
        and all(assemblies[a['assembly'] + '.dll'] == a['assembly_sha256'] for a in census['assemblies'])
        and not census['diagnostic_free_bodies_semantically_validated'] and not census['full_clean_decompile_ready'])
    delta = read('compiler_comparison', 'reports/compiler-diagnostic-delta-v40.json', 'PASS_CANONICAL_COMPLETE_SOURCE_COMPILER_COMPARISON')
    gate('compiler_comparison_exact_runs', delta['before_run'] == BASE and delta['after_run'] == RUN)
    checked_reports = set()
    for assembly, row in delta['assemblies'].items():
        for run, proof in row['source_integrity'].items():
            gate('canonical_source_profile_' + assembly + '_' + run, proof['matching_reference_source_manifest_unchanged']
                and proof['restore_exit_code'] == 0 and proof['build_exit_code'] == 1)
            for role in ('summary', 'export'):
                item = proof[role]
                if item['path'] not in checked_reports:
                    gate('canonical_manifest_hash_' + item['path'], sha(ROOT / item['path']) == item['sha256'])
                    checked_reports.add(item['path'])
    added = sum(r['semantic_added_occurrences'] for r in delta['assemblies'].values())
    added_review = read('added_diagnostics_review', args.added_diagnostics_review) if args.added_diagnostics_review else None
    gate('added_semantic_diagnostics_reviewed_or_absent', added == 0 or added_review is not None
        and added_review.get('status', '').startswith('PASS_') and added_review.get('canonical_delta_sha256') == evidence['compiler_comparison']['sha256']
        and added_review.get('added_occurrences') == added, pending=added > 0 and added_review is None)
    failed = [g['name'] for g in gates if g['status'] == 'FAIL']
    pending = [g['name'] for g in gates if g['status'] == 'PENDING']
    status = ('OBJECT_ISINST_ABI_EVIDENCE_FAILED' if failed else 'OBJECT_ISINST_ABI_ADDED_DIAGNOSTIC_REVIEW_PENDING' if pending
              else 'SCOPED_OBJECT_ISINST_ABI_VALIDATED_EXECUTABLE_SEMANTICS_UNRECOVERED')
    compiler = {name: {'before': r['before_unique'], 'after': r['after_unique'], 'delta': r['delta'],
        'added_semantic_diagnostic_occurrences': r['semantic_added_occurrences']} for name, r in delta['assemblies'].items()}
    report = {'status': status, 'recovery_run': RUN, 'baseline_run': BASE,
        'updated': datetime.now(timezone.utc).isoformat(), 'recovery_core_sha256': CORE,
        'evidence': evidence, 'gates': gates, 'failed_gates': failed, 'pending_gates': pending,
        'assembly_hashes': assemblies, 'compiler': compiler,
        'diagnostic_scaffolds': census['game_assembly_counts'],
        'canonical_source_audit_reused': True, 'new_full_source_tree_hash_audit_performed': False,
        'candidate_patch': {'path': candidate['patch'], 'sha256': candidate['sha256'], 'files': 41, 'promoted': False},
        'native_wrapper_scope': {'cases': 1034, 'checks': 8272, 'supplied_assignability_calls': 1024, 'actual_assignability_executed': False},
        'contract_checks': 57, 'production_stage_checks': 41, 'fresh_output_checks': 41, 'bounded_regression_jobs': 18,
        'numeric_diagnostic_runtime_behavior': 'Injected bare ret; does not log or throw. Unassigned results can read as InitLocals defaults.',
        'fixture_console_write_line_is_full_output_helper': False,
        'semantic_isinst_recovered': False, 'class_input_evaluation_recovered': False,
        'array_forced_analysis_is_emitted_body_recovery': False,
        'full_clean_decompile_ready': False, 'whole_game_source_ready': False, 'portable_game_ready': False,
        'summary_tool_sha256': sha(Path(__file__)),
        'limits': 'This validates an exact native signature and retained IR provenance, not executable helper semantics. The actual injected diagnostic helper is a bare return. The sampled constructor has 28 unassigned helper results that can read as implicit null, and the five sampled System.Array methods remain unchanged default stubs. Original class metadata, assignability, COM/error effects and production EH are unresolved. Both complete source builds fail. Bodies without diagnostic calls remain semantically unclassified. The separate exact-class native oracle is future research and does not implement caller recovery in this run.'}
    target = destination(ROOT, ROOT / 'reports/object-isinst-abi-source-recovery-v40.json')
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    counts = Counter(g['status'] for g in gates)
    text = ['# Exact native helper signature recovery', '', status, '',
        'The original two-input Object::IsInst signature passes 57 contract checks, 41 original-caller stage checks and 41 fresh-output checks. All 18 bounded regressions pass. Native wrapper testing covers 1,034 cases / 8,272 checks at an explicitly supplied assignability boundary.', '',
        'The generated diagnostic helper is a bare return. It neither logs nor throws; the sampled constructor still has 28 unassigned results that can read as implicit null. Five sampled Array bodies remain default stubs. No helper return, class evaluation or assignability behavior has been implemented.', '',
        *[f"{name}: {r['before']:,} → {r['after']:,} compiler diagnostic lines ({r['delta']:+,}); full build fails." for name, r in compiler.items()], '',
        f"Evidence gates: {counts['PASS']} pass / {counts['PENDING']} pending / {counts['FAIL']} fail. Frozen 41-file sources and three exact tool binaries bind the historical run. Full clean decompilation and portable game source remain incomplete.", '']
    destination(ROOT, ROOT / 'reports/object-isinst-abi-source-recovery-v40.md').write_text('\n'.join(text), encoding='utf-8')
    print(json.dumps({'status': status, 'gates': dict(counts), 'failed_gates': failed, 'pending_gates': pending, 'sha256': sha(target)}))
    return 2 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
