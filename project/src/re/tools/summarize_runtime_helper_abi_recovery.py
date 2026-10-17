"""Bind v37 signature/liveness evidence while leaving both helper semantics unresolved."""
import argparse
import datetime
import json
from pathlib import Path
import re

from summarize_indirect_return_recovery import ROOT, REGRESSIONS, sha, read, brief, compiler
from summarize_class_guard_load_recovery import source_manifest, source_rows
from usb_boundary import destination

RUN = 'nso-runtime-helper-abi-v37'
BASELINE = 'nso-virtual-dispatch-v36'
ASSEMBLIES = {'Assembly-CSharp-firstpass', 'Assembly-CSharp'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--active-session', action='append', default=[])
    parser.add_argument('--reuse-verified-source-audit', action='store_true',
                        help='Bind the exact preserved completed source audit after report-only corrections; does not claim a new file read')
    args = parser.parse_args()
    paths = {
        'invocation': f'logs/cpp2il-{RUN}-result.json',
        'source_snapshot': 'reports/runtime-helper-abi-source-snapshot-v37.json',
        'review': 'reports/runtime-helper-abi-independent-source-review-v37.json',
        'initial_contract': 'reports/class-layout-abi-contract-v37-initial-core014d.json',
        'initial_capture': 'reports/class-layout-abi-initial-freeze-v37.json',
        'contract': 'reports/runtime-helper-abi-contract-v37.json',
        'stages': 'reports/class-layout-overflow-abi-production-ir-v37.json',
        'class_source': 'reports/class-layout-runtime-source-v37.json',
        'native_class': 'reports/native-class-layout-bool-v37.json',
        'factory_source': 'reports/exception-factory-native-source-inventory-v37.json',
        'host_metadata': 'reports/clr-type-metadata-boundary-v37.json',
        'native_prefix': 'reports/native-virtual-stream-prefix-v36.json',
        'actual_prefix': f'reports/recovered-virtual-stream-prefix-{RUN}.json',
        'actual_prefix_baseline': f'reports/recovered-virtual-stream-prefix-{BASELINE}.json',
        'prefix_fragment_runtime': f'reports/recovered-virtual-stream-prefix-runtime-{RUN}.json',
        'prefix_field_boundary': 'reports/virtual-stream-prefix-field-boundary-v37.json',
        'raw_guards': 'reports/raw-classinit-lowering-guards-v37.json',
        'phi_guards': 'reports/class-metadata-phi-production-v37.json',
        'constructor_contract': 'reports/legacy-class-init-lowering-v37-regression.json',
        'virtual_contract': 'reports/virtual-dispatch-contract-v37-final.json',
        'batch': f'reports/recovery-regression-{RUN}.json',
        'codec_initial_failure': f'reports/recovered-value-this-{RUN}-initial-failure.json',
        'batch_initial_failure': f'reports/recovery-regression-{RUN}-initial-failure.json',
        'codec_token_equivalence': 'reports/value-this-token-relocation-v37.json',
        'candidate_lock': 'reports/cpp2il-hfa-experimental-lock-runtime-helper-abi-v37-complete.json',
        'syntax': f'analysis/il2cpp/cil-audit-{RUN}/summary.json',
        'stack': f'reports/cil-stack-audit-{RUN}.json',
        'compiler_before': f'reports/recovered-source-profile-legacy-reference-check-{BASELINE}.json',
        'compiler_after': f'reports/recovered-source-profile-legacy-reference-check-{RUN}.json',
        'project_compiler': f'reports/recovered-source-profile-project-build-{RUN}.json',
        'diagnostic_delta': 'reports/compiler-diagnostic-delta-v37.json',
    }
    data = {name: read(path) for name, path in paths.items()}
    evidence = {name: brief(path) for name, path in paths.items()}
    audit_reference = None
    old_audit = {}
    if args.reuse_verified_source_audit:
        audit_path = destination(ROOT, ROOT / 'analysis/reconstruction/runtime-helper-abi-v37-audit/first-final-summary.json')
        audit_hash = sha(audit_path)
        if audit_hash != '06f0ba19f1f841b46715d66c6f4a7823248692026c382efb0d3b02b52f45cc23':
            raise ValueError('Preserved completed source-audit identity differs')
        old_audit = read(str(audit_path.relative_to(ROOT)))
        if old_audit.get('recovery_run') != RUN or old_audit.get('active_sessions'):
            raise ValueError('Source audit was incomplete or belongs to another run')
        audit_reference = dict(path=str(audit_path.relative_to(ROOT)), sha256=audit_hash,
                               verified_at=old_audit.get('updated'), new_source_file_reads=False,
                               scope='Reuse of the exact completed hash audit while only reports, probe logic and the candidate package changed; exported source was not modified.')
    core = data['invocation'].get('tool_assembly_sha256', {}).get('Cpp2IL.Core.dll')
    output = ROOT / f'analysis/il2cpp/cpp2il-recovery-{RUN}'
    dll_hashes = {path.name: sha(path) for path in sorted(output.glob('*.dll'))}
    gates = []
    def gate(name, passed, scope, state=None):
        gates.append(dict(name=name, passed=bool(passed), state=state or ('PASS' if passed else 'PENDING_OR_FAIL'), scope=scope))
    invocation, snapshot = data['invocation'], data['source_snapshot']
    frozen_review = read(snapshot.get('source_review_snapshot', '__missing__'))
    frozen_sources = snapshot.get('sources', [])
    reviewed = {row['path'].replace('\\', '/'): row['sha256'] for row in frozen_review.get('reviewed_sources', [])}
    captured = {row['path'].replace('\\', '/'): row['sha256'] for row in frozen_sources}
    gate('immutable_invocation_and_eight_source_provenance', invocation.get('exit_code') == 0
         and invocation.get('legacy_hfa_recovery') is True and re.fullmatch('[0-9a-f]{64}', str(core))
         and snapshot.get('status') == 'PASS_IMMUTABLE_V37_REVIEWED_SOURCE_CAPTURE'
         and core == snapshot.get('core_sha256') == frozen_review.get('stable_tested_core_sha256')
         and len(frozen_sources) == len(reviewed) == 8 and captured == reviewed
         and all((ROOT / row['snapshot_path']).is_file() and sha(ROOT / row['snapshot_path']) == row['sha256'] for row in frozen_sources)
         and bool(snapshot.get('source_review_snapshot')) and sha(ROOT / snapshot['source_review_snapshot']) == snapshot.get('source_review_sha256')
         and bool(snapshot.get('recovery_invocation_snapshot')) and sha(ROOT / snapshot['recovery_invocation_snapshot']) == snapshot.get('recovery_invocation_sha256') == evidence['invocation']['report_sha256']
         and bool(snapshot.get('manifest_path')) and sha(ROOT / snapshot['manifest_path']) == snapshot.get('manifest_sha256'),
         'Frozen invocation, original eight reviewed source bytes and Core identity remain verifiable after later tool edits/builds.')
    gate('independent_source_review_scope', frozen_review.get('status') == 'SOURCE_REVIEW_NO_ADDITIONAL_BLOCKER_FULL_RECOVERY_GATES_PENDING'
         and frozen_review.get('core_modified_by_review') is False and frozen_review.get('full_clean_decompile_ready') is False,
         'Read-only review certifies neither helper semantics nor complete recovered behavior.')
    initial, capture = data['initial_contract'], data['initial_capture']
    gate('separate_initial_014d_51_check_contract_preserved', initial.get('status') == 'PASS_EXACT_NATIVE_CLASS_LAYOUT_ABI_ONLY_CONTRACT'
         and initial.get('checks') == 51 and initial.get('fatal') is None
         and initial.get('core_sha256') == capture.get('core_sha256') == '014d9b9698ae1448e9a14a41c132fae3ed7efc7023fef4932dae2da8196c9a49'
         and capture.get('original_contract_sha256') == capture.get('initial_report_sha256') == evidence['initial_contract']['report_sha256']
         and capture.get('status') == 'PASS_IMMUTABLE_INITIAL_CLASS_LAYOUT_ABI_CONTRACT_CAPTURE'
         and bool(capture.get('files')) and all((ROOT / row['snapshot']).is_file() and sha(ROOT / row['snapshot']) == row['sha256'] for row in capture['files'])
         and bool(capture.get('manifest')) and sha(ROOT / capture['manifest']) == capture.get('manifest_sha256'),
         'Historical class-only Core/report/source/runnable binaries are separate from final dual-helper evidence and are never represented as final-Core tests.')
    contract = data['contract']
    gate('final_dual_helper_96_signature_contract_checks', contract.get('status') == 'PASS_EXACT_NATIVE_RUNTIME_HELPER_ABI_ONLY_CONTRACTS'
         and contract.get('checks') == 96 and contract.get('fatal') is None and contract.get('core_sha256') == core
         and all(row.get('status') == 'PASS' for row in contract.get('tests', [])) and len(contract.get('tests', [])) == 96
         and contract.get('original_binary_sha256') == invocation.get('source_binary_sha256')
         and contract.get('metadata_sha256') == invocation.get('source_metadata_sha256')
         and contract.get('probe_source_sha256') == sha(ROOT / 'src/re/RuntimeHelperAbiContractProbe/Program.cs')
         and contract.get('helper_source_sha256') == captured.get('refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64ClassLayoutAbi.cs')
         and contract.get('overflow_helper_source_sha256') == captured.get('refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64OverflowExceptionAbi.cs')
         and contract.get('native_code_executed') is False and contract.get('recovered_game_methods_executed') == 0
         and contract.get('cold_layout_effects_implemented') is False and contract.get('managed_cctor_substituted') is False
         and len(contract.get('original_reader_raw_sites', [])) == 4
         and len(contract.get('overflow_helper', {}).get('original_reader_raw_sites', [])) == 1,
         'Independent exact image/frame, signature, original X0 SSA input/result, managed-alias exclusion, clone and real-emitter diagnostic checks. Both native helper effects remain unresolved.')
    stages = data['stages']
    gate('actual_production_signature_liveness_through_emitter_input', stages.get('status') == 'PASS_SCOPED_NATIVE_HELPER_ABIS_THROUGH_PRODUCTION_EMITTER_INPUT'
         and stages.get('checks') == 51 and stages.get('core_sha256') == core
         and stages.get('source_binary_sha256') == invocation.get('source_binary_sha256')
         and stages.get('source_metadata_sha256') == invocation.get('source_metadata_sha256'),
         'Four Boolean layout calls and one base-Exception factory call preserve their original instruction/result/throw identity. Companion loads can die without suppressing either numeric helper diagnostic.')
    source, native, factory = data['class_source'], data['native_class'], data['factory_source']
    gate('official_source_exact_helper_and_bounded_original_native_evidence', source.get('status') == 'PASS_EXACT_COMMON_RUNTIME_CLASS_INIT_BOOL_ABI_AND_EFFECTS'
         and source.get('checks') == 15 and source.get('failures') == 0
         and native.get('status') == 'PASS_ORIGINAL_INITIALIZED_LAYOUT_BOOL_AND_NULL_ASSERT_BOUNDARY'
         and native.get('cases') == 512 and native.get('checks') == 3584 and native.get('code_unmodified') is True
         and native.get('guest_function_replacements') == 0
         and factory.get('status') == 'READ_ONLY_EXACT_RUNTIME_FACTORY_AND_OFFICIAL_SOURCE_PAIR'
         and factory.get('helper_bytes') == 52 and factory.get('guest_functions_executed') == 0
         and contract.get('native_source_report_sha256') == evidence['class_source']['report_sha256']
         and contract.get('native_oracle_report_sha256') == evidence['native_class']['report_sha256']
         and contract.get('overflow_native_source_report_sha256') == evidence['factory_source']['report_sha256'],
         'Official runtime source distinguishes layout initialization from managed .cctor. Native512 initialized-layout cases exclude cold effects; factory identification is source/disassembly evidence, not execution.')
    host = data['host_metadata']
    gate('host_metadata_observation_cctor_boundary_retained', host.get('status') == 'PASS_HOST_METADATA_OBSERVATION_WITH_CCTOR_CANARIES'
         and host.get('checks') == 60,
         'Separate authored host metadata/.cctor canaries are contract research; no helper lowering or original caller execution follows from them.')
    for name, count, core_key in (('raw_guards', 31, 'core_sha256'), ('phi_guards', 73, 'core_sha256'), ('constructor_contract', 120, 'core_assembly_sha256'), ('virtual_contract', 218, 'core_sha256')):
        report = data[name]
        gate(name, str(report.get('status', '')).startswith('PASS') and report.get('checks') == count and report.get(core_key) == core,
             'Current final Core regression in its independently documented synthetic/native/CLR boundary.')
    actual, prior = data['actual_prefix'], data['actual_prefix_baseline']
    native_prefix = data['native_prefix']
    prior_dll = ROOT / f'analysis/il2cpp/cpp2il-recovery-{BASELINE}/Assembly-CSharp-firstpass.dll'
    gate('unchanged_baseline_prefix_execution_blocker_preserved', prior.get('recovery_run') == BASELINE
         and prior.get('status') == 'ACTUAL_VIRTUAL_PREFIX_CORRELATED_EXECUTION_LIMITATIONS'
         and prior_dll.is_file() and sha(prior_dll) == prior.get('assembly_sha256')
         and prior.get('actual_callvirt_sites') == 2 and prior.get('actual_direct_readbyte_sites') == 0
         and len(prior.get('helper_zero_placeholders', [])) == 1 and prior.get('runtime_performed') is False and prior.get('runtime_cases') == 0,
         'The unchanged v36 DLL retained a live companion-load diagnostic/placeholder. Comparing it with v37 does not retroactively certify baseline execution.')
    fixture = ROOT / native_prefix.get('fixture_path', '__missing__')
    gate('unchanged_native_prefix_fixture_802_cases_9624_checks', native_prefix.get('status') == 'PASS_UNCHANGED_NATIVE_STREAM_OVERRIDE_AND_VIRTUAL_READER_PREFIX'
         and native_prefix.get('cases') == 802 and native_prefix.get('checks') == 9624 and native_prefix.get('failures') == 0
         and native_prefix.get('original_instructions_unmodified') is True and native_prefix.get('native_guest_functions_replaced') == 0
         and native_prefix.get('native_source_sha256') == sha(ROOT / 'analysis/nso/main-uncompressed.nso')
         and fixture.is_file() and sha(fixture) == native_prefix.get('fixture_sha256'),
         'Historical unchanged native prefix/override inputs are hash-bound; their supplied object/vtable/initialized-metadata boundary does not execute recovered helpers.')
    prefix_bound = actual.get('recovery_run') == RUN and actual.get('assembly_sha256') == dll_hashes.get('Assembly-CSharp-firstpass.dll') \
        and actual.get('status') == 'ACTUAL_VIRTUAL_PREFIX_CORRELATED_EXECUTION_LIMITATIONS' \
        and actual.get('native_report_sha256') == evidence['native_prefix']['report_sha256'] \
        and actual.get('fixture_sha256') == native_prefix.get('fixture_sha256') and actual.get('native_evidence_bound') is True \
        and actual.get('native_fixture_cases') == 802 and actual.get('actual_prefix_cfg_shape_proven') is True \
        and actual.get('actual_native_virtual_identity_preserved') is True and actual.get('actual_callvirt_sites') == 2 \
        and actual.get('actual_direct_readbyte_sites') == 0 and actual.get('cil_or_source_modified') is False \
        and actual.get('call_opcodes_rewritten') == actual.get('member_substitutions') == actual.get('tokens_remapped') == actual.get('dynamic_clones') == 0 \
        and actual.get('fatal') is None and actual.get('probe_source_sha256') == sha(ROOT / 'src/re/RecoveredVirtualStreamPrefixProbe/Program.cs')
    gate('actual_current_dll_prefix_correlation', prefix_bound,
         'Read-only current original CIL keeps two exact Stream.ReadByte callvirt sites and original header-field identities; helper-free entry correlation alone is not execution.')
    private_cil_path = actual.get('evidence', {}).get('private_actual_cil_path')
    whole_cil = read(private_cil_path) if private_cil_path else {}
    gate('unchanged_complete_reader_cil_provenance', bool(private_cil_path)
         and (ROOT / private_cil_path).is_file() and sha(ROOT / private_cil_path) == actual.get('private_cil_evidence_sha256')
         and whole_cil.get('body_sha256') == actual.get('actual_body_il_sha256'),
         'Complete actual CIL evidence binds the unchanged DLL/body. Its ldstr operands are metadata tokens, not resolved string text; this gate makes no text-count claim from that encoding.')
    final_stages = [row for row in stages.get('stages', []) if row.get('stage') == 'emitter-input']
    final_stage = final_stages[0] if len(final_stages) == 1 else {}
    helper_boundaries = {'B04F60': len(final_stage.get('helper_calls', [])), 'B4D960': len(final_stage.get('overflow_calls', []))}
    gate('complete_reader_unresolved_helper_emitter_input_boundaries', helper_boundaries == {'B04F60': 4, 'B4D960': 1}
         and stages.get('game_methods_invoked') == 0 and stages.get('helper_semantics_recovered') is False,
         'Actual full production analysis retains four numeric layout calls and one numeric factory call at emitter input. Independent real-emitter fixtures preserve their diagnostics; neither helper effect is implemented or executed.')
    fragment = data['prefix_fragment_runtime']
    mappings = fragment.get('member_token_mappings', [])
    controls = fragment.get('synthetic_dispatch_controls', [])
    gate('isolated_actual_prefix_fragment_802_cases_7218_comparisons', fragment.get('status') == 'PASS_ACTUAL_RECOVERED_PREFIX_FRAGMENT_VS_ORIGINAL_NATIVE'
         and fragment.get('recovery_run') == RUN and fragment.get('review_only') is False
         and fragment.get('runtime_performed') is True and fragment.get('runtime_cases') == fragment.get('fragment_invocations_attempted') == 802
         and fragment.get('comparisons') == 7218 and fragment.get('failure_count') == 0 and fragment.get('fatal') is None
         and fragment.get('observed_virtual_override_calls') == 1604 and fragment.get('observed_eof_returns') == 276
         and fragment.get('assembly_sha256') == dll_hashes.get('Assembly-CSharp-firstpass.dll')
         and fragment.get('original_body_il_sha256') == actual.get('actual_body_il_sha256')
         and fragment.get('correlation_report_sha256') == evidence['actual_prefix']['report_sha256']
         and fragment.get('native_report_sha256') == evidence['native_prefix']['report_sha256']
         and fragment.get('fixture_sha256') == native_prefix.get('fixture_sha256')
         and fragment.get('probe_source_sha256') == sha(ROOT / 'src/re/RecoveredVirtualStreamPrefixRuntimeProbe/Program.cs')
         and fragment.get('original_prefix_instructions') == 47 and fragment.get('original_declared_locals_retained') == 95
         and fragment.get('recovered_fragment_dynamic_clones') == 1 and fragment.get('member_token_remap_sites') == len(mappings) == 6
         and all(row.get('exact_original_identity') is True for row in mappings)
         and fragment.get('local_signature_reencoded') is True and fragment.get('branch_offsets_relocated') == fragment.get('inserted_return_fences') == 1
         and fragment.get('source_opcode_changes') == fragment.get('original_member_substitutions') == fragment.get('helper_substitutions') == 0
         and fragment.get('original_dll_unchanged') is True and fragment.get('actual_whole_read_invocations') == fragment.get('game_instance_constructors_invoked') == 0
         and len(controls) == 2 and {row.get('opcode') for row in controls} == {'callvirt', 'call'} and all(row.get('passed') is True for row in controls)
         and 'skipVisibility=true' in fragment.get('access_bypass', ''),
         'An isolated clone retains47 original instructions/95 locals/exact members, remaps6 member sites and one entry branch, and inserts one return at the original Length-store fence. Real host observed MemoryStream inputs compare802 original native cases. This is not whole Read or helper execution.')
    field_boundary = data['prefix_field_boundary']
    gate('prefix_other_fields_null_reference_boundary', field_boundary.get('status') == 'PASS_OTHER_FIELDS_ARE_TWO_NULL_BYTE_ARRAY_REFERENCES'
         and field_boundary.get('recovery_run') == RUN and field_boundary.get('assembly_sha256') == fragment.get('assembly_sha256')
         and field_boundary.get('other_field_count') == 2 and field_boundary.get('other_field_types') == ['System.Byte[]', 'System.Byte[]']
         and field_boundary.get('other_fields_initially_null') is True and field_boundary.get('game_equals_invoked') is False
         and field_boundary.get('game_instance_constructor_invoked') is False and field_boundary.get('whole_read_invoked') is False,
         'The fragment comparison of other receiver fields cannot invoke a custom game Equals; the only other fields are two supplied null byte-array references.')
    gate('inspection_fragment_and_whole_reader_execution_are_distinct', prefix_bound and actual.get('runtime_performed') is False
         and actual.get('runtime_cases') == actual.get('actual_game_methods_invoked') == 0 and bool(actual.get('execution_limitations')),
         'LIMITATION: the read-only inspection keeps zero cases; the separate47-instruction fragment executor has802. The complete reader and unresolved layout/factory helpers have not executed.',
         state='LIMITATION' if prefix_bound else 'PENDING_OR_FAIL')
    regressions, additional_missing = {}, []
    for name in REGRESSIONS + ['scalars', 'enumerator', 'boolean-reader']:
        suffix = '-with-identities' if name == 'nested-tween' else ''
        path = f'reports/recovered-{name}-{RUN}{suffix}.json'
        row = read(path)
        if not row: additional_missing.append(path)
        bound = {key: value for key, value in row.items() if isinstance(value, str)
                 and key != 'pinned_reference_assembly_sha256'
                 and (key == 'assembly_sha256' or key.endswith('_assembly_sha256') or key == 'firstpass_sha256')}
        passed = row.get('recovery_run') == RUN and str(row.get('status', '')).startswith('PASS') and not row.get('fatal') \
            and row.get('failure_count', 0) == 0 and bool(bound) and all(value in dll_hashes.values() for value in bound.values())
        passed = passed and (row.get('successful_cases') == 5 if name == 'enumerator' else row.get('checks', 0) > 0)
        if name == 'value-this':
            passed = passed and row.get('cases') == 342 and row.get('checks') == 2052 and row.get('exact_null_getter_boundary_proved') is True \
                and row.get('null_boundary_checks') == 342 and row.get('active_detector_callback_executed') is False \
                and row.get('cil_or_source_edited') is False and row.get('tokens_remapped') == 0 \
                and row.get('probe_source_sha256') == sha(ROOT / 'src/re/RecoveredValueThisProbe/Program.cs') \
                and row.get('diagnostic_token_relocation_equivalent') is True and row.get('relocated_diagnostic_string_tokens') == 1 \
                and len(row.get('scope_guard_controls', [])) == 4 and all(part.get('passed') is True for part in row['scope_guard_controls']) \
                and {part.get('control') for part in row['scope_guard_controls']} == {'exact_original_null_getter_branch',
                    'non_null_detector_rejected_without_invocation', 'altered_getter_copy_rejected_without_execution', 'altered_branch_copy_rejected_without_execution'}
        if name == 'boolean-reader':
            passed = passed and row.get('cases') == 811 and row.get('checks') == 3244 and row.get('cil_or_source_edited') is False \
                and row.get('tokens_remapped') == 0 and row.get('native_case_binding', {}).get('all_native_cases_executed') is True
        regressions[name] = dict(report=path, report_sha256=sha(ROOT / path) if row else None, recorded_dll_hashes=bound,
                                historical_reference_assembly_sha256=row.get('pinned_reference_assembly_sha256'),
                                status=row.get('status'), cases=row.get('cases'), checks=row.get('checks'), scope=row.get('scope'))
        gate('recovered_' + name, passed, 'Current-run unchanged recovered CIL within the original independent member/native/fixture boundaries; DLL hashes are explicit.')
    batch = data['batch']
    codec_failure = data['codec_initial_failure']
    gate('initial_codec_and_batch_failures_retained', codec_failure.get('status') == 'RECOVERY_EXECUTION_LIMITATION_CONFIRMED'
         and codec_failure.get('recovery_run') == RUN and codec_failure.get('cases') == codec_failure.get('checks') == 0
         and codec_failure.get('assembly_sha256') == dll_hashes.get('Assembly-CSharp-firstpass.dll')
         and bool(codec_failure.get('fatal')) and data['batch_initial_failure'].get('status') == 'FAIL_SCOPED_RECOVERY_REGRESSIONS',
         'Initial strict-byte token rejection is retained. The corrected fixture proves one relocated ldstr token resolves to identical text with every other byte/local/branch/getter unchanged; it does not rewrite runtime tokens or execute the active callback.')
    token_proof = data['codec_token_equivalence']
    gate('codec_historical_reference_and_one_same_text_token_relocation', token_proof.get('status') == 'PASS_PINNED_CODEC_LOGIC_IDENTICAL_EXCEPT_RESOLVED_USERSTRING_TOKEN'
         and token_proof.get('compared_cil_rows') == 106 and token_proof.get('changed_rows') == 1
         and token_proof.get('changed_offset') == 195 and token_proof.get('changed_operand_bytes') == 4
         and token_proof.get('reference_assembly_sha256') == sha(prior_dll)
         and token_proof.get('after_assembly_sha256') == dll_hashes.get('Assembly-CSharp-firstpass.dll')
         and token_proof.get('actual_codec_cases') == 342 and token_proof.get('actual_codec_checks') == 2052
         and token_proof.get('local_signature_and_header_identical') is True and token_proof.get('game_cil_or_source_modified') is False
         and token_proof.get('runtime_tokens_remapped') == 0 and token_proof.get('active_callback_recovered') is False
         and token_proof.get('source_sha256') == sha(ROOT / 'src/re/RecoveredValueThisProbe/Program.cs'),
         'A historical v36 assembly is a pinned reference, not a current-run output. All106 rows match except one same-text diagnostic ldstr token; unchanged current CIL executes342 original absent-detector fixtures and active callback recovery remains false.')
    expected = {'syntax', 'stack', 'scalar-direct', 'scalar-isolated', 'vector', 'boolean', 'nested-tween', 'type-token', 'constructor',
                'currency-scalars', 'aggregate-leaves', 'leaf-accessor', 'static-getter', 'exception-factory', 'primitive-box', 'value-this-codec', 'indirect-enumerator', 'boolean-reader'}
    gate('all_18_established_regression_invocations', batch.get('status') == 'PASS_SCOPED_RECOVERY_REGRESSIONS'
         and batch.get('recovery_run') == RUN and len(batch.get('probes', [])) == 18
         and {row.get('suffix') for row in batch['probes']} == expected and all(row.get('exit_code') == 0 for row in batch['probes']),
         'All established bounded probes must actually complete; prefix inspection is separate and no helper semantic execution is included.')
    syntax, stack = data['syntax'], data['stack']
    syntax_rows = syntax.get('assemblies', [])
    gate('syntax_44', len(dll_hashes) == len(syntax_rows) == 44 and {row.get('file') for row in syntax_rows} == set(dll_hashes)
         and Path(syntax.get('source_directory', '')).resolve() == output.resolve() and all(row.get('malformed_il') == 0 for row in syntax_rows),
         'Encoding syntax only; unresolved helpers and source/type errors can remain.')
    gate('stack_44', stack.get('status') == 'PASS_STACK_DEPTH_AND_HEADERS_ONLY' and stack.get('recovery_run') == RUN
         and stack.get('assembly_count') == 44 and all(stack.get(key) == 0 for key in ('understated_max_stack', 'stack_flow_failures', 'helper_types_without_base')),
         'Stack/header consistency only, without operand type, helper semantics or game startup equivalence.')
    source_integrity, hash_cache = {}, {}
    for key in ('compiler_before', 'compiler_after', 'project_compiler'):
        report = data[key]; rows = source_rows(report); expected_run = BASELINE if key == 'compiler_before' else RUN
        experiment = 'source-profile-project-build' if key == 'project_compiler' else 'source-profile-legacy-reference-check'
        manifest = source_manifest(report); prefix = f'analysis/il2cpp/source-profile-project-build-{expected_run}/'
        gate(key + '_complete_profiles', report.get('recovery_run') == expected_run and report.get('experiment') == experiment
             and {row.get('assembly') for row in rows} == ASSEMBLIES and all(row.get('export_exit_code') == row.get('restore_exit_code') == 0
                 and isinstance(row.get('build_exit_code'), int) and isinstance(row.get('unique_compiler_diagnostic_lines'), int) for row in rows),
             'Both complete exported assembly source builds retain exact original compiler failures.')
        failures, verified = [], 0
        if manifest and not args.active_session and args.reuse_verified_source_audit:
            previous = old_audit.get('complete_source_integrity', {}).get(key, {})
            if old_audit.get('evidence', {}).get(key, {}).get('report_sha256') != evidence[key]['report_sha256'] \
                    or previous.get('verification_deferred_for_active_work') is not False \
                    or previous.get('failures') or previous.get('verified_files') != sum(len(files) for files in manifest.values()):
                failures.append(dict(reason='completed audit or exact source-manifest report identity differs'))
            else:
                verified = previous['verified_files']
        elif manifest and not args.active_session:
            for files in manifest.values():
                for relative, digest in files.items():
                    if not relative.replace('\\', '/').startswith(prefix): failures.append(dict(path=relative, reason='wrong run/profile path')); continue
                    path = destination(ROOT, ROOT / relative)
                    if relative not in hash_cache: hash_cache[relative] = sha(path) if path.is_file() else None
                    if hash_cache[relative] == digest: verified += 1
                    else: failures.append(dict(path=relative, reason='actual source hash differs'))
        source_integrity[key] = dict(verified_files=verified, failures=failures, verification_deferred_for_active_work=bool(args.active_session),
                                    completed_audit_reference=audit_reference)
        gate(key + '_complete_source_hashes', bool(manifest) and verified > 0 and not failures,
             'Every complete source file was independently hash-verified in this invocation or the exact cited completed audit; current full source-manifest report bytes must match. This tool never rewrites exported source.')
    gate('both_current_compiler_profiles_use_identical_source', source_manifest(data['compiler_after']) is not None
         and source_manifest(data['compiler_after']) == source_manifest(data['project_compiler']), 'Both compiler reference profiles use the same complete source-file/hash inventory.')
    before, after = compiler(BASELINE), compiler(RUN)
    old = {row['assembly']: row['unique_compiler_diagnostic_lines'] for row in before}
    counts = {row['assembly']: row['unique_compiler_diagnostic_lines'] for row in after}
    delta = {name: counts[name] - old[name] for name in ASSEMBLIES if name in old and name in counts}
    comparison = data['diagnostic_delta']; comparisons = comparison.get('assemblies', {})
    gate('canonical_complete_compiler_delta', comparison.get('status') == 'PASS_CANONICAL_COMPLETE_SOURCE_COMPILER_COMPARISON'
         and comparison.get('before_run') == BASELINE and comparison.get('after_run') == RUN
         and comparison.get('source_modified') is False and comparison.get('core_modified') is False
         and set(comparisons) == set(old) == set(counts) == ASSEMBLIES and comparison.get('compiler_diagnostic_delta') == delta
         and all(row.get('before_unique') == old[name] and row.get('after_unique') == counts[name] and row.get('delta') == delta[name]
                 and set(row.get('source_integrity', {})) == {BASELINE, RUN} and all(part.get('matching_reference_source_manifest_unchanged') is True
                     and part.get('diagnostic_source_files_hash_verified', 0) > 0 for part in row['source_integrity'].values()) for name, row in comparisons.items()),
         'Canonical complete-source compiler counts include cascades and are not percentages or independent missing-method counts.')
    candidate = data['candidate_lock']
    candidate_patch = ROOT / candidate.get('patch', '__missing__')
    candidate_files = {'refs/Cpp2IL/' + row['path'].replace('\\', '/'): row['sha256'] for row in candidate.get('files', [])}
    gate('separate_complete_40_file_unpromoted_candidate_identity', candidate.get('status') == 'EXPERIMENTAL_SAVED_NOT_PROMOTED'
         and len(candidate_files) == 40 and candidate_patch.is_file() and sha(candidate_patch) == candidate.get('sha256')
         and candidate.get('patch', '').replace('\\', '/') == 'src/re/tool-patches/cpp2il-sf2-hfa-experimental-runtime-helper-abi-v37-complete.patch'
         and all(candidate_files.get(name) == digest for name, digest in captured.items()),
         'Separate candidate patch bytes and eight reviewed source identities are pinned independently of later live tool edits. The patch remains experimental and does not establish full recovered portability.')
    missing = [path for path in paths.values() if not (ROOT / path).exists()] + additional_missing
    status = 'SCOPED_NATIVE_HELPER_ABIS_VALIDATED_HELPER_SEMANTICS_UNRESOLVED' if all(row['passed'] for row in gates) else (
        'IN_PROGRESS' if missing or args.active_session else 'NATIVE_HELPER_ABI_VALIDATION_LIMITATION_CONFIRMED')
    report = dict(status=status, recovery_run=RUN, baseline_run=BASELINE, updated=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        recovery_core_sha256=core, evidence=evidence, gates=gates, failed_gates=[row['name'] for row in gates if not row['passed']],
        limitation_gates=[row['name'] for row in gates if row['state'] == 'LIMITATION'], missing_reports=missing,
        assembly_hashes=dll_hashes, recovered_regressions=regressions, complete_source_integrity=source_integrity,
        compiler_before=before, compiler_after=after, compiler_diagnostic_line_delta=delta,
        source_compiler_results={key: source_rows(data[key]) for key in ('compiler_before', 'compiler_after', 'project_compiler')},
        prefix_before=dict(callvirt=prior.get('actual_callvirt_sites'), placeholders=len(prior.get('helper_zero_placeholders', [])), runtime_performed=prior.get('runtime_performed')),
        prefix_after=dict(callvirt=actual.get('actual_callvirt_sites'), direct=actual.get('actual_direct_readbyte_sites'),
            runtime_eligible=actual.get('runtime_eligible'), runtime_performed=actual.get('runtime_performed'), runtime_cases=actual.get('runtime_cases'),
            placeholders=actual.get('helper_zero_placeholders', []), unresolved_calls=actual.get('unresolved_prefix_calls', []),
            limitations=actual.get('execution_limitations', []), scope=actual.get('scope')),
        isolated_prefix_fragment=dict(runtime_performed=fragment.get('runtime_performed'), cases=fragment.get('runtime_cases'), comparisons=fragment.get('comparisons'),
            dynamic_clones=fragment.get('recovered_fragment_dynamic_clones'), member_token_remap_sites=fragment.get('member_token_remap_sites'),
            branch_offsets_relocated=fragment.get('branch_offsets_relocated'), inserted_return_fences=fragment.get('inserted_return_fences'),
            original_members_substituted=fragment.get('original_member_substitutions'), whole_read_invocations=fragment.get('actual_whole_read_invocations'),
            host_boundary=fragment.get('host_boundary'), access_bypass=fragment.get('access_bypass'), scope=fragment.get('scope')),
        unpromoted_candidate=dict(patch=candidate.get('patch'), sha256=candidate.get('sha256'), files=len(candidate_files), promoted=False),
        complete_reader_unresolved_emitter_input_helpers=helper_boundaries,
        active_sessions=args.active_session, summary_tool_sha256=sha(Path(__file__)), full_clean_decompile_ready=False,
        completed_source_audit_reuse=audit_reference,
        whole_game_source_ready=False, portable_game_ready=False, class_layout_semantics_recovered=False,
        exception_factory_semantics_recovered=False, managed_helper_translation_executed=False,
        native_layout_initialized_path_cases=native.get('cases'),
        limits='Only signatures/liveness and original input/result identities are recovered for these two helpers. Numeric diagnostics, factory result/throw, cold metadata setup, native message conversion/construction, locks, cleanup and unwind remain unresolved. '
               'Prefix inspection, native initialized-path fixtures, authored emitter/host contracts and established recovered-code probes are separate scopes. No complete reader/game execution or full clean source is claimed.')
    base = ROOT / 'reports/runtime-helper-abi-source-recovery-v37'
    destination(ROOT, base.with_suffix('.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    lines = ['# Native runtime helper ABI checkpoint', '', status, '',
        'Two native helper signatures now retain their real X0 inputs/results without phantom MethodInfo arguments. Both semantic helper calls remain unresolved diagnostics; full clean decompilation and portable source remain incomplete.', '',
        '| Complete matching-reference source check | Firstpass diagnostics | Main diagnostics |', '|---|---:|---:|']
    for name, rows in ((BASELINE, before), (RUN, after)):
        totals = {row['assembly']: row['unique_compiler_diagnostic_lines'] for row in rows}
        lines.append(f"| {name} | {totals.get('Assembly-CSharp-firstpass', 'pending')} | {totals.get('Assembly-CSharp', 'pending')} |")
    lines += ['', f"Required evidence gates: {sum(row['passed'] for row in gates)}/{len(gates)}. Failed gates: {', '.join(report['failed_gates']) or 'none'}.", '',
        'Independent scopes: initial class-only51 checks retained separately; final dual-helper96 contract checks; actual production51 checks; exact native initialized-layout512 cases/3,584 checks. These counts do not certify cold helper effects.', '',
        f"Read-only prefix inspection: two callvirt sites; eligibility `{actual.get('runtime_eligible')}`; runtime performed `{actual.get('runtime_performed')}`; cases `{actual.get('runtime_cases')}`.", '',
        f"Separate isolated prefix execution: {fragment.get('runtime_cases', 'pending')} cases / {fragment.get('comparisons', 'pending')} comparisons. One clone retains47 original instructions and95 locals, remaps6 exact-member sites/one branch and adds one return at the Length-store fence. Host MemoryStream and private-field access are explicit boundaries. Complete Read invocations: {fragment.get('actual_whole_read_invocations', 'pending')}.", '', report['limits'], '']
    lines += [f"Unpromoted candidate: `{candidate.get('patch')}`; SHA-256 `{candidate.get('sha256')}`;{len(candidate_files)} files. Initial codec/batch failures remain preserved separately.", '']
    destination(ROOT, base.with_suffix('.md')).write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'failed_gates', 'missing_reports', 'limitation_gates', 'compiler_after', 'compiler_diagnostic_line_delta')}))


if __name__ == '__main__':
    main()
