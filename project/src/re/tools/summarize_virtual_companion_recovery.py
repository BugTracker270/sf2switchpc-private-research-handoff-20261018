"""Bind completed companion-copy recovery and explicit host XML execution scope."""
import datetime
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination

RUN = 'nso-virtual-companion-copy-v38'
CORE = '197403735d374bdde681ad203cdb3eb18e8cd9eef01897908a8c4f9e786ad99a'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    paths = dict(invocation=f'logs/cpp2il-{RUN}-result.json',
                 snapshot='reports/virtual-companion-copy-v38-source-snapshot.json',
                 binaries='reports/virtual-companion-copy-v38-tool-binary-snapshot.json',
                 review='reports/virtual-companion-independent-source-review-v38.json',
                 contract='reports/virtual-companion-copy-contract-v38.json',
                 production='reports/virtual-companion-production-v38.json',
                 actual=f'reports/recovered-virtual-companion-{RUN}.json',
                 runtime=f'reports/recovered-xml-attribute-runtime-{RUN}.json',
                 module='reports/recovered-xml-attribute-module-initializer-v38.json',
                 batch=f'reports/recovery-regression-{RUN}.json',
                 compiler=f'reports/recovered-source-profile-legacy-reference-check-{RUN}.json',
                 delta='reports/compiler-diagnostic-delta-v38.json',
                 candidate='reports/cpp2il-hfa-experimental-lock-virtual-companion-copy-v38.json')
    data = {k: json.loads((ROOT / p).read_text(encoding='utf-8-sig')) for k, p in paths.items()}
    gates = []
    def gate(name, ok):
        gates.append(dict(name=name, passed=bool(ok)))
    invocation, snapshot = data['invocation'], data['snapshot']
    gate('completed_exact_core_invocation', invocation['exit_code'] == 0 and invocation['legacy_hfa_recovery']
         and invocation['tool_assembly_sha256']['Cpp2IL.Core.dll'] == CORE == snapshot['core_sha256'])
    gate('complete_frozen_candidate_sources', len(snapshot['sources']) == 40
         and sha(ROOT / snapshot['manifest_path']) == snapshot['manifest_sha256']
         and all(sha(ROOT / x['snapshot_path']) == x['sha256'] for x in snapshot['sources']))
    gate('frozen_tool_assemblies', len(data['binaries']['files']) == 3
         and all(sha(ROOT / x['path']) == x['sha256'] for x in data['binaries']['files']))
    review = data['review']
    gate('only_companion_helper_changed', review['reviewed_changed_paths'] == ['Cpp2IL.Core/Utils/LegacyArm64VirtualDispatch.cs']
         and review['inherited_v37_helper_sources_unchanged'] == 8 and review['frozen_reverse_check_exit_code'] == 0)
    for key, count in [('contract', 276), ('production', 27)]:
        row = data[key]
        gate(key + '_same_core_and_all_checks', row['status'].startswith('PASS') and row['checks'] == count
             and row['core_sha256'] == CORE and not row['fatal'] and all(x.get('passed', x.get('status') == 'PASS') for x in row['tests']))
    actual, runtime = data['actual'], data['runtime']
    gate('actual_cil_correlation_without_execution_or_edits', actual['status'].startswith('PASS') and actual['checks'] == 19
         and actual['game_methods_invoked'] == 0 and not actual['cil_modified'] and not actual['fatal'])
    gate('unchanged_whole_helper_at_host_xml_boundary', runtime['status'].startswith('PASS')
         and runtime['cases'] == runtime['attempts'] == 26 and runtime['comparisons'] == 104
         and runtime['failures'] == 0 and runtime['actual_virtual_override_calls'] == 5
         and runtime['assembly_sha256'] == actual['actual']['AssemblyHash']
         and runtime['complete_original_cil_sha256'] == actual['actual']['BodyHash']
         and not runtime['cil_modified'] and runtime['member_substitutions'] == 0 and not runtime['native_parity_proved'])
    module = data['module']
    gate('module_initializer_absent_metadata_only', module['status'].startswith('PASS')
         and module['global_type_initializer_count'] == 0 and module['global_methods'] == []
         and module['runtime_report_sha256'] == sha(ROOT / paths['runtime']))
    for key, folder, field in [('contract', 'CompanionCopyContractProbe', 'probe_source_sha256'),
                               ('production', 'VirtualCompanionProductionProbe', 'probe_source_sha256'),
                               ('actual', 'RecoveredVirtualCompanionProbe', 'probe_source_sha256'),
                               ('runtime', 'RecoveredXmlAttributeRuntimeProbe', 'source_sha256'),
                               ('module', 'ModuleInitializerInventoryProbe', 'source_sha256')]:
        gate(key + '_probe_source_unchanged', sha(ROOT / f'src/re/{folder}/Program.cs') == data[key][field])
    batch = data['batch']
    gate('all_18_scoped_regressions', batch['status'] == 'PASS_SCOPED_RECOVERY_REGRESSIONS'
         and batch['recovery_run'] == RUN and len(batch['probes']) == 18 and all(x['exit_code'] == 0 for x in batch['probes']))
    compiler, delta = data['compiler'], data['delta']
    totals = {x['assembly']: x['unique_compiler_diagnostic_lines'] for x in compiler['assemblies']}
    gate('both_full_source_failures_recorded', totals == {'Assembly-CSharp-firstpass': 20728, 'Assembly-CSharp': 32710}
         and all(x['build_exit_code'] == 1 and x['restore_exit_code'] == x['export_exit_code'] == 0 for x in compiler['assemblies']))
    gate('canonical_complete_source_comparison', delta['status'] == 'PASS_CANONICAL_COMPLETE_SOURCE_COMPILER_COMPARISON'
         and delta['before_run'] == 'nso-runtime-helper-abi-v37' and delta['after_run'] == RUN
         and delta['compiler_diagnostic_delta'] == {'Assembly-CSharp-firstpass': -5, 'Assembly-CSharp': -14}
         and not delta['source_modified'] and not delta['core_modified'])
    candidate = data['candidate']
    gate('complete_unpromoted_candidate_bound', len(candidate['files']) == 40 and candidate['source_inventory_coverage_verified']
         and sha(ROOT / candidate['patch']) == candidate['sha256'] == snapshot['candidate_patch_sha256'])
    dlls = sorted((ROOT / f'analysis/il2cpp/cpp2il-recovery-{RUN}').glob('*.dll'))
    gate('all_44_output_assemblies_present', len(dlls) == 44)
    gate('executed_main_assembly_still_unchanged', sha(ROOT / f'analysis/il2cpp/cpp2il-recovery-{RUN}/Assembly-CSharp.dll')
         == actual['actual']['AssemblyHash'] == runtime['assembly_sha256'] == module['assembly_sha256'])
    report = dict(status='SCOPED_COMPANION_COPY_RECOVERY_VALIDATED_FULL_SOURCE_INCOMPLETE'
                  if all(x['passed'] for x in gates) else 'COMPANION_COPY_EVIDENCE_GATE_FAILED',
                  recovery_run=RUN, baseline_run='nso-runtime-helper-abi-v37',
                  updated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  core_sha256=CORE, gates=gates, failed_gates=[x['name'] for x in gates if not x['passed']],
                  summary_tool_sha256=sha(Path(__file__)),
                  evidence={k: dict(path=p, sha256=sha(ROOT / p)) for k, p in paths.items()},
                  assembly_hashes={p.name: sha(p) for p in dlls}, compiler_after=totals,
                  compiler_diagnostic_delta=delta['compiler_diagnostic_delta'],
                  source_audit='Reuse of the completed canonical comparison and its exact source/log manifests; this summarizer does not re-read every exported source file.',
                  host_xml_whole_helper=dict(cases=26, comparisons=104, observing_getter_calls=5, native_xml_parity=False),
                  full_clean_decompile_ready=False, portable_game_ready=False, whole_game_source_ready=False,
                  limits='Only paired companion copies are added to the existing virtual witness. Producer roots, void/argument signatures, general aggregate ABI and production EH remain unresolved. The unchanged complete XML helper executes at an explicit host System.Xml boundary; this is not Switch XML runtime or whole-game parity. Both complete source builds fail; diagnostic counts include cascades and are not completion percentages.')
    destination(ROOT, ROOT / 'reports/virtual-companion-source-recovery-v38.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: report[k] for k in ('status', 'failed_gates', 'compiler_after', 'compiler_diagnostic_delta')}))
    if report['failed_gates']:
        raise ValueError('Incomplete companion-copy evidence')


if __name__ == '__main__':
    main()
