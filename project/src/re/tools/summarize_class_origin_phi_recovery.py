"""Bind v34 exact-class Phi proof, unchanged emitted CIL and complete-source outcomes."""
import argparse
import datetime
import json
from pathlib import Path

from summarize_indirect_return_recovery import ROOT, REGRESSIONS, sha, read, brief, compiler
from summarize_class_guard_load_recovery import source_manifest, source_rows
from usb_boundary import destination

RUN='nso-class-origin-phi-v34'
BASELINE='nso-class-guard-load-v33'
KFR='refs/Cpp2IL/Cpp2IL.Core/Analysis/KeyFunctionRecovery.cs'
EXPECTED_KFR='9064474aed01a88a959be70f338e7597ed46b69c6dea487a58ae13a3e9d3a5f0'
PROVENANCE='reports/class-origin-phi-build-provenance-v34.json'


def capture_provenance():
    output=ROOT/PROVENANCE
    if output.exists():
        return
    invocation_path=ROOT/f'logs/cpp2il-{RUN}-result.json'
    invocation=read(str(invocation_path.relative_to(ROOT)))
    review=read('reports/class-metadata-phi-independent-review-v34.json')
    production=read('reports/class-metadata-phi-production-v34.json')
    core=invocation.get('tool_assembly_sha256',{}).get('Cpp2IL.Core.dll')
    source=ROOT/KFR
    build_log=ROOT/'logs/cpp2il-class-metadata-phi-v34-build.log'
    if sha(source)!=EXPECTED_KFR or review.get('source_sha256')!=EXPECTED_KFR:
        raise ValueError('Reviewed source differs from the observed serial build snapshot')
    if invocation.get('exit_code')!=0 or core!=production.get('core_sha256'):
        raise ValueError('Completed invocation and production fixture Core hashes differ')
    built_core=ROOT/'refs/Cpp2IL/Cpp2IL.Core/bin/Release/net10.0/Cpp2IL.Core.dll'
    cli_core=ROOT/'refs/Cpp2IL/Cpp2IL/bin/Release/net10.0/Cpp2IL.Core.dll'
    if sha(built_core)!=core or sha(cli_core)!=core:
        raise ValueError('Current build output no longer matches the completed immutable invocation')
    text=build_log.read_text(encoding='utf-8-sig')
    if not all(s in text for s in ('Build succeeded.','0 Warning(s)','0 Error(s)')):
        raise ValueError('Successful serial build evidence absent')
    snapshot=destination(ROOT,ROOT/'analysis/reference/class-origin-v34/KeyFunctionRecovery.cs')
    snapshot.parent.mkdir(parents=True,exist_ok=True)
    if snapshot.exists() and snapshot.read_bytes()!=source.read_bytes():
        raise ValueError('Immutable source snapshot already exists with different bytes')
    snapshot.write_bytes(source.read_bytes())
    result=dict(status='PASS_RECORDED_SERIAL_BUILD_SOURCE_AND_INVOCATION_BINDING',recovery_run=RUN,
        source_snapshot=str(snapshot.relative_to(ROOT)),source_sha256=EXPECTED_KFR,core_sha256=core,
        recovery_invocation_sha256=sha(invocation_path),build_log=str(build_log.relative_to(ROOT)),build_log_sha256=sha(build_log),
        independent_source_review_sha256=sha(ROOT/'reports/class-metadata-phi-independent-review-v34.json'),
        production_fixture_sha256=sha(ROOT/'reports/class-metadata-phi-production-v34.json'),
        historical_proposal_sha256=sha(ROOT/'reports/class-metadata-phi-proposal-v34-expanded.json'),
        historical_proposal_core_sha256=read('reports/class-metadata-phi-proposal-v34-expanded.json').get('core_sha256'),
        scope='Immutable recorded source copy and observed successful serial build bind the independently reviewed KFR snapshot to the exact Core used by production fixtures and completed recovery. This is recorded build provenance, not an independent bit-for-bit rebuild. The proposal30 is historical independent-checker evidence on old v33 Core and is not relabeled as current production execution.')
    destination(ROOT,output).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-provenance',action='store_true')
    parser.add_argument('--active-session',action='append',default=[])
    args=parser.parse_args()
    if args.capture_provenance:capture_provenance()
    paths={
        'invocation':f'logs/cpp2il-{RUN}-result.json','build_provenance':PROVENANCE,
        'production':'reports/class-metadata-phi-production-v34.json',
        'proposal':'reports/class-metadata-phi-proposal-v34-expanded.json',
        'independent_review':'reports/class-metadata-phi-independent-review-v34.json',
        'raw_guards':'reports/raw-classinit-lowering-guards-v34.json',
        'clr_contract':'reports/legacy-class-init-lowering-v34-regression.json',
        'actual_ir':'reports/raw-classinit-stage-survey-v34.json',
        'native_ir':'reports/raw-classinit-native-correlation-v34.json',
        'emitted_cil':f'reports/recovered-class-phi-{RUN}.json',
        'batch':f'reports/recovery-regression-{RUN}.json',
        'syntax':f'analysis/il2cpp/cil-audit-{RUN}/summary.json',
        'stack':f'reports/cil-stack-audit-{RUN}.json',
        'compiler_before':f'reports/recovered-source-profile-legacy-reference-check-{BASELINE}.json',
        'compiler_after':f'reports/recovered-source-profile-legacy-reference-check-{RUN}.json',
        'project_compiler':f'reports/recovered-source-profile-project-build-{RUN}.json',
    }
    data={k:read(v) for k,v in paths.items()};evidence={k:brief(v) for k,v in paths.items()}
    directory=ROOT/f'analysis/il2cpp/cpp2il-recovery-{RUN}'
    dlls=sorted(directory.glob('*.dll'));hashes={p.name:sha(p) for p in dlls};latest=max((p.stat().st_mtime for p in dlls),default=float('inf'))
    invocation=data['invocation'];core=invocation.get('tool_assembly_sha256',{}).get('Cpp2IL.Core.dll')
    gates=[]
    def gate(name,passed,scope):gates.append(dict(name=name,passed=bool(passed),scope=scope))
    source=data['build_provenance'];review=data['independent_review'];production=data['production']
    snapshot=ROOT/source.get('source_snapshot','missing-snapshot')
    gate('immutable_build_review_and_invocation',invocation.get('exit_code')==0 and invocation.get('legacy_hfa_recovery') is True
        and source.get('status')=='PASS_RECORDED_SERIAL_BUILD_SOURCE_AND_INVOCATION_BINDING'
        and source.get('recovery_invocation_sha256')==evidence['invocation']['report_sha256']
        and source.get('core_sha256')==core and source.get('source_sha256')==EXPECTED_KFR
        and source.get('production_fixture_sha256')==evidence['production']['report_sha256']
        and source.get('independent_source_review_sha256')==evidence['independent_review']['report_sha256']
        and review.get('source_sha256')==EXPECTED_KFR and review.get('no_additional_blocking_issue_found') is True
        and review.get('finding',{}).get('current_source_contains_fix') is True
        and snapshot.is_file() and sha(snapshot)==EXPECTED_KFR,
        'Recorded reviewed source906447 and successful serial build bind Coreeb14 to the completed recovery; later mutable builds are not substituted.')
    fixtures=production.get('fixtures',[])
    gate('production_exact_phi_73',production.get('status')=='PASS_PRODUCTION_EDGE_AWARE_CLASS_METADATA_PHI_LOWERING'
        and production.get('checks')==73 and production.get('core_sha256')==core and production.get('production_lowering') is True
        and production.get('actual_call_stays_unresolved') is False
        and production.get('original_post_cctor_reload_indices')==[41,42,43]
        and production.get('remaining_runtime_class_flag_loads')==4
        and any(f.get('name')=='shared acyclic Phi DAG depth9' and f.get('accepted') is False and f.get('rejection')=='origin-visit-budget' for f in fixtures)
        and any(f.get('name')=='shared acyclic Phi DAG depth3' and f.get('accepted') is True for f in fixtures),
        'Actual type fixpoint plus positive/negative32-local and256-total-visit fixtures; original post-cctor reloads remain, no CFG folding.')
    proposal=data['proposal']
    gate('historical_independent_proposal_30',proposal.get('status')=='PASS_READ_ONLY_EDGE_AWARE_CLASS_METADATA_PHI_PROPOSAL'
        and proposal.get('checks')==30 and proposal.get('actual_call_stays_unresolved') is True
        and source.get('historical_proposal_sha256')==evidence['proposal']['report_sha256']
        and proposal.get('core_sha256')!=core,
        'Historical independent checker ran on old v33 Core with unresolved actual helper; it is not current production acceptance.')
    raw=data['raw_guards'];contract=data['clr_contract'];survey=data['actual_ir'];native=data['native_ir']
    gate('current_raw_31_and_clr_80_120',raw.get('status')=='PASS_RAW_CLASS_INIT_ABI_UNUSED_RESULT_AND_DEEP_USE_GUARDS'
        and raw.get('checks')==31 and raw.get('core_sha256')==core
        and contract.get('status')=='PASS_LEGACY_CLASS_INIT_TYPED_LOWERING_AND_CLR_CONTRACT'
        and contract.get('cases')==80 and contract.get('checks')==120 and contract.get('core_assembly_sha256')==core,
        'Original ABI/dead-result/deep-use guards and real emitter/host once/concurrent/throwing constructor contract.')
    correlated=native.get('methods',[]);phi=native.get('class_phi_gate',{})
    gate('actual_six_native_requests_six_managed',survey.get('core_sha256')==core and survey.get('managed_aliases_at_helper')==[]
        and invocation.get('source_binary_sha256')==raw.get('binary_sha256')==survey.get('binary_sha256')==production.get('binary_sha256')
        and invocation.get('source_metadata_sha256')==raw.get('metadata_sha256')==survey.get('metadata_sha256')==production.get('metadata_sha256')
        and native.get('survey_sha256')==evidence['actual_ir']['report_sha256']
        and native.get('recovered_managed_requests')==6 and native.get('remaining_raw_requests')==0
        and sorted(m.get('original_native_class_init_calls',-1) for m in correlated)==[1,2,3]
        and all(m.get('surviving_raw_isil_calls')==m.get('original_native_class_init_calls') and m.get('original_calls_already_absent_before_metadata_resolution')==0 for m in correlated)
        and phi.get('status')=='PASS_EXACT_CLASS_PHI_LOWERING_WITH_POST_CCTOR_RELOADS_RETAINED'
        and phi.get('proof_sha256')==evidence['production']['report_sha256']
        and phi.get('get_safe_remaining_raw_class_flag_loads')==4,
        'All original native class requests survive; exact Phi helper now lowers. Raw class flag checks and post-constructor field effects are not suppressed.')
    cil=data['emitted_cil'];old=cil.get('before',{});new=cil.get('after',{})
    baseline_dll=ROOT/f'analysis/il2cpp/cpp2il-recovery-{BASELINE}/Assembly-CSharp-firstpass.dll'
    gate('actual_unchanged_getsafe_cil',cil.get('status')=='PASS_ACTUAL_GETSAFE_CLASS_INITIALIZER_CIL_CORRELATION'
        and cil.get('recovery_run')==RUN and cil.get('baseline_run')==BASELINE and cil.get('checks')==13
        and cil.get('assembly_sha256')==hashes.get('Assembly-CSharp-firstpass.dll')
        and baseline_dll.is_file() and cil.get('baseline_assembly_sha256')==sha(baseline_dll)
        and (old.get('ConstructorRequests'),old.get('RawHelperDiagnostics'),old.get('PostConstructorFieldReloads'))==(2,1,1)
        and (new.get('ConstructorRequests'),new.get('RawHelperDiagnostics'),new.get('PostConstructorFieldReloads'))==(3,0,2)
        and old.get('RawClassFlagDiagnostics')==new.get('RawClassFlagDiagnostics')==4
        and cil.get('recovered_cil_or_source_modified') is False and cil.get('tokens_remapped')==0
        and cil.get('game_methods_invoked')==cil.get('class_initializers_invoked')==0 and cil.get('whole_method_executed') is False,
        'Unchanged actual body has3 exact BundlesUtil ldtoken/RCC pairs versus prior2+raw; required currentConfig reload survives. Inspection only; caller not executed.')
    regressions={}
    for name in REGRESSIONS+['scalars','enumerator','boolean-reader']:
        suffix='-with-identities' if name=='nested-tween' else ''
        path=f'reports/recovered-{name}-{RUN}{suffix}.json';report=read(path);entry=brief(path)
        bound={k:v for k,v in report.items() if isinstance(v,str) and (k=='assembly_sha256' or k.endswith('_assembly_sha256') or k=='firstpass_sha256')}
        passed=report.get('recovery_run')==RUN and str(report.get('status','')).startswith('PASS') and not report.get('fatal') and report.get('failure_count',0)==0
        passed=passed and bool(report) and (ROOT/path).stat().st_mtime>=latest and all(v in hashes.values() for v in bound.values())
        if name=='enumerator':passed=passed and report.get('successful_cases')==5 and report.get('production_cil_or_source_modified') is False
        else:passed=passed and report.get('checks',0)>0
        if name=='nested-tween':passed=passed and report.get('cases')==64 and report.get('identity_cases')==240 and report.get('initializer_effect_count')==1 and report.get('throwing_initializer_effect_count')==1
        if name=='boolean-reader':passed=passed and report.get('cases')==811 and report.get('checks')==3244 and report.get('cil_or_source_edited') is False and report.get('tokens_remapped')==0 and report.get('dynamic_clones')==0 and report.get('native_case_binding',{}).get('all_native_cases_executed') is True
        entry['recorded_assembly_hashes']=bound;regressions[name]=entry
        gate('recovered_'+name,passed,'Current bounded regression report, exact run and recorded DLL hashes; its original input/native/member boundaries remain in force.')
    batch=data['batch'];expected={'syntax','stack','scalar-direct','scalar-isolated','vector','boolean','nested-tween','type-token','constructor','currency-scalars','aggregate-leaves','leaf-accessor','static-getter','exception-factory','primitive-box','value-this-codec','indirect-enumerator','boolean-reader'}
    gate('complete_scoped_regression_batch_18',batch.get('status')=='PASS_SCOPED_RECOVERY_REGRESSIONS' and batch.get('recovery_run')==RUN and len(batch.get('probes',[]))==18 and {r.get('suffix') for r in batch.get('probes',[])}==expected and all(r.get('exit_code')==0 for r in batch.get('probes',[])),'All18 scoped runner invocations completed successfully; individual scopes remain separate.')
    syntax=data['syntax'];stack=data['stack'];rows=syntax.get('assemblies',[])
    gate('syntax_44',len(dlls)==len(rows)==44 and {r.get('file') for r in rows}==set(hashes) and all(r.get('malformed_il')==0 for r in rows),'CIL syntax only; helpers/behavior can remain incomplete.')
    gate('stack_44',stack.get('status')=='PASS_STACK_DEPTH_AND_HEADERS_ONLY' and stack.get('recovery_run')==RUN and stack.get('assembly_count')==44 and all(stack.get(k)==0 for k in ('understated_max_stack','stack_flow_failures','helper_types_without_base')),'Stack/header only, not full CLR type verification.')
    source_sets={k:source_rows(data[k]) for k in ('compiler_before','compiler_after','project_compiler')}
    for key,rows in source_sets.items():gate(key+'_both_assemblies',{r.get('assembly') for r in rows}=={'Assembly-CSharp-firstpass','Assembly-CSharp'} and all(r.get('export_exit_code')==r.get('restore_exit_code')==0 and isinstance(r.get('build_exit_code'),int) and isinstance(r.get('unique_compiler_diagnostic_lines'),int) for r in rows),'Complete two-assembly compiler results, including failures; diagnostic lines are not completeness percentages.')
    manifest=source_manifest(data['compiler_after'])
    gate('identical_source_manifest_both_profiles',manifest is not None and manifest==source_manifest(data['project_compiler']),'Both reference profiles compile the same complete source inventory; no source fixes are injected.')
    before=compiler(BASELINE);after=compiler(RUN);previous={r['assembly']:r['unique_compiler_diagnostic_lines'] for r in before}
    delta={r['assembly']:r['unique_compiler_diagnostic_lines']-previous[r['assembly']] for r in after if r['assembly'] in previous}
    missing=[v for v in paths.values() if not (ROOT/v).exists()]+[v['report'] for v in regressions.values() if not (ROOT/v['report']).exists()]
    passed=all(g['passed'] for g in gates)
    status='SCOPED_EXACT_CLASS_PHI_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE' if passed else 'IN_PROGRESS' if missing or args.active_session else 'EXACT_CLASS_PHI_VALIDATION_LIMITATION_CONFIRMED'
    result=dict(status=status,recovery_run=RUN,updated=datetime.datetime.now(datetime.timezone.utc).isoformat(),evidence=evidence,gates=gates,failed_gates=[g['name'] for g in gates if not g['passed']],missing_reports=missing,recovery_core_sha256=core,source_snapshot_sha256=source.get('source_sha256'),assembly_hashes=hashes,recovered_regressions=regressions,compiler_before=before,compiler_after=after,compiler_diagnostic_line_delta=delta,source_compiler_results=source_sets,active_sessions=args.active_session,full_clean_decompile_ready=False,whole_game_source_ready=False,portable_game_ready=False,
        limits='The correlated GetSafe body gains one exact managed constructor request in place of its raw helper diagnostic; no global recovered-method count is inferred. GetSafe and Unload raw class-flag/cold-CFG paths remain unresolved; post-cctor fields and branches are preserved. Actual GetSafe CIL is inspected, not executed. Independent constructor/native fixtures, current bounded runtime regressions,44-assembly syntax/stack checks and full-source compiler outcomes have distinct scopes. Compiler diagnostic-line deltas include cascades and are not completion percentages. Full clean decompilation, gameplay equivalence and every platform port remain incomplete.')
    base=ROOT/'reports/class-origin-phi-source-recovery-v34';destination(ROOT,base.with_suffix('.json')).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    lines=['# Exact class-metadata Phi recovery','',status,'','Full clean decompilation and portable game source remain incomplete.','','Actual GetSafe CIL:3 exact constructor requests versus prior2 plus1 raw diagnostic; required field reload retained. Four raw class-flag diagnostics remain.','','| Complete matching-reference source check | Firstpass diagnostics | Main diagnostics |','|---|---:|---:|']
    for label,rows in ((BASELINE,before),(RUN,after)):
        counts={r['assembly']:r['unique_compiler_diagnostic_lines'] for r in rows};lines.append(f"| {label} | {counts.get('Assembly-CSharp-firstpass','pending')} | {counts.get('Assembly-CSharp','pending')} |")
    lines+=['',f"Required gates: {sum(g['passed'] for g in gates)}/{len(gates)} passed.",'',result['limits'],'']
    destination(ROOT,base.with_suffix('.md')).write_text('\n'.join(lines),encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('status','failed_gates','missing_reports','compiler_after','compiler_diagnostic_line_delta')}))


if __name__=='__main__':main()
