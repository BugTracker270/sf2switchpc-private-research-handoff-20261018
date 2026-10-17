"""Summarize native-backed leaf/factory corrections without copying game sources."""
import argparse
import datetime
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination
ROOT = Path(__file__).resolve().parents[3]
RUN = 'nso-native-leaves-v28'

def read(path):
    p = ROOT / path
    return json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else {}

def brief(path):
    r = read(path)
    keys = ['status', 'cases', 'checks', 'failure_count', 'fatal', 'selected_getters', 'selected_setters',
            'fields_examined', 'matched_obscured_int_leaves', 'call_sites', 'accessor_calls']
    return dict(report=path, **{key:r[key] for key in keys if key in r}) if r else dict(report=path, status='NOT_STARTED')

def compiler(run):
    r = read(f'reports/recovered-source-profile-legacy-reference-check-{run}.json')
    return [{key:a.get(key) for key in ['assembly', 'build_exit_code', 'unique_compiler_diagnostic_lines']}
            for a in r.get('assemblies', [])]

def main():
    global RUN
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--active-session', action='append', default=[])
    p.add_argument('--run', choices=['nso-native-leaves-v28','nso-native-leaves-v29'], default=RUN)
    args = p.parse_args()
    RUN = args.run
    paths = {
        'accessor_selection':'reports/private-access-leaf-selection-v28.json',
        'accessor_native':'reports/private-access-native-store-v28.json',
        'accessor_recovered':f'reports/recovered-leaf-accessor-{RUN}.json',
        'aggregate_selection':'reports/integer-aggregate-leaf-recognition.json',
        'aggregate_native':'reports/integer-aggregate-leaf-native-fixtures.json',
        'aggregate_recovered':f'reports/recovered-aggregate-leaves-{RUN}.json',
        'factory_selection':'reports/compiler-priority-exception-factory.json',
        'factory_native':'reports/compiler-priority-native-exception-factory.json',
        'factory_recovered':f'reports/recovered-exception-factory-{RUN}.json',
        'currency_scalar_recovered':f'reports/recovered-currency-scalars-{RUN}.json',
        'accessor_source':f'reports/private-access-source-{RUN}.json',
    }
    evidence = {key:brief(path) for key,path in paths.items()}
    stack = read(f'reports/cil-stack-audit-{RUN}.json')
    audit = read(f'analysis/il2cpp/cil-audit-{RUN}/summary.json')
    syntax_ok = len(audit.get('assemblies', [])) == 44 and not any(a.get('malformed_il', 1) for a in audit.get('assemblies', []))
    bounded_pass = all(item.get('status','').startswith('PASS') for item in evidence.values()) and syntax_ok and stack.get('status') == 'PASS_STACK_DEPTH_AND_HEADERS_ONLY'
    result = dict(status='SCOPED_NATIVE_LEAF_RECOVERY_VALIDATED_SOURCE_INCOMPLETE' if bounded_pass else 'IN_PROGRESS',
        updated=datetime.datetime.now(datetime.timezone.utc).isoformat(), recovery_run=RUN,
        compiler_before=compiler('nso-generic-ctor-v27'), compiler_intermediate=compiler('nso-native-leaves-v28'), compiler_after=compiler(RUN), evidence=evidence,
        initial_accessor_emission_failure=brief('reports/recovered-leaf-accessor-nso-native-leaves-v28.json'),
        stack_status=stack.get('status','NOT_STARTED'), cil_assemblies_audited=len(audit.get('assemblies', [])),
        syntax_valid=syntax_ok, active_sessions=args.active_session, whole_game_source_ready=False,
        changes=[
            'Restore existing public nonvirtual accessors only after an exact native scalar/ref load/store plus return witness, preserving original private field flags.',
            'Recover complete native two-word integer field-copy leaves as managed whole-field operations before generic argument analysis.',
            'Recognize the reviewed no-argument returning exception factory and preserve its exact default constructor effect as an adjacent allocation/constructor pair.'
        ],
        limits='Opt-in alternative patch only. The accessor scope excludes nested paths, addresses, generic/value receivers, effectful accessors, readonly writes and unsupported initialization contracts. '
               'Aggregate tests compare managed fields and adjacent storage; padding-byte identity, generic aggregate entry/call/return and GC remain outside scope. '
               'Exception tests reach an explicit managed invoker boundary; host CLR constructor checks do not execute the Nintendo GC, original constructor implementation, full caller or gameplay. '
               'Compiler diagnostic counts include cascades and do not measure completion. Full game source and port readiness remain incomplete.')
    destination(ROOT,ROOT/'reports/native-leaf-source-recovery-20261017.json').write_text(json.dumps(result,indent=2)+'\n')
    lines=['# Native leaf and exception factory recovery','',result['status'],'',
           'Full clean game source is still incomplete. The following corrections have separate native, metadata and recovered-CIL gates.','',
           '| Source check | Firstpass diagnostic lines | Main diagnostic lines |','|---|---:|---:|']
    for label,rows in [('v27',result['compiler_before']),('v28',result['compiler_intermediate']),(RUN.rsplit('-',1)[-1],result['compiler_after'])]:
        counts={a['assembly']:a['unique_compiler_diagnostic_lines'] for a in rows}
        lines.append(f"| {label} | {counts.get('Assembly-CSharp-firstpass','pending')} | {counts.get('Assembly-CSharp','pending')} |")
    lines += ['','Corrections:',''] + ['- '+item for item in result['changes']]
    lines += ['','Evidence:','']
    for key,item in evidence.items():
        lines.append(f"- [{key.replace('_',' ')}]({Path(item['report']).name}): {item.get('status','NOT_STARTED')}; {item.get('checks','pending')} checks.")
    lines += ['',result['limits'],'']
    destination(ROOT,ROOT/'reports/native-leaf-source-recovery-20261017.md').write_text('\n'.join(lines))
    state=read('analysis/continuation-state.json')
    state['active_'+RUN.rsplit('-',1)[-1]]=dict(status=result['status'],run=RUN,sessions=args.active_session,
        report='reports/native-leaf-source-recovery-20261017.json',compiler=result['compiler_after'],whole_game_source_ready=False)
    state['next']=['Verify any active native leaf recovery jobs before restarting completed outputs.',
        'Continue actual source recovery against native evidence: remaining inaccessible members, constructor/inlining, ABI, runtime calls, attributes and control flow. No port phase.']
    destination(ROOT,ROOT/'analysis/continuation-state.json').write_text(json.dumps(state,indent=2)+'\n')
    print(json.dumps({key:result[key] for key in ['status','compiler_after','active_sessions','whole_game_source_ready']}))

if __name__ == '__main__':
    main()
