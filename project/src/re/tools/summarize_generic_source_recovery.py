"""Record bounded generic/ABI recovery evidence without copying game source."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination

ROOT = Path(__file__).resolve().parents[3]
RUNS = ['nso-generic-fp-fields-v22', 'nso-generic-fp-tail-v23', 'nso-nested-hfa-v24', 'nso-sparse-params-v25', 'nso-type-handle-v26', 'nso-generic-ctor-v27']


def read(relative):
    path = ROOT / relative
    return json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}


def brief_probe(relative):
    data = read(relative)
    if not data:
        return dict(status='NOT_STARTED', report=relative)
    keys = ['status', 'cases', 'checks', 'identity_cases', 'identity_checks', 'total_checks',
            'caller_nested_field_addresses', 'statically_unreachable_analysis_warning_calls', 'fatal',
            'diagnostic_tail_termination_experiment', 'body_il_sha256', 'type_from_handle_calls', 'actual_type',
            'raw_allocation_calls', 'direct_constructor_calls', 'newobj_constructors']
    return dict(report=relative, **{key: data[key] for key in keys if key in data})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--active-session', action='append', default=[])
    args = parser.parse_args()
    rows = []
    for run in RUNS:
        source = read(f'reports/recovered-source-profile-legacy-reference-check-{run}.json')
        probe_path = f'reports/recovered-nested-tween-{run}-with-identities.json'
        if not (ROOT / probe_path).exists():
            probe_path = f'reports/recovered-nested-tween-{run}.json'
        stack = read(f'reports/cil-stack-audit-{run}.json')
        audit = read(f'analysis/il2cpp/cil-audit-{run}/summary.json')
        rows.append(dict(run=run,
            source_status=source.get('status', 'NOT_STARTED'),
            compiler=[{key: a.get(key) for key in ['assembly', 'build_exit_code', 'unique_compiler_diagnostic_lines']}
                      for a in source.get('assemblies', [])],
            recovered_execution=brief_probe(probe_path), stack_status=stack.get('status', 'NOT_STARTED'),
            cil_assemblies_audited=len(audit.get('assemblies', []))))
    native_caller = read('reports/native-fp-class-guard-caller.json')
    native_identity = read('reports/native-nested-hfa-identity.json')
    metadata = read('reports/generic-field-path-v27.json') or read('reports/generic-field-path-v25.json')
    latest = rows[-1]
    proven = (latest['recovered_execution'].get('status') == 'PASS_RECOVERED_NESTED_HFA_AND_CALLER_NATIVE_COMPARISON'
              and latest['stack_status'] == 'PASS_STACK_DEPTH_AND_HEADERS_ONLY'
              and latest['cil_assemblies_audited'] == 44
              and metadata.get('parameter_binding_cases') == 96
              and metadata.get('constructor_checks', 0) >= 12
              and read('reports/recovered-constructor-nso-generic-ctor-v27.json').get('status') == 'PASS_RECOVERED_CONSTRUCTION_AT_CLR_LIST_BOUNDARY')
    report = dict(status='SCOPED_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE' if proven else 'IN_PROGRESS',
        updated=datetime.datetime.now(datetime.timezone.utc).isoformat(), runs=rows,
        original_caller={key: native_caller.get(key) for key in ['status', 'cases', 'checks', 'caller_sha256']},
        original_identities={key: native_identity.get(key) for key in ['status', 'cases', 'checks', 'fixture_sha256']},
        metadata_checks=metadata.get('checks'), sparse_parameter_cases=metadata.get('parameter_binding_cases'),
        sparse_parameter_checks=metadata.get('parameter_binding_checks'),
        type_handle_before=brief_probe('reports/recovered-type-handle-token-nso-sparse-params-v25.json'),
        type_handle_after=brief_probe('reports/recovered-type-handle-token-nso-type-handle-v26.json'),
        constructor_before=brief_probe('reports/recovered-constructor-nso-type-handle-v26.json'),
        constructor_after=brief_probe('reports/recovered-constructor-nso-generic-ctor-v27.json'),
        constructor_metadata_checks=metadata.get('constructor_checks'),
        active_sessions=args.active_session, whole_game_source_ready=False,
        changes=['Closed-generic field layout with observed inherited field offsets and tail-padding reuse.',
                 'Scalar FP access widths and nested managed field addresses for reads and stores.',
                 'Analysis-warning tails now terminate by throwing instead of falling off the method.',
                 'Recursive metadata-validated homogeneous FP aggregates; unsupported layouts remain diagnostic.',
                 'Surviving parameters keep their original signature position when earlier arguments are optimized out.',
                 'A literal token stays RuntimeTypeHandle when required by the managed signature; ordinary Type conversion remains separate.',
                 'Adjacent closed-generic reference allocation/constructor pairs match canonical definitions and arguments, while receiver/block/order guards remain.'],
        limits='Opt-in experimental tool patch remains separate from canonical v19. Native tests are bounded '
               'instruction harnesses. The original full caller uses an explicit class-initializer boundary; recovered '
               'execution substitutes exact isolated field storage and rejects reachable diagnostics. Stack-spilled '
               'HFAs, integer multiword aggregates, full runtime ordering, other call paths and full game source '
               'remain unverified. Constructor expression checks use the host CLR List<T> contract and stop before '
               'Unity base initialization; Nintendo allocator/GC and the full constructor are unverified. '
               'Compiler diagnostic counts include cascades and are not completion measures.')
    output = destination(ROOT, ROOT / 'reports/generic-source-recovery-20261017.json')
    output.write_text(json.dumps(report, indent=2) + '\n')
    lines = ['# Generic field, aggregate and parameter recovery', '', report['status'], '',
             'The full clean decompile remains incomplete. These are original tool corrections with bounded native/CIL evidence.', '',
             '| Run | Firstpass diagnostic lines | Main diagnostic lines | Recovered execution |', '|---|---:|---:|---|']
    for row in rows:
        counts = {a['assembly']: a['unique_compiler_diagnostic_lines'] for a in row['compiler']}
        lines.append(f"| {row['run']} | {counts.get('Assembly-CSharp-firstpass', 'pending')} | {counts.get('Assembly-CSharp', 'pending')} | {row['recovered_execution']['status']} |")
    lines += ['', 'Corrections:', ''] + [f'- {change}' for change in report['changes']]
    lines += ['', 'Evidence:', '',
              '- [Original complete caller](native-fp-class-guard-caller.json): 256 cases / 1,024 checks at the stated runtime boundary.',
              '- [Original wrapper identities](native-nested-hfa-identity.json): 240 cases / 720 checks, including arbitrary float bit patterns.',
              '- [Recovered caller and wrapper comparisons](recovered-nested-tween-nso-sparse-params-v25-with-identities.json).',
              '- [Metadata/layout and sparse-parameter checks](generic-field-path-v25.json).',
              '- [Type-handle expression contract](recovered-type-handle-token-nso-type-handle-v26.json): isolated CLR expression; not original ARM64 or full-getter validation.',
              '- [Closed-generic construction expression](recovered-constructor-nso-generic-ctor-v27.json): actual CIL at the host CLR List<T> boundary, stopping before Unity base initialization.',
              '- [Earlier failure isolated to an unterminated warning tail](recovered-nested-tween-nso-generic-fp-fields-v22-tail-experiment.json). This probe experiment is not unchanged-CIL acceptance.',
              '- [Arm ABI definition](https://github.com/ARM-software/abi-aa/blob/2025Q1/aapcs64/aapcs64.rst), sections 5.10.5 and 6.8.', '', report['limits'], '']
    destination(ROOT, ROOT / 'reports/generic-source-recovery-20261017.md').write_text('\n'.join(lines))
    state = read('analysis/continuation-state.json')
    state['active_source_recovery'] = dict(status=report['status'], latest_run=RUNS[-1], sessions=args.active_session,
        report='reports/generic-source-recovery-20261017.json', compiler=latest['compiler'], runtime=latest['recovered_execution'])
    state['next'] = ['Finish/verify current v27 jobs if listed; do not restart finished recovery outputs.',
        'Continue source correction: System.Type versus RuntimeTypeHandle token lowering; direct constructor calls; '
        'integer multiword ABI; inlined private accesses, unresolved runtime calls, attributes and control flow. '
        'Full clean source is still primary; no port phase.',
        'Use complete experimental patch separately from canonical v19; preserve old failed probes and compiler evidence.']
    state['hfa_experiment'].update(run=RUNS[-1], status=report['status'], patch='src/re/tool-patches/cpp2il-sf2-hfa-experimental.patch; complete alternative 25-file patch, never combine with canonical',
        remaining='See current aggregate/parameter evidence report. Stack spills, integer multiword ABI, generic/indirect calls and complete source remain unresolved.')
    state['active_v21']['pipeline'] = 'Completed and checkpointed a206fce; no v21 active jobs. Both source compilers failed 21400/36324 diagnostic lines.'
    destination(ROOT, ROOT / 'analysis/continuation-state.json').write_text(json.dumps(state, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['status', 'metadata_checks', 'sparse_parameter_cases', 'active_sessions']}))


if __name__ == '__main__':
    main()
