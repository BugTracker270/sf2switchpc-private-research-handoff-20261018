"""Summarize bounded initialization recovery without promoting failed whole-source builds."""
import argparse
import datetime
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination

ROOT = Path(__file__).resolve().parents[3]
RUN = 'nso-cfg-init-v31'


def read(path):
    file = ROOT / path
    return json.loads(file.read_text(encoding='utf-8-sig')) if file.exists() else {}


def compiler(run):
    report = read(f'reports/recovered-source-profile-legacy-reference-check-{run}.json')
    return [{key: item.get(key) for key in ('assembly', 'build_exit_code', 'unique_compiler_diagnostic_lines')}
            for item in report.get('assemblies', [])]


def brief(path):
    report = read(path)
    return dict(report=path, **{key: value for key, value in report.items()
                               if value is None or isinstance(value, (str, int, float, bool))})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--active-session', action='append', default=[])
    parser.add_argument('--run-name', default=RUN)
    parser.add_argument('--report-label', default='v31')
    parser.add_argument('--include-static-getter', action='store_true')
    args = parser.parse_args()
    if not all(re.fullmatch('[a-z0-9-]+', value) for value in (args.run_name, args.report_label)):
        parser.error('Only lowercase run/report identifiers are allowed')
    run = args.run_name
    paths = {
        'native_cfg_recognition': 'reports/cfg-initialization-recognition-v31.json',
        'typed_class_constructor_lowering': 'reports/legacy-class-init-lowering-v31.json',
        'actual_recovered_codec': f'reports/recovered-value-this-{run}.json',
        'recovered_boxing': f'reports/recovered-primitive-box-{run}.json',
    }
    if args.include_static_getter:
        paths.update(native_static_getter='reports/native-static-getter-v31b.json',
                     static_getter_selection='reports/static-leaf-getter-selection-v31b.json',
                     recovered_static_getter=f'reports/recovered-static-getter-{run}.json')
    evidence = {key: brief(path) for key, path in paths.items()}
    actual = read(paths['actual_recovered_codec'])
    recognition = read(paths['native_cfg_recognition'])
    audit = read(f'analysis/il2cpp/cil-audit-{run}/summary.json')
    stack = read(f'reports/cil-stack-audit-{run}.json')
    syntax_ok = len(audit.get('assemblies', [])) == 44 and not any(
        item.get('malformed_il', 1) for item in audit.get('assemblies', []))
    valid = all(item.get('status', '').startswith('PASS') for item in evidence.values()) \
        and syntax_ok and stack.get('status') == 'PASS_STACK_DEPTH_AND_HEADERS_ONLY' \
        and actual.get('cases', 0) > 0 and not actual.get('blocked_calls') \
        and actual.get('cil_or_source_edited') is False and actual.get('tokens_remapped') == 0
    status = 'SCOPED_INITIALIZATION_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE' if valid else (
        'RECOVERED_GAME_EXECUTION_LIMITATION_CONFIRMED' if actual and not args.active_session else 'IN_PROGRESS')
    result = dict(
        status=status,
        updated=datetime.datetime.now(datetime.timezone.utc).isoformat(), recovery_run=run,
        evidence=evidence, native_metadata_guard_sites=len(recognition.get('metadata_guards', [])),
        native_class_guard_sites=len(recognition.get('class_guards', [])),
        reachable_recovered_codec_blockers=len(actual.get('blocked_calls', [])) if actual else None,
        cil_assemblies_audited=len(audit.get('assemblies', [])), syntax_valid=syntax_ok,
        stack_status=stack.get('status', 'NOT_STARTED'),
        compiler_before=compiler('nso-cfg-init-v31' if args.include_static_getter else 'nso-value-this-box-v30'), compiler_after=compiler(run),
        active_sessions=args.active_session, whole_game_source_ready=False,
        limits='Native recognition is limited to exact FDE-bounded selected legacy value-receiver bodies and reviewed initializer identities. '
               'Metadata assurance flags are replaced only after exact native witnesses; scheduled arithmetic and semantic branches remain. '
               'Class-constructor effects use the exact existing managed RuntimeHelpers.RunClassConstructor handle API only after typed metadata-origin proof; '
               'unknown pointers stay diagnostic. Static foreign-private reads use an existing public getter only after exact native body, metadata-owner and no-cctor proof; field visibility stays intact. '
               'CLR constructor-contract fixtures and actual recovered game-code comparisons have separate scopes. '
               'The game codec comparison uses explicit supplied static state and native absent-detector fixtures; active detector callbacks, '
               'general aggregate ABI, serialization attributes, the complete source build and later ports remain unverified. '
               'Compiler diagnostic counts include cascades and do not measure completion.')
    report_base = f'reports/cfg-initialization-source-recovery-{args.report_label}'
    path = destination(ROOT, ROOT / (report_base + '.json'))
    path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    lines = ['# Bounded CFG initialization recovery', '', result['status'], '',
             'Full clean decompilation remains incomplete.', '',
             '| Source check | Firstpass diagnostic lines | Main diagnostic lines |',
             '|---|---:|---:|']
    for label, rows in [('baseline', result['compiler_before']), (args.report_label, result['compiler_after'])]:
        counts = {item['assembly']: item['unique_compiler_diagnostic_lines'] for item in rows}
        lines.append(f"| {label} | {counts.get('Assembly-CSharp-firstpass', 'pending')} | {counts.get('Assembly-CSharp', 'pending')} |")
    lines += ['', 'Evidence:', '']
    for key, item in evidence.items():
        lines.append(f"- [{key.replace('_', ' ')}]({Path(item['report']).name}): "
                     f"{item.get('status', 'NOT_STARTED')}; {item.get('cases', 0)} cases / {item.get('checks', 0)} checks.")
    lines += ['', result['limits'], '']
    destination(ROOT, ROOT / (report_base + '.md')).write_text('\n'.join(lines), encoding='utf-8')
    state = read('analysis/continuation-state.json')
    state.setdefault('active_' + args.report_label, {}).update(status=result['status'], run=run, sessions=args.active_session,
        report=report_base + '.json', compiler=result['compiler_after'], whole_game_source_ready=False)
    destination(ROOT, ROOT / 'analysis/continuation-state.json').write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: result[key] for key in ('status', 'compiler_after', 'reachable_recovered_codec_blockers', 'active_sessions')}))


if __name__ == '__main__':
    main()
