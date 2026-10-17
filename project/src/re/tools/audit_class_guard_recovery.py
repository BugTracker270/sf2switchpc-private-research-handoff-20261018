"""Correlate a native macro correction with actual fresh CIL and source output."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination
ROOT = Path(__file__).resolve().parents[3]
WITNESSES = {('AdvLog', 'Init'), ('BundlesUtil', 'UnloadDependencies'), ('BundlesUtil', 'LoadDependencies')}


def read_methods(run):
    path = ROOT / f'analysis/il2cpp/cil-audit-{run}/Assembly-CSharp-firstpass.jsonl'
    with path.open(encoding='utf-8') as stream:
        rows = {(row['type'], row['name']): row for row in map(json.loads, stream)
                if (row['type'], row['name']) in WITNESSES}
    if set(rows) != WITNESSES:
        raise ValueError('Missing actual method evidence')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--baseline', default='nso-default-member-v16')
    args = parser.parse_args()
    if any(not re.fullmatch('[a-z0-9-]+', value) for value in (args.run, args.baseline)):
        raise ValueError('Invalid run')
    native = json.loads((ROOT / 'reports/native-class-guard-branches.json').read_text(encoding='utf-8-sig'))
    if native['status'] != 'PASS_ORIGINAL_CLASS_GUARD_BRANCHES_AT_RUNTIME_BOUNDARY' or native['text_modified']:
        raise ValueError('Original native control-flow gate is missing')
    old, new = read_methods(args.baseline), read_methods(args.run)
    rows = []
    for key in sorted(WITNESSES):
        before, after = old[key], new[key]
        def class_reads(row):
            return [message for message in row['diagnostic_messages']
                    if 'Il2CppClass<' in message and '+122]' in message]
        a, b = len(class_reads(before)), len(class_reads(after))
        if a <= b or after['stack_rejection_diagnostic'] or after['error'] or after['body_bytes'] < 16:
            raise ValueError('The correction did not improve the real body without rejection')
        removed = sorted(set(before['call_targets']) - set(after['call_targets']))
        if any(target not in {'Cpp2ILInjected.Cpp2ILHelpers::NoteDecompilerIssue', 'System.Type::GetTypeFromHandle'} for target in removed):
            raise ValueError(f'Unexpected ordinary managed call loss: {removed}')
        rows.append(dict(type=key[0], method=key[1], before_native_class_reads=a,
                         after_native_class_reads=b, body_il_sha256=after['il_sha256'],
                         removed_bookkeeping_calls=removed,
                         remaining_diagnostic_messages=after['diagnostic_messages']))
    sources = []
    for name in ['AdvLog', 'BundlesUtil']:
        def source(run):
            return ROOT / f'analysis/il2cpp/source-profile-project-build-{run}/Assembly-CSharp-firstpass/{name}.cs'
        before, after = source(args.baseline), source(args.run)
        a = before.read_text(encoding='utf-8-sig').count('(nint)typeof(')
        b = after.read_text(encoding='utf-8-sig').count('(nint)typeof(')
        if b >= a:
            raise ValueError('Actual source export did not reduce class-pointer cast failures')
        sources.append(dict(path=str(after.relative_to(ROOT)), sha256=hashlib.sha256(after.read_bytes()).hexdigest(),
                            before_invalid_type_pointer_casts=a, after_invalid_type_pointer_casts=b))
    report = dict(status='PASS_SCOPED_NATIVE_CLASS_GUARD_CIL_SOURCE_CORRELATION',
                  recovery_run=args.run, baseline=args.baseline, methods=rows, sources=sources,
                  native_cases=native['cases'], native_checks=native['checks'],
                  scope='Three actual method bodies and two unchanged source exports. '
                        'Native class-byte diagnostic reads decrease without replacing bodies with rejection stubs '
                        'or losing ordinary managed calls. Cold/noncontiguous guards and other source errors remain. '
                        'Does not certify initialization ordering, complete methods, ABI or whole-source readiness.')
    destination(ROOT, ROOT / f'reports/recovered-class-guards-{args.run}.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
