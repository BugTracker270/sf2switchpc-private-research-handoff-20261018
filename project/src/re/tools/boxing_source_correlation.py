"""Correlate one unchanged source method with actual boxing execution evidence."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def selected_method(text):
    match = re.search(r'\bvoid\s+SetAge\s*\(\s*int\s+age\s*\)', text)
    if not match:
        raise ValueError('Actual SetAge signature was not exported')
    begin = text.index('{', match.end())
    # This selected method has ordinary C# strings; ignore their braces and
    # comments while finding the original body boundary.
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/|[{}]', re.S)
    depth = 0
    for token in tokens.finditer(text, begin):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if depth == 0:
                return text[begin + 1:token.start()]
    raise ValueError('Unterminated selected source method')


def inspect(run):
    path = ROOT / f'reports/recovered-source-profile-project-build-{run}.json'
    manifest = json.loads(path.read_text(encoding='utf-8-sig'))
    assembly = next(row for row in manifest['assemblies'] if row['assembly'] == 'Assembly-CSharp')
    source = ROOT / f'analysis/il2cpp/source-profile-project-build-{run}/Assembly-CSharp/FyberPlugin/User.cs'
    row = next(row for row in assembly['source_files'] if (ROOT / row['path']).resolve() == source.resolve())
    if assembly['export_exit_code'] != 0 or digest(source) != row['sha256'] or source.stat().st_size != row['bytes']:
        raise ValueError('Actual source export differs from its complete source manifest')
    body = selected_method(source.read_text(encoding='utf-8-sig'))
    code = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/', '', body, flags=re.S)
    return dict(recovery_run=run, source_manifest_sha256=digest(path), selected_source_sha256=row['sha256'],
        selected_method_sha256=hashlib.sha256(body.encode()).hexdigest(),
        legacy_box_diagnostic_strings=body.count('Method not found @B5B070'),
        actual_age_identifier_uses=len(re.findall(r'\bage\b', code)),
        selected_remaining_diagnostic_calls=body.count('Cpp2ILHelpers.NoteDecompilerIssue'),
        source_export_project_compile_exit_code=assembly['build_exit_code'])


def main():
    if len(sys.argv) != 2 or not re.fullmatch('[a-z0-9-]+', sys.argv[1]):
        raise ValueError('Actual recovery run required')
    run = sys.argv[1]
    before, after = inspect('nso-native-leaves-v29'), inspect(run)
    if (before['legacy_box_diagnostic_strings'] != 1 or before['actual_age_identifier_uses'] != 0
            or after['legacy_box_diagnostic_strings'] != 0 or after['actual_age_identifier_uses'] < 1):
        raise ValueError('Selected actual source did not restore its formerly missing boxed age input')
    required = {
        'metadata_and_native_argument_provenance': ('reports/boxing-input-provenance-v29.json', 'PASS_SCOPED_NATIVE_BOX_ARGUMENT_TYPE_PROVENANCE'),
        'lowering_and_ir': ('reports/scalar-boxing-validation-v30.json', 'PASS_TYPED_SCALAR_BOX_DISCOVERY_AND_CALLER_IR'),
        'native_runtime_at_explicit_boundaries': ('reports/native-scalar-boxing-v30.json', 'PASS_ORIGINAL_NON_NULLABLE_SCALAR_BOX_PAYLOADS_AT_GC_COPY_BOUNDARIES'),
        'actual_recovered_expression': (f'reports/recovered-primitive-box-{run}.json', 'PASS_RECOVERED_INT32_BOX_EXPRESSION_AT_TYPED_VALUE_BOUNDARY'),
    }
    gates = {}
    for name, (relative, expected) in required.items():
        path = ROOT / relative
        evidence = json.loads(path.read_text(encoding='utf-8-sig'))
        if evidence['status'] != expected:
            raise ValueError(name + ' evidence incomplete')
        gates[name] = dict(status=expected, report_sha256=digest(path), cases=evidence.get('cases'), checks=evidence.get('checks'))
    report = dict(status='PASS_SCOPED_INT32_BOX_SOURCE_AND_RUNTIME_CORRELATION', recovery_run=run,
        caller='FyberPlugin.User::SetAge(System.Int32)', caller_rva='0xF230F0', boxing_call_rva='0xF23144',
        before=before, after=after, proof_gates=gates, source_text_edited=False, whole_game_source_ready=False,
        scope='Only the selected actual SetAge source method is compared: its exact complete-export manifest/source hashes are checked, the unresolved boxing diagnostic disappears and the real age argument use returns. Actual recovered Int32 expression tests, metadata/typed-argument provenance, guarded lowering and the separately bounded original native boxing oracle must pass. These scopes are complementary rather than paired full-caller inputs. Other game source effects, remaining method diagnostics, complete native allocation/GC/class initialization and Switch feature availability are not certified.')
    destination(ROOT, ROOT / f'reports/boxing-source-correlation-{run}.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
