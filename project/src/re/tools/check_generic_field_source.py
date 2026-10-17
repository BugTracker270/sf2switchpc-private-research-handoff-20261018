"""Correlate selected unchanged decompiler source with strict recovered-CIL gates."""
import hashlib
import json
import re
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination

ROOT = Path(__file__).resolve().parents[3]


def method(tag, name):
    path = ROOT / f'analysis/il2cpp/hfa-caller-{tag}/DG.Tweening.Plugins.Vector3WrapperPlugin.decompiled.cs'
    text = path.read_text()
    start = text.index(name + '(')
    opening = text.index('{', start)
    depth = 0
    for at in range(opening, len(text)):
        if text[at] == '{':
            depth += 1
        elif text[at] == '}':
            depth -= 1
            if depth == 0:
                body = text[opening:at + 1]
                return path, body
    raise ValueError('Selected method has no complete body')


def main():
    before_path, before = method('v21', 'SetRelativeEndValue')
    after_path, after = method('v25', 'SetRelativeEndValue')
    _, convert_before = method('v24', 'ConvertToStartValue')
    _, convert_after = method('v25', 'ConvertToStartValue')
    if before.count('Unmanaged memory load:') != 6 or 'NoteDecompilerIssue' in after or '//IL_' in after:
        raise ValueError('Selected relative caller did not lose exactly the six known load diagnostics')
    if len(re.findall(r'= t\.(?:startValue|endValue)\.value\.[xyz];', after)) != 6:
        raise ValueError('Expected all six original input component paths')
    if len(re.findall(r't\.endValue\.value\.[xyz] = ', after)) != 3:
        raise ValueError('Expected all three original destination component paths')
    if convert_before.count('Unmanaged memory load:') != 2 or 'NoteDecompilerIssue' in convert_after or '//IL_' in convert_after:
        raise ValueError('Sparse parameter correction did not clean the selected wrapper return')
    if len(re.findall(r'= value\.value\.[xyz];', convert_after)) != 3:
        raise ValueError('Expected all three preserved input wrapper components')
    runtime = json.loads((ROOT/'reports/recovered-nested-tween-nso-sparse-params-v25-with-identities.json').read_text())
    if runtime['status'] != 'PASS_RECOVERED_NESTED_HFA_AND_CALLER_NATIVE_COMPARISON' or runtime['total_checks'] != 1296:
        raise ValueError('Actual recovered-CIL/native comparison gate required')
    report = dict(status='PASS_SCOPED_GENERIC_FIELD_AND_SPARSE_PARAMETER_SOURCE_CORRELATION',
        recovery_run='nso-sparse-params-v25', native_comparison_checks=runtime['total_checks'],
        before_source_sha256=hashlib.sha256(before_path.read_bytes()).hexdigest(),
        after_source_sha256=hashlib.sha256(after_path.read_bytes()).hexdigest(),
        relative_load_diagnostics_before=6, relative_load_diagnostics_after=0,
        recovered_reads=6, recovered_writes=3, wrapper_load_diagnostics_before=2, wrapper_load_diagnostics_after=0,
        scope='Two selected actual ILSpy methods without source edits. Source field paths correlate with strict '
              'actual recovered-CIL execution against the recorded original-code fixtures. Other methods in '
              'the same type still contain unresolved logic; full assemblies still fail compilation.')
    destination(ROOT, ROOT/'reports/generic-field-source-v25.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
