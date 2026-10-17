"""Correlate the corrected class macro with retained actual caller operations."""
import hashlib
import json
import re
from pathlib import Path
from execute_native_ai_leaves import ROOT
from usb_boundary import destination


def method(folder):
    files = list((ROOT / folder).glob('*.cs'))
    if len(files) != 1:
        raise ValueError('Expected a single selected-type export')
    text = files[0].read_text()
    start = text.index('SetRelativeEndValue(')
    opening = text.index('{', start)
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == '{':
            depth += 1
        elif text[index] == '}':
            depth -= 1
            if depth == 0:
                body = text[opening:index + 1]
                break
    else:
        raise ValueError('Unterminated selected method')
    fields = ['10C', '110', '114', '118', '11C', '120']
    return dict(path=str(files[0].relative_to(ROOT)), source_sha256=hashlib.sha256(files[0].read_bytes()).hexdigest(),
                class_flag_diagnostics=body.count('Il2CppClass<UnityEngine.Vector3>)+122'),
                native_component_load_diagnostics={offset: body.count(')+' + offset + ']') for offset in fields},
                vector_additions=len(re.findall(r'\bvector\d*\s*\+\s*vector\d*', body)))


def main():
    before = method('analysis/il2cpp/hfa-caller-v20d')
    after = method('analysis/il2cpp/hfa-caller-v21')
    native = json.loads((ROOT/'reports/native-fp-class-guard-caller.json').read_text())
    if (before['class_flag_diagnostics'] != 1 or after['class_flag_diagnostics'] != 0
            or before['native_component_load_diagnostics'] != after['native_component_load_diagnostics']
            or set(after['native_component_load_diagnostics'].values()) != {1}
            or before['vector_additions'] != 1 or after['vector_additions'] != 1
            or native['status'] != 'PASS_ORIGINAL_FP_SCHEDULED_CLASS_GUARD_HFA_CALLER'):
        raise ValueError('Actual source/native correlation differs from expected narrow correction')
    report = dict(status='PASS_SCOPED_FP_CLASS_MACRO_SOURCE_CORRELATION', recovery_run='nso-class-fp-loads-v21',
                  before=before, after=after, native_cases=native['cases'], native_checks=native['checks'],
                  scope='One actual DOTween caller export: class-byte diagnostic removed while all six component '
                        'load diagnostics and the addition remain. Independent original caller execution is supporting '
                        'evidence; generic nested field recovery, recovered-caller execution and complete source '
                        'still fail/unverified. No clean-method or class-initialization ordering certification.')
    destination(ROOT, ROOT/'reports/recovered-fp-class-guard-nso-class-fp-loads-v21.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
