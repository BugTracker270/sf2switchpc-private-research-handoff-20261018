"""Correlate exact generic constructor identity, actual CIL and unchanged source."""
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination

ROOT = Path(__file__).resolve().parents[3]


def source(run, assembly):
    return ROOT / f'analysis/il2cpp/source-profile-project-build-{run}' / assembly


def calls(run, assembly):
    folder = source(run, assembly)
    return sum(path.read_text(encoding='utf-8-sig').count('._002Ector(')
               for path in folder.rglob('*.cs') if not {'obj', 'bin'}.intersection(path.relative_to(folder).parts))


def main():
    before_run, after_run = 'nso-type-handle-v26', 'nso-generic-ctor-v27'
    before_path = source(before_run, 'Assembly-CSharp') / 'BackKeyManager.cs'
    after_path = source(after_run, 'Assembly-CSharp') / 'BackKeyManager.cs'
    before, after = before_path.read_text(), after_path.read_text()
    if before.count('._002Ector(') != 2 or '._002Ector(' in after or 'FormatterServices.GetUninitializedObject' in after:
        raise ValueError('Selected unchanged source did not recover normal construction')
    if not re.search(r'_backKeyListeners\s*=\s*new List<BackKeyController>\(\);', after):
        raise ValueError('Expected the actual recovered instance field initializer')
    rows = [dict(assembly=a, escaped_constructor_calls_before=calls(before_run, a), escaped_constructor_calls_after=calls(after_run, a))
            for a in ['Assembly-CSharp-firstpass', 'Assembly-CSharp']]
    if any(row['escaped_constructor_calls_after'] >= row['escaped_constructor_calls_before'] for row in rows):
        raise ValueError('Expected escaped constructor spelling count to decrease in both actual source exports')
    old = json.loads((ROOT/f'reports/recovered-constructor-{before_run}.json').read_text())
    new = json.loads((ROOT/f'reports/recovered-constructor-{after_run}.json').read_text())
    identity = json.loads((ROOT/f'reports/recovered-allocation-identity-{after_run}.json').read_text())
    if (old['status'] != 'PASS_RECOVERED_CONSTRUCTION_AT_CLR_LIST_BOUNDARY'
            or new['status'] != old['status'] or old['direct_constructor_calls'] != 1 or old['raw_allocation_calls'] != 1
            or new['direct_constructor_calls'] != 0 or new['raw_allocation_calls'] != 0 or new['newobj_constructors'] != 1
            or identity['status'] != 'PASS_STATIC_ALLOCATION_IDENTITY_ONLY'):
        raise ValueError('Actual construction equivalence and separate-allocation identity gates required')
    report = dict(status='PASS_SCOPED_CLOSED_GENERIC_CONSTRUCTION_CIL_AND_SOURCE_CORRELATION', recovery_run=after_run,
        assemblies=rows, selected_escaped_constructor_calls_before=2, selected_escaped_constructor_calls_after=0,
        before_source_sha256=hashlib.sha256(before_path.read_bytes()).hexdigest(),
        after_source_sha256=hashlib.sha256(after_path.read_bytes()).hexdigest(),
        constructor_checks_before=old['checks'], constructor_checks_after=new['checks'],
        separate_allocation_identity=identity['status'], source_edits=False, full_constructor_validated=False,
        whole_game_source_ready=False,
        scope='The exact closed generic constructor owner mismatch is corrected without moving across block, '
              'receiver or ordering barriers. Actual recovered expressions compare at the host CLR List<T> boundary, '
              'stopping before Unity base initialization. An unrelated native-witnessed separate allocation retains '
              'VersionContainer identity. The selected source renders an instance initializer and implicit base '
              'constructor; no source text is rewritten. Original ARM64 constructor/GC/initialization, the remainder '
              'of this class and complete assemblies remain unverified or fail compilation.')
    destination(ROOT, ROOT/'reports/generic-constructor-source-v27.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
