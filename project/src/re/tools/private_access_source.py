"""Correlate proven handle setter with unchanged recovered C# source exports."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def main():
    run = sys.argv[1] if len(sys.argv) == 2 else 'nso-native-leaves-v28'
    if not re.fullmatch('[a-z0-9-]+', run):
        raise ValueError('Invalid recovery run')
    before = ROOT / 'analysis/il2cpp/source-profile-project-build-nso-generic-ctor-v27/Assembly-CSharp'
    after = ROOT / f'analysis/il2cpp/source-profile-project-build-{run}/Assembly-CSharp'
    before_manifest = json.loads((ROOT / 'reports/recovered-source-profile-legacy-reference-check-nso-generic-ctor-v27.json').read_text(encoding='utf-8-sig'))
    log = ROOT / next(row['compiler_log'] for row in before_manifest['assemblies'] if row['assembly'] == 'Assembly-CSharp')
    relative_files = set()
    for line in log.open(encoding='utf-8-sig', errors='replace'):
        if "error CS0122: 'InputControlMapping.handle'" not in line:
            continue
        match = re.match(r'(.+\.cs)\(\d+,\d+\):', line)
        relative_files.add(Path(match[1].strip()).relative_to(before))
    counts = {'before_field_stores': 0, 'after_field_stores': 0, 'before_property_stores': 0, 'after_property_stores': 0}
    for relative in relative_files:
        for label, folder in [('before', before), ('after', after)]:
            text = (folder / relative).read_text(encoding='utf-8-sig')
            counts[label + '_field_stores'] += len(re.findall(r'\.handle\s*=(?!=)', text))
            counts[label + '_property_stores'] += len(re.findall(r'\.Handle\s*=(?!=)', text))
    if counts['before_field_stores'] != 673 or counts['after_field_stores'] != 0:
        raise ValueError('Expected all 673 prior inaccessible handle stores to disappear from the same actual exported files')
    if counts['after_property_stores'] < counts['before_property_stores'] + 673:
        raise ValueError('Expected corresponding existing public property setter expressions')
    required = {
        'selection': ('reports/private-access-leaf-selection-v28.json', 'PASS_NATIVE_LEAF_ACCESSOR_SELECTION_ONLY'),
        'native': ('reports/private-access-native-store-v28.json', 'PASS_ORIGINAL_REFERENCE_FIELD_SETTER'),
        'recovered': (f'reports/recovered-leaf-accessor-{run}.json', 'PASS_RECOVERED_LEAF_ACCESSOR_AT_ISOLATED_STORAGE_BOUNDARY'),
    }
    gates = {}
    for name, (relative, expected) in required.items():
        evidence = json.loads((ROOT / relative).read_text(encoding='utf-8-sig'))
        if evidence['status'] != expected:
            raise ValueError(f'{name} proof is incomplete')
        gates[name] = dict(status=expected, checks=evidence['checks'])
    selected = Path('InControl/GoogleNexusPlayerRemoteProfile.cs')
    report = dict(status='PASS_SCOPED_PRIVATE_FIELD_TO_NATIVE_PROVEN_PUBLIC_SETTER_SOURCE_CORRELATION', recovery_run=run,
        source_files=len(relative_files), **counts, proof_gates=gates,
        before_selected_source_sha256=hashlib.sha256((before / selected).read_bytes()).hexdigest(),
        after_selected_source_sha256=hashlib.sha256((after / selected).read_bytes()).hexdigest(),
        source_text_edited=False, original_field_privacy_preserved=True, new_game_metadata_added=False,
        whole_game_source_ready=False,
        scope='All 673 prior inaccessible InputControlMapping.handle stores in the same exported source files become existing public Handle setter expressions. Actual recovered setter/caller expressions execute at isolated CLR storage boundaries; the exact original native setter separately passes pointer-store tests. The effectful getter is not used for arbitrary loads. Remaining assemblies, profile constructors and Unity/class-initialization/GC behavior are not validated by this count.')
    destination(ROOT, ROOT / f'reports/private-access-source-{run}.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
