"""Save bounded private compiler/source contexts and public hash-only locations."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def main():
    data = json.loads((ROOT / 'analysis/reconstruction/compiler-family-v37/canonical-diagnostics.json').read_text())
    summary = json.loads((ROOT / 'reports/recovered-source-profile-legacy-reference-check-nso-runtime-helper-abi-v37.json').read_text(encoding='utf-8-sig'))
    expected = {row['path'].replace('\\', '/'): row for assembly in summary['assemblies'] for row in assembly['source_files']}
    samples = []
    public = []
    for assembly, rows in data.items():
        for family, pattern in [('type_pointer', "Cannot convert type 'System.Type' to 'nint'"), ('mapping_array_pointer', "Cannot convert type 'InControl.InputControlMapping[]' to 'nint'"),
                                ('object_mask', "Operator '&' cannot be applied to operands of type 'object' and 'int'"), ('object_array_pointer', "Cannot convert type 'object[]' to 'nint'")]:
            matching = [row for row in rows if row['message'] == pattern]
            by_file = Counter(row['path'] for row in matching)
            chosen = []
            for path, count in by_file.most_common(2):
                row = next(r for r in matching if r['path'] == path)
                source_path = ROOT / path
                raw = source_path.read_bytes()
                sha = hashlib.sha256(raw).hexdigest()
                if expected[path.replace('\\', '/')]['sha256'] != sha:
                    raise ValueError('Recovered exported source changed')
                lines = raw.decode('utf-8-sig').splitlines()
                record = dict(assembly=assembly, family=family, path=path, line=row['line'], diagnostic_count_in_file=count, source_sha256=sha)
                chosen.append(record)
                samples.append(dict(**record, diagnostic=row['message'], context_start=max(1, row['line']-20), context_lines=lines[max(0, row['line']-21):row['line']+22]))
                print(assembly, family, path, row['line'], count)
            public.extend(chosen)
    private = destination(ROOT, ROOT / 'analysis/reconstruction/compiler-family-v37/selected-source-contexts.json')
    private.write_text(json.dumps(samples, indent=2) + '\n', encoding='utf-8')
    destination(ROOT, ROOT / 'reports/compiler-type-family-sample-locations-v37.json').write_text(json.dumps(dict(status='READ_ONLY_SELECTED_SOURCE_HASHES_AND_LOCATIONS', samples=public, private_context_path=str(private.relative_to(ROOT)), private_context_sha256=hashlib.sha256(private.read_bytes()).hexdigest(), source_edited=False, source_excerpts_in_report=False), indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
