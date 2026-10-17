"""Read complete v37 logs; summarize type-error families without source edits."""
from collections import Counter
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination
from compiler_diagnostic_delta import ERROR


def main():
    report_path = ROOT / 'reports/recovered-source-profile-legacy-reference-check-nso-runtime-helper-abi-v37.json'
    summary = json.loads(report_path.read_text(encoding='utf-8-sig'))
    private = {}
    public = []
    for assembly in summary['assemblies']:
        seen = set()
        rows = []
        log = ROOT / assembly['compiler_log']
        for raw in log.read_text(encoding='utf-8-sig', errors='replace').splitlines():
            canonical = re.sub(r'^\d+>', '', raw.lstrip()).strip()
            if ': error ' not in canonical or canonical in seen:
                continue
            match = ERROR.match(canonical)
            if match is None:
                continue
            seen.add(canonical)
            path = Path(match[1].strip())
            rows.append(dict(path=str(path.relative_to(ROOT)), line=int(match[2]), column=int(match[3]), code=match[4], message=match[5].strip()))
        codes = Counter(r['code'] for r in rows)
        if len(rows) != assembly['unique_compiler_diagnostic_lines'] or dict(codes) != assembly['error_codes']:
            raise ValueError('Canonical compiler log count differs')
        casts = Counter()
        operators = Counter()
        for row in rows:
            if row['code'] == 'CS0030':
                pair = re.fullmatch(r"Cannot convert type '(.+)' to '(.+)'", row['message'])
                if pair:
                    casts[pair.groups()] += 1
            if row['code'] == 'CS0019':
                pair = re.fullmatch(r"Operator '(.+)' cannot be applied to operands of type '(.+)' and '(.+)'", row['message'])
                if pair:
                    operators[pair.groups()] += 1
        families = ('CS0030', 'CS0019', 'CS0023', 'CS0266', 'CS1061', 'CS0117')
        cast_files = Counter(r['path'] for r in rows if r['code'] in ('CS0030', 'CS0019'))
        private[assembly['assembly']] = rows
        public.append(dict(assembly=assembly['assembly'], unique_diagnostic_lines=len(rows), build_exit_code=assembly['build_exit_code'], compiler_log=assembly['compiler_log'], compiler_log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
            error_codes=dict(codes), selected_family_counts={c: codes[c] for c in families},
            cast_pairs=[dict(source_type=a, target_type=b, count=n) for (a, b), n in casts.most_common(30)],
            operator_pairs=[dict(operator=op, left_type=a, right_type=b, count=n) for (op, a, b), n in operators.most_common(30)],
            top_cast_operator_files=[dict(path=p, count=n) for p, n in cast_files.most_common(20)]))
    private_path = destination(ROOT, ROOT / 'analysis/reconstruction/compiler-family-v37/canonical-diagnostics.json')
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(json.dumps(private, indent=2) + '\n', encoding='utf-8')
    output = dict(status='READ_ONLY_CANONICAL_COMPILER_TYPE_FAMILY_COUNTS', recovery_run='nso-runtime-helper-abi-v37', assemblies=public,
        complete_matching_reference_report_sha256=hashlib.sha256(report_path.read_bytes()).hexdigest(), private_diagnostic_path=str(private_path.relative_to(ROOT)), private_diagnostic_sha256=hashlib.sha256(private_path.read_bytes()).hexdigest(),
        source_edited=False, core_edited=False, export_performed=False, source_excerpts_in_report=False, full_clean_decompile_ready=False,
        scope='Complete canonical unique compiler lines, deduplicated repeated build summaries. Diagnostic counts are not independent root causes or a decompilation completeness percentage. Source/native/IR candidate review is separate.')
    destination(ROOT, ROOT / 'reports/compiler-type-families-v37.json').write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')
    for row in public:
        print(row['assembly'], row['unique_diagnostic_lines'])
        print('casts', row['cast_pairs'][:12])
        print('operators', row['operator_pairs'][:10])
        print('files', row['top_cast_operator_files'][:8])


if __name__ == '__main__':
    main()
