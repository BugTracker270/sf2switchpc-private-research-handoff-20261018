"""Compare complete matching-reference compiler diagnostics without editing source."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination

ERROR = re.compile(r'^(.*?)\((\d+),(\d+)\): error (CS\d+|[A-Z]+\d+): (.*?)(?: \[.*\])?$')
ASSEMBLIES = ('Assembly-CSharp-firstpass', 'Assembly-CSharp')
KIND = 'source-profile-legacy-reference-check'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def document(relative):
    path = destination(ROOT, ROOT / relative)
    return json.loads(path.read_text(encoding='utf-8-sig')), dict(path=relative, sha256=digest(path))


def inspect(run, assembly):
    summary, summary_fact = document(f'reports/recovered-{KIND}-{run}.json')
    profile, profile_fact = document(f'reports/recovered-source-profile-project-build-{run}.json')
    row = next(row for row in summary['assemblies'] if row['assembly'] == assembly)
    export = next(row for row in profile['assemblies'] if row['assembly'] == assembly)
    if row['restore_exit_code'] != 0 or export['export_exit_code'] != 0:
        raise ValueError('Complete export and successful matching-reference restore required')
    if row['source_files'] != export['source_files']:
        raise ValueError('Matching-reference build must use unchanged exported source manifest')
    base = destination(ROOT, ROOT / f'analysis/il2cpp/source-profile-project-build-{run}/{assembly}')
    log = destination(ROOT, ROOT / row['compiler_log'])
    seen = set()
    rows = []
    with log.open(encoding='utf-8-sig', errors='replace') as stream:
        for line in stream:
            canonical = re.sub(r'^\d+>', '', line.lstrip()).strip()
            if ': error ' not in canonical or canonical in seen:
                continue
            match = ERROR.match(canonical)
            if not match:
                continue
            seen.add(canonical)
            source = Path(match[1].strip())
            if not source.is_absolute():
                raise ValueError('Nonabsolute compiler diagnostic path')
            relative = source.relative_to(base).as_posix()
            rows.append(dict(file=relative, line=int(match[2]), column=int(match[3]),
                             code=match[4], message=match[5].strip()))
    if len(rows) != row['unique_compiler_diagnostic_lines']:
        raise ValueError((run, assembly, 'Canonical counts disagree', len(rows), row['unique_compiler_diagnostic_lines']))
    if dict(Counter(item['code'] for item in rows)) != row['error_codes']:
        raise ValueError('Canonical compiler error-code counts disagree')
    indexed = {(ROOT / item['path']).relative_to(base).as_posix(): item for item in row['source_files']}
    facts = {}
    for file in {item['file'] for item in rows}:
        item = indexed[file]
        source = destination(ROOT, base / file)
        sha = digest(source)
        if source.stat().st_size != item['bytes'] or sha != item['sha256']:
            raise ValueError('Original exported source changed: ' + file)
        facts[file] = dict(bytes=item['bytes'], sha256=sha)
    return rows, facts, dict(summary=summary_fact, export=profile_fact,
                             manifest_sha256=profile_fact['sha256'],
                             compiler_log=dict(path=str(log.relative_to(ROOT)), sha256=digest(log)),
                             build_exit_code=row['build_exit_code'],
                             restore_exit_code=row['restore_exit_code'],
                             source_manifest_files=len(indexed),
                             diagnostic_source_files_hash_verified=len(facts),
                             matching_reference_source_manifest_unchanged=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', required=True)
    parser.add_argument('--after', required=True)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument('--label', help='Write reports/compiler-diagnostic-delta-LABEL.json')
    output.add_argument('--report', help='Compatible existing report identifier without extension')
    args = parser.parse_args()
    identifier = args.label or args.report
    if any(not re.fullmatch('[a-z0-9-]+', value) for value in (args.before, args.after, identifier)):
        raise ValueError('Invalid run or report label')
    result = dict(status='PASS_CANONICAL_COMPLETE_SOURCE_COMPILER_COMPARISON',
                  before_run=args.before, after_run=args.after, before=args.before, after=args.after,
                  source_modified=False, core_modified=False, assemblies={})
    for assembly in ASSEMBLIES:
        old, old_facts, old_gate = inspect(args.before, assembly)
        new, new_facts, new_gate = inspect(args.after, assembly)
        old_codes = Counter(item['code'] for item in old)
        new_codes = Counter(item['code'] for item in new)
        semantic = lambda rows: Counter((item['file'], item['code'], item['message']) for item in rows)
        added, removed = semantic(new) - semantic(old), semantic(old) - semantic(new)
        def message_counts(counts):
            grouped = Counter()
            for (_, code, message), count in counts.items():
                grouped[code, message] += count
            return grouped
        added_files = Counter()
        for (file, _, _), count in added.items():
            added_files[file] += count
        old_files, new_files = (Counter(item['file'] for item in rows) for rows in (old, new))
        changed_files = [file for file in set(old_files) | set(new_files) if old_files[file] != new_files[file]]
        file_order = sorted(changed_files, key=lambda file: (-abs(new_files[file] - old_files[file]), file))[:20]
        result['assemblies'][assembly] = dict(
            before_unique=len(old), after_unique=len(new), old_unique=len(old), new_unique=len(new), delta=len(new) - len(old),
            before_error_codes=dict(old_codes), after_error_codes=dict(new_codes),
            error_code_delta={code: new_codes[code] - old_codes[code] for code in sorted(set(old_codes) | set(new_codes)) if old_codes[code] != new_codes[code]},
            semantic_added_occurrences=sum(added.values()), semantic_removed_occurrences=sum(removed.values()),
            top_added_messages=[dict(code=key[0], message=key[1], count=count) for key, count in message_counts(added).most_common(12)],
            most_added_messages=[dict(code=key[0], message=key[1], count=count) for key, count in message_counts(added).most_common(20)],
            most_added_files=[dict(file=file, count=count) for file, count in added_files.most_common(20)],
            top_removed_messages=[dict(code=key[0], message=key[1], count=count) for key, count in message_counts(removed).most_common(12)],
            top_changed_files=[dict(file=file, before=old_files[file], after=new_files[file], delta=new_files[file] - old_files[file], before_source=old_facts.get(file), after_source=new_facts.get(file)) for file in file_order],
            source_integrity={args.before: old_gate, args.after: new_gate})
    result['compiler_diagnostic_delta'] = {assembly: row['delta'] for assembly, row in result['assemblies'].items()}
    result['whole_game_source_ready'] = False
    result['full_clean_decompile_ready'] = False
    result['portable_game_ready'] = False
    result['methodology'] = 'Each complete matching-reference log is streamed. Canonical lines remove build-worker prefixes, surrounding whitespace and duplicate build-summary occurrences, and must exactly match the authoritative summary total and error-code counts. Multisets of relative source path, code and message additionally reduce line-shift inflation; local-name or decompiler presentation changes can still alter messages. Every diagnostic-bearing file is checked against the byte-identical export/matching-reference source manifest. Reports contain no source excerpts.'
    result['limits'] = 'Diagnostic lines include compiler cascades and are not independent bugs, recovered-method counts or completion percentages. This read-only comparison neither executes recovered game methods nor establishes that added or removed diagnostics correspond to correct semantics. Complete source compilation, original-runtime/gameplay parity and portability remain separate requirements.'
    output_name = f'compiler-diagnostic-delta-{args.label}' if args.label else args.report
    output_path = destination(ROOT, ROOT / f'reports/{output_name}.json')
    output_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(status=result['status'], compiler_diagnostic_delta=result['compiler_diagnostic_delta'], counts={assembly: dict(before=row['before_unique'], after=row['after_unique']) for assembly, row in result['assemblies'].items()})))


if __name__ == '__main__':
    main()
