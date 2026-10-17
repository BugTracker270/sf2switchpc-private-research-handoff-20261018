"""Preserve exact compiler addition candidates without claiming semantic attribution."""
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
from compiler_diagnostic_delta import ERROR


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+', args.label):
        raise ValueError('Invalid label')
    canonical_path = ROOT / f'reports/compiler-diagnostic-delta-{args.label}.json'
    canonical = load(canonical_path)
    if canonical['status'] != 'PASS_CANONICAL_COMPLETE_SOURCE_COMPILER_COMPARISON':
        raise ValueError('Completed canonical comparison required')
    before, after = canonical['before_run'], canonical['after_run']
    groups, contexts = [], []
    for assembly, comparison in canonical['assemblies'].items():
        by_run = {}
        facts = {}
        for run in (before, after):
            summary_path = ROOT / f'reports/recovered-source-profile-legacy-reference-check-{run}.json'
            summary = load(summary_path)
            row, = [item for item in summary['assemblies'] if item['assembly'] == assembly]
            log = ROOT / row['compiler_log']
            integrity = comparison['source_integrity'][run]
            if sha(summary_path) != integrity['summary']['sha256'] or sha(log) != integrity['compiler_log']['sha256']:
                raise ValueError('Canonical receipts changed')
            base = ROOT / f'analysis/il2cpp/source-profile-project-build-{run}/{assembly}'
            seen, diagnostics = set(), []
            for line in log.open(encoding='utf-8-sig', errors='replace'):
                text = re.sub(r'^\d+>', '', line.lstrip()).strip()
                if text in seen or ': error ' not in text:
                    continue
                match = ERROR.match(text)
                if not match:
                    continue
                seen.add(text)
                file = Path(match[1].strip()).relative_to(base).as_posix()
                diagnostics.append(dict(file=file, line=int(match[2]), column=int(match[3]),
                                        code=match[4], message=match[5].strip()))
            if len(diagnostics) != row['unique_compiler_diagnostic_lines']:
                raise ValueError('Diagnostic totals differ')
            by_run[run] = diagnostics
            facts[run] = {str((ROOT / item['path']).relative_to(base).as_posix()):item for item in row['source_files']}
        key = lambda item:(item['file'], item['code'], item['message'])
        old, new = (Counter(map(key, by_run[run])) for run in (before, after))
        for signature, amount in sorted((new - old).items()):
            occurrences = {}
            for run in (before, after):
                rows = [item for item in by_run[run] if key(item) == signature]
                occurrences[run] = rows
                source = ROOT / f'analysis/il2cpp/source-profile-project-build-{run}/{assembly}/{signature[0]}'
                if source.exists():
                    if sha(source) != facts[run][signature[0]]['sha256']:
                        raise ValueError('Candidate source changed')
                    lines = source.read_text(encoding='utf-8-sig').splitlines()
                    for item in rows:
                        prefix = lines[:item['line']]
                        declarations = [(index+1, text.strip()) for index,text in enumerate(prefix)
                            if re.match(r'^\s*(public|private|internal|protected)\b',text) and '(' in text and not text.rstrip().endswith(';')]
                        nearest = declarations[-1] if declarations else None
                        item['nearest_declaration_candidate'] = dict(line=nearest[0], text=nearest[1]) if nearest else None
                        contexts.append(dict(assembly=assembly,run=run,diagnostic=item,
                            source_sha256=facts[run][signature[0]]['sha256'],
                            context_start=max(1,item['line']-9),
                            context=lines[max(0,item['line']-10):item['line']+8]))
            groups.append(dict(assembly=assembly,file=signature[0],code=signature[1],message=signature[2],
                added_multiplicity=amount,before_count=old[signature],after_count=new[signature],
                after_locations_uniquely_new_semantic_key=old[signature] == 0,occurrences=occurrences,
                semantic_attribution='UNATTRIBUTED_REQUIRES_ORIGINAL_NATIVE_AND_CIL_PROOF'))
    private = destination(ROOT, ROOT / f'analysis/reconstruction/compiler-additions-{args.label}/source-context.json')
    private.parent.mkdir(parents=True,exist_ok=True)
    private.write_text(json.dumps(contexts,indent=2)+'\n',encoding='utf-8')
    report = dict(status='EXACT_CANONICAL_ADDITION_LOCATION_CANDIDATES_UNATTRIBUTED',
        before_run=before,after_run=after,added_occurrences=sum(item['added_multiplicity'] for item in groups),
        groups=groups,canonical_report_sha256=sha(canonical_path),
        private_source_context_sha256=sha(private),private_source_context=str(private.relative_to(ROOT)),
        probe_source_sha256=sha(Path(__file__)),source_modified=False,core_modified=False,
        native_or_cil_semantics_verified=False,full_clean_decompile_ready=False,
        limits='Groups compare relative file/code/message multiplicity, reducing line shifts. All before/after candidates are retained when an existing key grows; no arbitrary occurrence is declared uniquely new. Nearest declarations are textual candidates, not verified owners. Source and complete log hashes bind the canonical comparison. Original source context stays private. Added diagnostics are not automatically regressions or harmless exposures.')
    output = destination(ROOT, ROOT / f'reports/compiler-diagnostic-added-locations-{args.label}.json')
    output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=report['status'],added_occurrences=report['added_occurrences'],groups=groups)))


if __name__ == '__main__':
    main()
