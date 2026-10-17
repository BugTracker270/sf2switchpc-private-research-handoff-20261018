"""Narrow file/message growth by textual declaration; does not prove semantics."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+', args.label):
        raise ValueError('Invalid label')
    source = ROOT / f'reports/compiler-diagnostic-added-locations-{args.label}.json'
    data = json.loads(source.read_text(encoding='utf-8-sig'))
    before, after = data['before_run'], data['after_run']
    def declaration(row):
        candidate = row['nearest_declaration_candidate']
        if candidate is None:
            return '<unknown>'
        return re.sub(r'\s+', ' ', re.sub(r'\bunsafe\s+', '', candidate['text'])).strip()
    groups = []
    for group in data['groups']:
        old, new = [Counter(map(declaration, group['occurrences'][run])) for run in (before, after)]
        for method, amount in sorted((new-old).items()):
            groups.append(dict(assembly=group['assembly'],file=group['file'],code=group['code'],message=group['message'],
                declaration_candidate=method,added_multiplicity=amount,
                before_method_occurrences=old[method],after_method_occurrences=new[method],
                after_location_candidates=[row for row in group['occurrences'][after] if declaration(row)==method],
                before_location_candidates=[row for row in group['occurrences'][before] if declaration(row)==method],
                uniquely_new_method_message_key=old[method]==0))
    output = dict(status='METHOD_GROUPED_ADDITION_CANDIDATES_UNATTRIBUTED',before_run=before,after_run=after,
        original_file_group_growth=data['added_occurrences'],method_group_growth=sum(row['added_multiplicity'] for row in groups),
        groups=groups,location_report_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),source_modified=False,core_modified=False,
        native_or_cil_semantics_verified=False,
        limits='Textual declaration candidates are not verified method owners. Existing message growth keeps every before/after location within the same declaration. A source body/CIL/native comparison is still required, including renamed diagnostics and pointer-result control uses. No occurrence is arbitrarily selected from a growing multiplicity.')
    path=destination(ROOT,ROOT/f'reports/compiler-diagnostic-added-methods-{args.label}.json')
    path.write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=output['status'],method_group_growth=output['method_group_growth'],groups=groups)))


if __name__=='__main__':
    main()
