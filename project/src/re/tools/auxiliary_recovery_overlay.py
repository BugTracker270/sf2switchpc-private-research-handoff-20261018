"""Preserve failed auxiliary exports and account for explicit retry overlays."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination
ROOT = Path(__file__).resolve().parents[3]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', choices=['sdk', 'subsdk0', 'rtld'], required=True)
    parser.add_argument('--prepare-overlay')
    args = parser.parse_args()
    folder = ROOT / f'analysis/nso/auxiliary-{args.module}-v1'
    selection = json.loads((folder / 'selection.json').read_text(encoding='utf-8-sig'))
    original = ROOT / f'analysis/nso/{args.module}-uncompressed.nso'
    if hashlib.sha256(original.read_bytes()).hexdigest() != selection['uncompressed_sha256']:
        raise ValueError('Original module digest differs')
    targets = json.loads((folder / 'targets.json').read_text(encoding='utf-8-sig'))
    expected = {row['rva']: row for row in targets}
    if len(expected) != selection['total_validated_ranges']:
        raise ValueError('Invalid original target set')
    frame_path = ROOT / f'analysis/nso/module-inventory-v2/{args.module}-frames.jsonl'
    if hashlib.sha256(frame_path.read_bytes()).hexdigest() != selection['frame_file_sha256']:
        raise ValueError('Independent frame inventory changed')
    frames = {row['rva']: row for row in map(json.loads, frame_path.open(encoding='utf-8'))}
    if set(frames) != set(expected) or any(row['end_rva'] != frames[rva]['end_rva'] or row['module'] != args.module
                                         for rva, row in expected.items()):
        raise ValueError('Target ranges differ from independent module frames')
    def is_good(row):
        return row['status'] == 'PSEUDOCODE_EXPORTED' and bool(row.get('pseudocode'))
    best, layers, historical_failures = {}, [], 0
    for corpus in [folder / 'corpus/functions.jsonl'] + sorted(folder.glob('overlay-*/functions.jsonl')):
        seen = set()
        with corpus.open(encoding='utf-8') as stream:
            for row in map(json.loads, stream):
                rva = row['rva']
                if rva in seen or rva not in expected or row['end_rva'] != expected[rva]['end_rva'] or row['module'] != args.module:
                    raise ValueError('Duplicate, wrong-module or non-inventory retry record')
                seen.add(rva)
                good = is_good(row)
                if not good:
                    historical_failures += 1
                if good or rva not in best or not is_good(best[rva]):
                    best[rva] = row
        layers.append(dict(path=str(corpus.relative_to(ROOT)), records=len(seen),
                           sha256=hashlib.sha256(corpus.read_bytes()).hexdigest()))
    remaining = [row for rva, row in expected.items()
                 if rva not in best or not is_good(best[rva])]
    if args.prepare_overlay:
        if not re.fullmatch('[a-z0-9-]+', args.prepare_overlay):
            raise ValueError('Invalid overlay identifier')
        output = destination(ROOT, folder / f'overlay-{args.prepare_overlay}')
        if output.exists() or not remaining:
            raise ValueError('Preserve prior overlay, or no unresolved targets remain')
        output.mkdir()
        destination(ROOT, output / 'targets.json').write_text(json.dumps(remaining, indent=2) + '\n', encoding='utf-8')
        destination(ROOT, output / 'selection.json').write_text(json.dumps(dict(
            module=args.module, unresolved_targets=len(remaining), baseline_layers=layers,
            source_sha256=selection['uncompressed_sha256']), indent=2) + '\n', encoding='utf-8')
        print(json.dumps(dict(overlay=str(output), targets=len(remaining))))
        return
    succeeded = len(expected) - len(remaining)
    report = dict(module=args.module,
                  status='AUXILIARY_RANGE_EXPORT_COMPLETE' if not remaining else 'AUXILIARY_RANGE_EXPORT_INCOMPLETE',
                  total_targets=len(expected), ranges_with_pseudocode=succeeded,
                  unresolved_ranges=len(remaining), historical_failed_records=historical_failures,
                  layers=layers, source_sha256=selection['uncompressed_sha256'],
                  scope='Independent module range exports with preserved failed attempts and explicit retry overlays. '
                        'Every original target is accounted for once in the resolved view. No main RVA index mutation, '
                        'clean-source or semantic-completeness claim.')
    destination(ROOT, ROOT / f'reports/native-auxiliary-{args.module}-resolved-v1.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
