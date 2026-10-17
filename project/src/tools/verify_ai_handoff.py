"""Read-only verification of the selected handoff evidence after a private copy."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def contained_file(root, relative):
    parts = PurePosixPath(relative)
    if parts.is_absolute() or '..' in parts.parts or not parts.parts:
        raise ValueError('Invalid relative manifest path')
    if '\\' in relative or any(':' in part for part in parts.parts):
        raise ValueError('Manifest paths must be relative forward-slash paths')
    candidate = root.joinpath(*parts.parts)
    if candidate.suffix.lower() in ('.keys', '.tik', '.cert'):
        raise ValueError('Credential files are excluded from handoff verification')
    for item in (candidate, *candidate.parents):
        if item.is_symlink() or hasattr(item, 'is_junction') and item.is_junction():
            raise ValueError('Symlink/junction in manifest path')
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(root) or resolved == root:
        raise ValueError('Manifest path escapes workspace')
    return resolved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--include-game-inputs', action='store_true',
                        help='Also hash the listed large original game inputs; key files are never read.')
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    manifest = json.loads((root / 'AI_HANDOFF_EVIDENCE_MANIFEST.json').read_text(encoding='utf-8'))
    rows = list(manifest['files'])
    if args.include_game_inputs:
        rows += manifest['recorded_game_input_hashes_not_rehashed_at_handoff']
    failures = []
    if len({row['path'] for row in rows}) != len(rows):
        raise ValueError('Duplicate manifest paths')
    for row in rows:
        path = contained_file(root, row['path'])
        if not path.is_file():
            failures.append({'path': row['path'], 'reason': 'missing'})
        elif digest(path) != row['sha256']:
            failures.append({'path': row['path'], 'reason': 'SHA-256 mismatch'})
    result = {'status': 'PASS_SELECTED_HANDOFF_BYTES' if not failures else 'FAIL_SELECTED_HANDOFF_BYTES',
              'files_checked': len(rows), 'game_inputs_rehashed': args.include_game_inputs,
              'failures': failures, 'files_modified': False,
              'scope': 'Transfer integrity for the selected evidence only; not a full-folder inventory, build, semantic validation or game readiness test.'}
    print(json.dumps(result, indent=2))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
