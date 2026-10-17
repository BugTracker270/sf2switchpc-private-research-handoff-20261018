"""Freeze every candidate tool source against its completed recovery invocation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-label', required=True)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    if any(not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,79}', v)
           for v in (args.artifact_label, args.run)):
        parser.error('labels must be lowercase letters, digits and hyphens')
    lock_path = ROOT / f'reports/cpp2il-hfa-experimental-lock-{args.artifact_label}.json'
    invocation_path = ROOT / f'logs/cpp2il-{args.run}-result.json'
    lock_bytes, invocation_bytes = lock_path.read_bytes(), invocation_path.read_bytes()
    lock, invocation = json.loads(lock_bytes), json.loads(invocation_bytes)
    if invocation['exit_code'] != 0 or lock['source_inventory_coverage_verified'] is not True:
        raise ValueError('Completed invocation and complete candidate inventory required')
    if not lock['files'] or len({x['path'] for x in lock['files']}) != len(lock['files']):
        raise ValueError('Empty or duplicate source inventory')
    patch = destination(ROOT, ROOT / lock['patch'])
    if sha(patch) != lock['sha256']:
        raise ValueError('Candidate patch changed')
    core = ROOT / 'refs/Cpp2IL/Cpp2IL.Core/bin/Release/net10.0/Cpp2IL.Core.dll'
    core_hash = invocation['tool_assembly_sha256']['Cpp2IL.Core.dll']
    if sha(core) != core_hash:
        raise ValueError('Live Core no longer matches completed invocation')
    base = destination(ROOT, ROOT / f'analysis/il2cpp/{args.artifact_label}-source-snapshot')
    if base.exists():
        manifest = json.loads((base / 'manifest.json').read_text(encoding='utf-8'))
        if manifest['core_sha256'] != core_hash or manifest['candidate_lock_sha256'] != sha(lock_path) \
                or manifest['recovery_invocation_sha256'] != sha(invocation_path) \
                or sha(base / 'candidate-lock.json') != sha(lock_path) \
                or sha(base / 'recovery-invocation.json') != sha(invocation_path) \
                or {(x['path'], x['sha256']) for x in manifest['sources']} != {
                    (str(Path('refs/Cpp2IL') / x['path']), x['sha256']) for x in lock['files']} \
                or any(sha(ROOT / x['snapshot_path']) != x['sha256'] for x in manifest['sources']):
            raise ValueError('Existing immutable snapshot differs; preserve it')
    else:
        staging = destination(ROOT, ROOT / (str(base.relative_to(ROOT)) + '.staging-' + uuid.uuid4().hex))
        staging.mkdir(parents=True)
        rows = []
        for row in lock['files']:
            source = destination(ROOT, ROOT / 'refs/Cpp2IL' / row['path'])
            if not source.is_relative_to(ROOT / 'refs/Cpp2IL'):
                raise ValueError('Source outside tool checkout')
            content = source.read_bytes()
            if hashlib.sha256(content).hexdigest() != row['sha256']:
                raise ValueError('Source changed before capture: ' + row['path'])
            relative = source.relative_to(ROOT)
            target = destination(ROOT, staging / relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(content)
            rows.append(dict(path=str(relative), snapshot_path=str((base / relative).relative_to(ROOT)),
                             sha256=row['sha256']))
        if any(sha(ROOT / x['path']) != x['sha256'] for x in rows) or sha(core) != core_hash:
            raise ValueError('Sources/Core changed during capture; staging preserved')
        for name, content in [('candidate-lock.json', lock_bytes), ('recovery-invocation.json', invocation_bytes)]:
            destination(ROOT, staging / name).write_bytes(content)
        manifest = dict(status='PASS_IMMUTABLE_COMPLETE_CANDIDATE_SOURCE_CAPTURE',
                        recovery_run=args.run, core_sha256=core_hash, sources=rows, source_count=len(rows),
                        candidate_lock_sha256=hashlib.sha256(lock_bytes).hexdigest(),
                        recovery_invocation_sha256=hashlib.sha256(invocation_bytes).hexdigest(),
                        candidate_patch_sha256=lock['sha256'], capture_source_sha256=sha(Path(__file__)),
                        source_mutated=False, core_built=False)
        destination(ROOT, staging / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8', newline='\n')
        if base.exists():
            raise FileExistsError('Snapshot appeared concurrently; no overwrite')
        staging.replace(base)
    report = dict(manifest, manifest_path=str((base / 'manifest.json').relative_to(ROOT)),
                  manifest_sha256=sha(base / 'manifest.json'))
    destination(ROOT, ROOT / f'reports/{args.artifact_label}-source-snapshot.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: report[k] for k in ('status', 'source_count', 'core_sha256', 'manifest_sha256')}))


if __name__ == '__main__':
    main()
