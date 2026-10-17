"""Capture the six reviewed v36 tool sources once, with immutable provenance."""
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    review_path = ROOT / 'reports/virtual-dispatch-independent-source-review-v36.json'
    invocation_path = ROOT / 'logs/cpp2il-nso-virtual-dispatch-v36-result.json'
    review_bytes, invocation_bytes = review_path.read_bytes(), invocation_path.read_bytes()
    review, invocation = json.loads(review_bytes), json.loads(invocation_bytes)
    core_hash = invocation['tool_assembly_sha256']['Cpp2IL.Core.dll']
    if len(review['reviewed_sources']) != 6 or review['stable_tested_core_sha256'] != core_hash or invocation['exit_code'] != 0:
        raise ValueError('Final six-source/Core provenance differs')
    base = destination(ROOT, ROOT / 'analysis/il2cpp/virtual-dispatch-v36-source-snapshot')
    if base.exists():
        manifest = json.loads((base / 'manifest.json').read_text(encoding='utf-8-sig'))
        if manifest['core_sha256'] != core_hash or any(sha(ROOT / row['snapshot_path']) != row['sha256'] for row in manifest['sources']):
            raise ValueError('Existing immutable source snapshot differs; preserve it')
        print(json.dumps(dict(status='VERIFIED_EXISTING_IMMUTABLE_V36_SOURCE_SNAPSHOT', sources=len(manifest['sources']))))
        return
    # Both directory rename targets are absolute USB destinations checked against reparse/traversal escape.
    staging = destination(ROOT, ROOT / ('analysis/il2cpp/virtual-dispatch-v36-source-snapshot.staging-' + uuid.uuid4().hex))
    staging.mkdir(parents=True)
    sources = []
    for row in review['reviewed_sources']:
        original = destination(ROOT, ROOT / row['path'])
        if not original.is_relative_to(ROOT / 'refs/Cpp2IL/Cpp2IL.Core'):
            raise ValueError('Unexpected reviewed source location')
        data = original.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != row['sha256']:
            raise ValueError('Live source changed before capture: ' + row['path'])
        relative = original.relative_to(ROOT)
        target = destination(ROOT, staging / relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        sources.append(dict(path=str(relative), snapshot_path=str((base / relative).relative_to(ROOT)), sha256=digest))
    if any(sha(ROOT / row['path']) != row['sha256'] for row in sources):
        raise ValueError('Source changed during capture; staging preserved')
    (staging / 'source-review.json').write_bytes(review_bytes)
    (staging / 'recovery-invocation.json').write_bytes(invocation_bytes)
    manifest = dict(status='PASS_IMMUTABLE_V36_REVIEWED_SOURCE_CAPTURE', core_sha256=core_hash, sources=sources,
        source_count=len(sources), source_review_sha256=hashlib.sha256(review_bytes).hexdigest(),
        recovery_invocation_sha256=hashlib.sha256(invocation_bytes).hexdigest(),
        source_review_snapshot=str((base / 'source-review.json').relative_to(ROOT)),
        recovery_invocation_snapshot=str((base / 'recovery-invocation.json').relative_to(ROOT)),
        source_mutated=False, core_built=False, probe_source_sha256=sha(Path(__file__)))
    (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    if base.exists():
        raise FileExistsError('Snapshot appeared concurrently; no overwrite')
    staging.replace(base)
    report = dict(manifest, manifest_path=str((base / 'manifest.json').relative_to(ROOT)), manifest_sha256=sha(base / 'manifest.json'))
    destination(ROOT, ROOT / 'reports/virtual-dispatch-source-snapshot-v36.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'source_count', 'core_sha256', 'manifest_sha256')}))


if __name__ == '__main__':
    main()
