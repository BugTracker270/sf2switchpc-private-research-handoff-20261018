"""Capture eight reviewed v37 tool sources once after its completed invocation."""
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    review_path = ROOT / 'reports/runtime-helper-abi-independent-source-review-v37.json'
    invocation_path = ROOT / 'logs/cpp2il-nso-runtime-helper-abi-v37-result.json'
    review_bytes, invocation_bytes = review_path.read_bytes(), invocation_path.read_bytes()
    review, invocation = json.loads(review_bytes), json.loads(invocation_bytes)
    core = invocation['tool_assembly_sha256']['Cpp2IL.Core.dll']
    if len(review['reviewed_sources']) != 8 or review['stable_tested_core_sha256'] != core or invocation['exit_code'] != 0:
        raise ValueError('Final eight-source/Core provenance differs')
    base = destination(ROOT, ROOT / 'analysis/il2cpp/runtime-helper-abi-v37-source-snapshot')
    if base.exists():
        manifest = json.loads((base / 'manifest.json').read_text(encoding='utf-8-sig'))
        if manifest['core_sha256'] != core or len(manifest['sources']) != 8 \
                or manifest['source_review_sha256'] != hashlib.sha256(review_bytes).hexdigest() \
                or manifest['recovery_invocation_sha256'] != hashlib.sha256(invocation_bytes).hexdigest() \
                or any(sha(ROOT / row['snapshot_path']) != row['sha256'] for row in manifest['sources']) \
                or sha(ROOT / manifest['source_review_snapshot']) != manifest['source_review_sha256'] \
                or sha(ROOT / manifest['recovery_invocation_snapshot']) != manifest['recovery_invocation_sha256']:
            raise ValueError('Existing immutable snapshot differs; preserve it')
    else:
        staging = destination(ROOT, ROOT / ('analysis/il2cpp/runtime-helper-abi-v37-source-snapshot.staging-' + uuid.uuid4().hex))
        staging.mkdir(parents=True)
        sources = []
        for row in review['reviewed_sources']:
            original = destination(ROOT, ROOT / row['path'])
            if not original.is_relative_to(ROOT / 'refs/Cpp2IL/Cpp2IL.Core'):
                raise ValueError('Unexpected reviewed source location')
            content = original.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            if digest != row['sha256']:
                raise ValueError('Live source changed before capture: ' + row['path'])
            relative = original.relative_to(ROOT)
            target = destination(ROOT, staging / relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(content)
            sources.append(dict(path=str(relative), snapshot_path=str((base / relative).relative_to(ROOT)), sha256=digest))
        if any(sha(ROOT / row['path']) != row['sha256'] for row in sources):
            raise ValueError('Source changed during capture; staging preserved')
        destination(ROOT, staging / 'source-review.json').write_bytes(review_bytes)
        destination(ROOT, staging / 'recovery-invocation.json').write_bytes(invocation_bytes)
        manifest = dict(status='PASS_IMMUTABLE_V37_REVIEWED_SOURCE_CAPTURE', core_sha256=core, sources=sources,
            source_count=8, source_review_sha256=hashlib.sha256(review_bytes).hexdigest(),
            recovery_invocation_sha256=hashlib.sha256(invocation_bytes).hexdigest(),
            source_review_snapshot=str((base / 'source-review.json').relative_to(ROOT)),
            recovery_invocation_snapshot=str((base / 'recovery-invocation.json').relative_to(ROOT)),
            source_mutated=False, core_built=False, capture_source_sha256=sha(Path(__file__)))
        destination(ROOT, staging / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8', newline='\n')
        if base.exists():
            raise FileExistsError('Snapshot appeared concurrently; no overwrite')
        staging.replace(base)
    report = dict(manifest, manifest_path=str((base / 'manifest.json').relative_to(ROOT)), manifest_sha256=sha(base / 'manifest.json'))
    destination(ROOT, ROOT / 'reports/runtime-helper-abi-source-snapshot-v37.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({key: report[key] for key in ('status', 'source_count', 'core_sha256', 'manifest_sha256')}))


if __name__ == '__main__':
    main()
