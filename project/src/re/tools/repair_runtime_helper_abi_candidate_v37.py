"""Repair the frozen v37 candidate without importing later live tool edits."""
from pathlib import Path
import difflib
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination

PIN = 'b5ad444b82267cb1e4b88b8b373c008105bdea52'
OLD_HASH = '73b65ce66f91bc1234dd7990c11d04e6c6b9e0544d34dac58239d0091bcbfe43'
MISSING = 'Cpp2IL.Core/Model/Contexts/MethodAnalysisContext.cs'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    repo = ROOT / 'refs/Cpp2IL'
    old_lock_path = ROOT / 'reports/cpp2il-hfa-experimental-lock-runtime-helper-abi-v37.json'
    old_lock = json.loads(old_lock_path.read_text(encoding='utf-8-sig'))
    old_patch = (ROOT / old_lock['patch']).read_bytes()
    if sha(old_patch) != OLD_HASH or len(old_lock['files']) != 39 or any(x['path'] == MISSING for x in old_lock['files']):
        raise ValueError('Original incomplete candidate differs; preserve it')
    frozen37 = json.loads((ROOT / 'reports/runtime-helper-abi-source-snapshot-v37.json').read_text(encoding='utf-8-sig'))
    frozen36 = json.loads((ROOT / 'reports/virtual-dispatch-source-snapshot-v36.json').read_text(encoding='utf-8-sig'))
    snapshots = {}
    for manifest in (frozen37, frozen36):
        for row in manifest['sources']:
            name = row['path'].replace('\\', '/').removeprefix('refs/Cpp2IL/')
            snapshots.setdefault(name, []).append((ROOT / row['snapshot_path'], row['sha256']))
    missing_row = next(x for x in frozen37['sources'] if x['path'].replace('\\', '/') == 'refs/Cpp2IL/' + MISSING)
    missing_bytes = (ROOT / missing_row['snapshot_path']).read_bytes()
    if sha(missing_bytes) != missing_row['sha256']:
        raise ValueError('Frozen integration source differs')
    before = subprocess.check_output(['git', '-C', str(repo), 'show', PIN + ':' + MISSING]).decode('utf-8')
    after = missing_bytes.decode('utf-8')
    addition = 'diff --git a/' + MISSING + ' b/' + MISSING + '\n'
    addition += ''.join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                          fromfile='a/' + MISSING, tofile='b/' + MISSING))
    new_patch = old_patch + addition.encode('utf-8')
    patch_path = destination(ROOT, ROOT / 'src/re/tool-patches/cpp2il-sf2-hfa-experimental-runtime-helper-abi-v37-complete.patch')
    if patch_path.exists() and patch_path.read_bytes() != new_patch:
        raise ValueError('Repaired patch already exists with different bytes')
    patch_path.write_bytes(new_patch)
    rows = old_lock['files'] + [dict(path=MISSING, sha256=sha(missing_bytes))]
    if len(rows) != 40 or len({x['path'] for x in rows}) != 40:
        raise ValueError('Expected forty unique source files')
    changed = subprocess.check_output(['git', '-C', str(repo), 'diff', '--name-only', '-z', PIN]).decode().strip('\0').split('\0')
    untracked = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '--others', '--exclude-standard', '-z']).decode().strip('\0').split('\0')
    if (set(changed + untracked) - {''}) != {x['path'] for x in rows}:
        raise ValueError('Frozen candidate paths do not cover the independently audited tool inventory')
    by_name = {x['path']: x['sha256'] for x in rows}
    if any(by_name.get(x['path'].replace('\\', '/').removeprefix('refs/Cpp2IL/')) != x['sha256'] for x in frozen37['sources']):
        raise ValueError('The eight independently reviewed v37 sources do not match the complete candidate')
    tree = destination(ROOT, ROOT / 'analysis/reference/runtime-helper-abi-v37-complete-verification-tree')
    tree.mkdir(parents=True, exist_ok=True)
    origins = []
    for row in rows:
        candidates = snapshots.get(row['path'], []) + [(repo / row['path'], row['sha256'])]
        source = next((p for p, h in candidates if h == row['sha256'] and p.is_file() and sha(p.read_bytes()) == h), None)
        if source is None:
            raise ValueError('No exact frozen/unchanged source for ' + row['path'])
        out = destination(ROOT, tree / row['path'])
        out.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        if out.exists() and out.read_bytes() != data:
            raise ValueError('Existing verification source differs')
        out.write_bytes(data)
        origins.append(dict(path=row['path'], sha256=row['sha256'], source=str(source.relative_to(ROOT))))
    git_dir = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', '--absolute-git-dir'], text=True).strip()
    destination(ROOT, Path(git_dir))
    command = ['git', '--git-dir=' + git_dir, '--work-tree=' + str(tree), 'apply', '--reverse', '--check', str(patch_path)]
    def check(label):
        result = subprocess.run(command, cwd=tree, capture_output=True)
        destination(ROOT, ROOT / ('logs/runtime-helper-abi-v37-complete-' + label + '.log')).write_bytes(result.stdout + result.stderr)
        return result.returncode
    first = check('reverse')
    changed = destination(ROOT, tree / MISSING)
    original = changed.read_bytes()
    altered = original.replace(b'LegacyArm64ClassLayoutAbi.SeedResults(this);', b'LegacyArm64ClassLayoutAbi.RejectedControl(this);', 1)
    if altered == original:
        raise ValueError('Negative-control anchor missing')
    try:
        changed.write_bytes(altered)
        negative = check('negative-control')
    finally:
        changed.write_bytes(original)
    restored = check('restored')
    if first != 0 or negative == 0 or restored != 0:
        raise ValueError('Frozen verification tree reverse/control checks failed: ' + repr((first, negative, restored)))
    lock = dict(old_lock, patch=str(patch_path.relative_to(ROOT)), sha256=sha(new_patch), files=rows,
                source_inventory_coverage_verified=True, changed_or_new_tool_paths=40,
                repaired_missing_file=MISSING, original_incomplete_patch_sha256=OLD_HASH,
                repair_source_snapshot=str((ROOT / missing_row['snapshot_path']).relative_to(ROOT)),
                reverse_check_exit=first, negative_control_exit=negative, restored_reverse_check_exit=restored,
                source_tree_origins=origins, core_built_by_repair=False,
                scope=old_lock['scope'] + ' The missing MethodAnalysisContext integration is restored from frozen v37 source; no later live v38 virtual-dispatch edit is included.')
    destination(ROOT, ROOT / 'reports/cpp2il-hfa-experimental-lock-runtime-helper-abi-v37-complete.json').write_text(
        json.dumps(lock, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(status='PASS_FROZEN_V37_COMPLETE_40_FILE_PATCH', files=40, sha256=lock['sha256'],
                          reverse=first, negative_control=negative, restored=restored)))


if __name__ == '__main__':
    main()
