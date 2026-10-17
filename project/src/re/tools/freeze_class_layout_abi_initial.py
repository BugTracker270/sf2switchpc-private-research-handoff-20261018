"""Preserve the initial 014d ABI contract before a later independently labelled run."""
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(r'F:\SF2SwitchPC')
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination, require_space

BASE = ROOT / 'analysis/reconstruction/class-layout-abi-v37/initial-core014d'


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def preserve(source, target):
    source, target = destination(ROOT, source), destination(ROOT, target)
    digest = sha(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if sha(target) != digest:
            raise ValueError(f'Existing initial snapshot differs: {target.name}')
    else:
        shutil.copyfile(source, target)
    if sha(source) != digest or sha(target) != digest:
        raise ValueError('Initial snapshot copy hash differs')
    return dict(source=str(source.relative_to(ROOT)), snapshot=str(target.relative_to(ROOT)), sha256=digest)


def main():
    report = ROOT / 'reports/class-layout-abi-contract-v37.json'
    probe = ROOT / 'src/re/ClassLayoutAbiContractProbe/Program.cs'
    core = ROOT / 'src/re/ClassLayoutAbiContractProbe/bin/Release/net10.0/Cpp2IL.Core.dll'
    expected = {
        report: 'c497c5732c4d10cbeef6998a82b69bfdd22c003d90ac4bb2b50a1a722a355b91',
        probe: 'ec70ade559247ff5fc2184e4b1a680526c32f59de6ee540c14d53a3a15e3f905',
        core: '014d9b9698ae1448e9a14a41c132fae3ed7efc7023fef4932dae2da8196c9a49',
    }
    if any(sha(path) != digest for path, digest in expected.items()):
        raise ValueError('Initial report, source or copied Core changed before preservation')
    require_space(ROOT, sum(path.stat().st_size for path in core.parent.iterdir() if path.is_file()) + 1024**2)
    rows = [preserve(report, BASE / 'report.json'), preserve(probe, BASE / 'Program.cs'),
            preserve(probe.with_name('ClassLayoutAbiContractProbe.csproj'), BASE / 'ClassLayoutAbiContractProbe.csproj')]
    rows += [preserve(path, BASE / 'bin' / path.name) for path in sorted(core.parent.iterdir()) if path.is_file()]
    initial = ROOT / 'reports/class-layout-abi-contract-v37-initial-core014d.json'
    preserve(report, initial)
    result = dict(status='PASS_IMMUTABLE_INITIAL_CLASS_LAYOUT_ABI_CONTRACT_CAPTURE', core_sha256=expected[core],
                  original_contract_sha256=expected[report], initial_report=str(initial.relative_to(ROOT)),
                  initial_report_sha256=sha(initial), files=rows, native_or_game_methods_executed=0,
                  current_production_abi_or_semantics_promoted=False)
    text = json.dumps(result, indent=2) + '\n'
    manifest = destination(ROOT, BASE / 'manifest.json')
    if manifest.exists() and manifest.read_text(encoding='utf-8') != text:
        raise ValueError('Existing initial capture manifest differs')
    manifest.write_text(text, encoding='utf-8', newline='\n')
    result['manifest'] = str(manifest.relative_to(ROOT))
    result['manifest_sha256'] = sha(manifest)
    destination(ROOT, ROOT / 'reports/class-layout-abi-initial-freeze-v37.json').write_text(
        json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(status=result['status'], files=len(rows), manifest_sha256=result['manifest_sha256'])))


if __name__ == '__main__':
    main()
