"""Verify locked crates and unpack a Cargo directory source without archive mtimes.

Windows exFAT rejects the pre-1980 timestamps used by some crate archives.
Package bytes and per-file checksums are retained; no host Cargo config is edited.
"""
import concurrent.futures
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib
import urllib.request
from usb_boundary import destination, require_space

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'refs/il2cpp-dumper-rs/Cargo.lock'


def fetch_package(package):
    name, version = package['name'], package['version']
    if not re.fullmatch(r'[A-Za-z0-9_-]+', name) or not re.fullmatch(r'[A-Za-z0-9.+_-]+', version):
        raise ValueError('Invalid locked package identifier')
    if package['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
        raise ValueError('Unexpected dependency registry')
    identifier = name + '-' + version
    try:
        directory = destination(ROOT, ROOT / 'cache/cargo-vendor' / identifier)
        archive = destination(ROOT, ROOT / 'cache/cargo-archives' / (identifier + '.crate'))
    except ValueError as error:
        raise ValueError(f'{identifier}: {error}; root={ROOT}; archive={(ROOT / "cache/cargo-archives" / (identifier + ".crate")).resolve()}') from error
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        data = archive.read_bytes()
    else:
        url = f'https://static.crates.io/crates/{name}/{identifier}.crate'
        for attempt in range(3):
            try:
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = response.read(32 * 1024**2)
                break
            except Exception:
                if attempt == 2:
                    raise
        if hashlib.sha256(data).hexdigest() != package['checksum']:
            raise ValueError('Crate checksum mismatch: ' + identifier)
        archive.write_bytes(data)
    if hashlib.sha256(data).hexdigest() != package['checksum']:
        raise ValueError('Cached crate checksum mismatch: ' + identifier)
    files = {}
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as stream:
        for item in stream:
            if item.isdir():
                continue
            if not item.isfile():
                raise ValueError('Archive links/special files forbidden: ' + identifier)
            parts = PurePosixPath(item.name).parts
            if len(parts) < 2 or parts[0] != identifier or '..' in parts:
                raise ValueError('Archive traversal: ' + item.name)
            relative = '/'.join(parts[1:])
            if relative in files or relative == '.cargo-checksum.json':
                raise ValueError('Duplicate/reserved archive entry')
            expanded += item.size
            if expanded > 128 * 1024**2:
                raise ValueError('Crate expansion exceeds reviewed bound')
            path = destination(ROOT, directory / relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            content = stream.extractfile(item).read()
            path.write_bytes(content)
            files[relative] = hashlib.sha256(content).hexdigest()
    destination(ROOT, directory / '.cargo-checksum.json').write_text(
        json.dumps(dict(files=files, package=package['checksum']), sort_keys=True), encoding='utf-8')
    return dict(name=name, version=version, checksum=package['checksum'], files=len(files), bytes=expanded)


def main():
    require_space(ROOT, 1024**3)
    for name in ['cache/cargo-vendor', 'cache/cargo-archives']:
        destination(ROOT, ROOT / name).mkdir(parents=True, exist_ok=True)
    packages = [p for p in tomllib.loads(LOCK.read_text())['package'] if 'source' in p]
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        for row in executor.map(fetch_package, packages):
            rows.append(row)
            print(f"Verified {len(rows)}/{len(packages)}: {row['name']} {row['version']}", flush=True)
    report = dict(status='PASS_LOCKED_CRATE_BYTES_AND_FILE_CHECKSUMS',
                  lock_sha256=hashlib.sha256(LOCK.read_bytes()).hexdigest(), packages=rows,
                  scope='Cargo directory source for Windows exFAT; archive timestamps are not applied. '
                        'All package SHA256 values match the pinned upstream Cargo.lock. '
                        'No changes to source contents, host config or package checksums.')
    destination(ROOT, ROOT / 'reports/il2cpp-dumper-rs-dependencies-lock.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
