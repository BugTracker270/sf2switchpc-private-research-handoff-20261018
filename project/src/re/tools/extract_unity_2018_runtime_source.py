"""Extract only reviewed common runtime/licensing members from verified Unity data."""
import hashlib
import json
from pathlib import Path, PureWindowsPath
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    provenance_path = ROOT / 'reports/unity-2018.1.9f1-archive-provenance.json'
    provenance = json.loads(provenance_path.read_text(encoding='utf-8-sig'))
    archive = ROOT / provenance['archive_path']
    if (provenance['status'] != 'PASS_OFFICIAL_ARCHIVE_MD5_WITH_RECORDED_API_SIZE_DELTA'
            or provenance['actual_md5'] != provenance['expected_md5'] or sha(archive) != provenance['local_sha256']):
        raise ValueError('Official archive verification is missing or changed')
    prefix = 'Editor\\Data\\il2cpp\\libil2cpp\\'
    selection = [prefix + name for name in ('vm\\Class.cpp', 'vm\\Class.h', 'vm\\Runtime.cpp', 'vm\\Runtime.h',
        'vm\\MetadataLock.h', 'os\\Mutex.cpp', 'os\\Mutex.h', 'il2cpp-class-internals.h', 'il2cpp-object-internals.h',
        'il2cpp-config.h', 'il2cpp-api.cpp', 'il2cpp-api.h', 'il2cpp-api-functions.h')]
    selection.append('$PLUGINSDIR\\License.rtf')
    listing = ROOT / 'logs/unity-2018.1.9f1-archive-list.log'
    archive_paths = {line[7:] for line in listing.read_text(encoding='utf-8-sig').splitlines() if line.startswith('Path = ')}
    if not set(selection) <= archive_paths:
        raise ValueError('Needed common runtime member missing: ' + repr(set(selection) - archive_paths))
    output = destination(ROOT, ROOT / 'tools/unity-2018.1.9f1/common-runtime-source')
    expected = []
    for member in selection:
        relative = PureWindowsPath(member)
        if relative.is_absolute() or relative.drive or '..' in relative.parts:
            raise ValueError('Unsafe selected member')
        expected.append(destination(ROOT, output.joinpath(*relative.parts)))
    if output.exists() and any(output.iterdir()):
        raise FileExistsError('Preserve existing source extraction; no overwrite')
    output.mkdir(parents=True, exist_ok=True)
    select_path = destination(ROOT, ROOT / 'tools/unity-2018.1.9f1/selected-runtime-files.txt')
    select_path.write_text('\n'.join(selection) + '\n', encoding='utf-8')
    seven_zip = Path('C:/Program Files/7-Zip/7z.exe')
    run = subprocess.run([str(seven_zip), 'x', str(archive), '-o' + str(output), '-scsUTF-8', '-aos', '@' + str(select_path)],
                         capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
    log = destination(ROOT, ROOT / 'logs/unity-2018.1.9f1-source-extraction.log')
    log.write_text(run.stdout + run.stderr, encoding='utf-8')
    if run.returncode not in (0, 1):
        raise RuntimeError('7-Zip extraction failed; exact log preserved')
    actual = {destination(ROOT, path) for path in output.rglob('*') if path.is_file()}
    if actual != set(expected):
        raise ValueError('Extracted member inventory differs from exact selection')
    records = [dict(path=str(path.relative_to(ROOT)), bytes=path.stat().st_size, sha256=sha(path)) for path in expected]
    report = dict(status='PASS_SELECTED_OFFICIAL_COMMON_RUNTIME_SOURCE_EXTRACTED', release=provenance['release'],
        revision=provenance['revision'], source_archive_sha256=provenance['local_sha256'],
        archive_provenance_sha256=sha(provenance_path), archive_listing_sha256=sha(listing),
        selection_sha256=sha(select_path), extraction_exit_code=run.returncode,
        seven_zip_sha256=sha(seven_zip), files=records, file_count=len(records), extraction_log_sha256=sha(log),
        installer_executed=False, editor_installed=False, platform_sdk_fetched=False, source_private_local_only=True,
        probe_source_sha256=sha(Path(__file__)))
    destination(ROOT, ROOT / 'reports/unity-2018.1.9f1-common-runtime-source.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'file_count', 'extraction_exit_code', 'source_archive_sha256')}))


if __name__ == '__main__':
    main()
