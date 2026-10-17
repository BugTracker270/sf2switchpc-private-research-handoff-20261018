"""Fetch the exact official editor archive as data; never execute/install it."""
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination, require_space


def digest(path, algorithm):
    result = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def main():
    api_path = ROOT / 'analysis/reference/unity-2018.1.9f1-release-api.json'
    api = json.loads(api_path.read_text(encoding='utf-8-sig'))
    release, = api['results']
    if release['version'] != '2018.1.9f1' or release['shortRevision'] != '24bbd83e8b9e':
        raise ValueError('Exact official release identity differs')
    item, = [row for row in release['downloads'] if row['platform'] == 'WINDOWS' and row['architecture'] == 'X86_64']
    expected_url = 'https://download.unity3d.com/download_unity/24bbd83e8b9e/Windows64EditorInstaller/UnitySetup64-2018.1.9f1.exe'
    expected_size = 596405248
    # The exact official HTTPS response advertises 272 more bytes than the API.
    # Retain both observations; the original published MD5 remains mandatory.
    transfer_size = 596405520
    if item['url'] != expected_url or item['type'] != 'EXE' or item['downloadSize'] != dict(value=expected_size, unit='BYTE'):
        raise ValueError('Exact reviewed download/size differs')
    if not item['integrity'].startswith('md5-'):
        raise ValueError('Unexpected official integrity algorithm')
    encoded = base64.b64decode(item['integrity'][4:], validate=True)
    expected_md5 = encoded.decode('ascii').lower()
    if not re.fullmatch('[0-9a-f]{32}', expected_md5):
        raise ValueError('Official MD5 value is not encoded ASCII hexadecimal')
    target = destination(ROOT, ROOT / 'tools/unity-2018.1.9f1/UnitySetup64-2018.1.9f1.exe')
    partial = destination(ROOT, target.with_suffix('.exe.part'))
    target.parent.mkdir(parents=True, exist_ok=True)
    report_path = destination(ROOT, ROOT / 'reports/unity-2018.1.9f1-archive-provenance.json')
    report = dict(status='DOWNLOAD_PENDING', release='2018.1.9f1', revision=release['shortRevision'],
        api_record_path=str(api_path.relative_to(ROOT)), api_record_sha256=digest(api_path, 'sha256'),
        official_download_url=expected_url, official_integrity=item['integrity'], expected_md5=expected_md5,
        expected_bytes=expected_size, archive_path=str(target.relative_to(ROOT)), installer_executed=False,
        observed_full_response_bytes=transfer_size, api_size_delta_bytes=transfer_size - expected_size,
        editor_installed=False, platform_module_fetched=False, probe_source_sha256=digest(Path(__file__), 'sha256'))
    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    save()
    if not target.exists():
        require_space(ROOT, transfer_size)
        offset = partial.stat().st_size if partial.exists() else 0
        if not 0 <= offset <= transfer_size:
            raise ValueError('Partial archive exceeds reviewed size')
        if offset < transfer_size:
            headers = {'User-Agent': 'LocalRuntimeSourceInspection/1.0'}
            if offset:
                headers['Range'] = f'bytes={offset}-'
            started, last_progress = time.monotonic(), 0
            with urlopen(Request(expected_url, headers=headers), timeout=60) as response:
                final = urlsplit(response.url)
                if final.scheme != 'https' or not (final.hostname == 'download.unity3d.com' or final.hostname.endswith('.unity3d.com')):
                    raise ValueError('Official download redirected outside reviewed Unity HTTPS domain')
                if offset and (response.status != 206 or response.headers.get('Content-Range') != f'bytes {offset}-{transfer_size - 1}/{transfer_size}'):
                    raise ValueError('Resume response differs from exact expected byte range')
                if not offset and response.status != 200:
                    raise ValueError('Unexpected full archive HTTP status')
                if not offset and response.headers.get('Content-Length') != str(transfer_size):
                    raise ValueError('Full archive length differs from the exact observed official response')
                report['final_download_url'] = response.url
                report['http_content_length'] = response.headers.get('Content-Length')
                with partial.open('ab' if offset else 'xb') as stream:
                    count = offset
                    while True:
                        chunk = response.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > transfer_size:
                            raise ValueError('Response exceeds reviewed archive size')
                        stream.write(chunk)
                        elapsed = time.monotonic() - started
                        if elapsed - last_progress >= 10:
                            report.update(status='DOWNLOADING', downloaded_bytes=count, elapsed_seconds=round(elapsed, 2))
                            save()
                            print(f'Downloaded {count}/{transfer_size} bytes', flush=True)
                            last_progress = elapsed
            report['download_seconds'] = round(time.monotonic() - started, 2)
        if partial.stat().st_size != transfer_size or digest(partial, 'md5') != expected_md5:
            report.update(status='FAIL_ARCHIVE_INTEGRITY', downloaded_bytes=partial.stat().st_size)
            save()
            raise ValueError('Official archive size/MD5 integrity failed; partial preserved')
        # Both absolute paths have passed the USB/reparse boundary guard; never overwrite an existing archive.
        if target.exists():
            raise FileExistsError('Archive appeared during verification; no overwrite performed')
        partial.replace(target)
    md5, sha256 = digest(target, 'md5'), digest(target, 'sha256')
    if target.stat().st_size != transfer_size or md5 != expected_md5:
        raise ValueError('Existing archive differs from official size/MD5')
    report.update(status='PASS_OFFICIAL_ARCHIVE_MD5_WITH_RECORDED_API_SIZE_DELTA', downloaded_bytes=target.stat().st_size,
                  actual_md5=md5, local_sha256=sha256, official_api_size_matches=False,
                  official_api_md5_matches=True,
                  size_delta_explanation='Official response is 272 bytes larger than API byte count. API rounding is a possible explanation, not established; no integrity hash was relaxed.')
    save()
    print(json.dumps({key: report[key] for key in ('status', 'downloaded_bytes', 'actual_md5', 'local_sha256')}))


if __name__ == '__main__':
    main()
