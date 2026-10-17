"""Acquire official unstripped .NET 3.5 reference metadata on USB; install no host framework."""
import base64
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import urllib.request
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]
PACKAGE='microsoft.netframework.referenceassemblies.net35';VERSION='1.0.3'

def fetch(url):
    if not url.startswith(('https://api.nuget.org/','https://globalcdn.nuget.org/')):raise ValueError('Unexpected upstream host')
    request=urllib.request.Request(url,headers={'User-Agent':'LocalReferenceAssemblyInspection/1.0','Accept-Encoding':'identity'})
    with urllib.request.urlopen(request,timeout=45) as response:
        data=response.read(100*1024*1024+1)
        if len(data)>100*1024*1024:raise ValueError('Unexpected response size')
        return gzip.decompress(data) if response.headers.get('Content-Encoding')=='gzip' else data

def main():
    folder=destination(ROOT,ROOT/f'tools/{PACKAGE}-{VERSION}')
    if folder.exists():raise ValueError('Preserve previous package acquisition')
    folder.mkdir()
    registration_url=f'https://api.nuget.org/v3/registration5-gz-semver2/{PACKAGE}/{VERSION}.json'
    registration_raw=fetch(registration_url);registration=json.loads(registration_raw)
    catalog_url=registration['catalogEntry'];catalog_raw=fetch(catalog_url);catalog=json.loads(catalog_raw)
    if catalog['id'].lower()!=PACKAGE or catalog['version']!=VERSION or catalog['packageHashAlgorithm'].upper()!='SHA512':raise ValueError('Unexpected official catalog identity/hash algorithm')
    url=registration['packageContent'];raw=fetch(url)
    actual=base64.b64encode(hashlib.sha512(raw).digest()).decode('ascii')
    package=destination(ROOT,folder/(PACKAGE+'.'+VERSION+'.nupkg'))
    package.write_bytes(raw)
    destination(ROOT,folder/'official-registration.json').write_bytes(registration_raw)
    destination(ROOT,folder/'official-catalog.json').write_bytes(catalog_raw)
    if actual!=catalog['packageHash']:raise ValueError('Official published package SHA512 mismatch; preserve archive')
    with zipfile.ZipFile(package) as archive:
        entries=archive.infolist()
        if len(entries)>10000 or sum(item.file_size for item in entries)>500*1024*1024:raise ValueError('Unexpected package expansion')
        for item in entries:
            name=PurePosixPath(item.filename)
            if name.is_absolute() or any(part in ('.','..') or ':' in part for part in name.parts) or stat.S_ISLNK(item.external_attr>>16):raise ValueError('Unsafe package entry')
            target=destination(ROOT,folder/'extracted'/Path(*name.parts))
            if item.is_dir():target.mkdir(parents=True,exist_ok=True);continue
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.read(item))
    files=[dict(path=str(path.relative_to(ROOT)),bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted((folder/'extracted').rglob('*.dll'))]
    report=dict(status='PASS_OFFICIAL_CATALOG_PACKAGE_SHA512',package=PACKAGE,version=VERSION,source=url,registration=registration_url,
        official_catalog=catalog_url,package_sha512_base64=actual,package_sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),files=files,
        package_license_url=catalog.get('licenseUrl'),host_installation=False,
        purpose='Compiler/decompiler reference metadata for the observed legacy mscorlib/System 2.0 and System.Core 3.5 API family. This is an unstripped reference profile, not recovered game logic, a runtime implementation or a selected future port target.')
    destination(ROOT,ROOT/'reports/legacy-reference-assemblies-lock.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=report['status'],package=PACKAGE,version=VERSION,reference_dlls=len(files),bytes=len(raw),sha256=report['package_sha256'],host_installation=False),indent=2))
if __name__=='__main__':main()
