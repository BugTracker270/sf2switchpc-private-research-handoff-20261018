"""Preserve game DLL bytes while supplying verified unstripped legacy framework metadata to ILSpy."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',required=True);args=parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+',args.run):raise ValueError('Invalid recovery run')
    lock=json.loads((ROOT/'reports/legacy-reference-assemblies-lock.json').read_text(encoding='utf-8-sig'))
    if lock['status']!='PASS_OFFICIAL_CATALOG_PACKAGE_SHA512' or lock['signature_verification']['exit_code']!=0:raise ValueError('Verified official framework references required')
    references={}
    for row in lock['files']:
        path=destination(ROOT,ROOT/row['path'])
        if hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:raise ValueError('Official reference metadata changed')
        name=path.name.lower()
        if name not in references or len(str(path))<len(str(references[name])):references[name]=path
    source=ROOT/f'analysis/il2cpp/cpp2il-recovery-{args.run}'
    folder=destination(ROOT,ROOT/f'analysis/il2cpp/decompiler-reference-view-{args.run}')
    if folder.exists():raise ValueError('Preserve prior decompiler input view')
    folder.mkdir();files=[]
    for path in sorted(source.glob('*.dll')):
        selected=references.get(path.name.lower(),path)
        output=destination(ROOT,folder/path.name);shutil.copyfile(selected,output)
        files.append(dict(name=path.name,source=str(selected.relative_to(ROOT)),sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
            official_framework_reference=selected!=path))
    for name in ('Assembly-CSharp.dll','Assembly-CSharp-firstpass.dll'):
        if (folder/name).read_bytes()!=(source/name).read_bytes():raise ValueError('Game assembly bytes must remain unchanged')
    report=dict(status='PASS_GAME_BYTES_WITH_VERIFIED_LEGACY_RESOLUTION_CONTEXT',recovery_run=args.run,files=files,
        scope='A separate decompiler resolution view. Game DLLs remain byte-identical; matching framework assembly filenames use official unstripped .NET 3.5 reference metadata. This changes API name/accessor resolution, not recovered game method bodies. It does not prove Mono/Microsoft API parity or source completeness.')
    destination(ROOT,folder/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(dict(status=report['status'],files=len(files),framework_references=sum(row['official_framework_reference'] for row in files))))
if __name__=='__main__':main()
