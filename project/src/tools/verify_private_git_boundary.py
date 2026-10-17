"""Fail a local infrastructure checkpoint if private game material is staged."""
import json
from pathlib import Path
import re
import subprocess
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[2]

def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args])

def main():
    names=git('diff','--cached','--name-only','-z').decode('utf-8').split('\0')
    names=[n for n in names if n];errors=[]
    forbidden=re.compile(r'(?im)^\s*(?:header_key|master_key_[0-9a-f]{2}|titlekek_[0-9a-f]{2}|key_area_key_[a-z_0-9]+)\s*=\s*[0-9a-f]{32,64}\s*$')
    for name in names:
        if name.startswith(('input/','analysis/','unpacked/','refs/','tools/','cache/','originals_manifest/','build/','dist/','logs/')) or Path(name).suffix.lower() in ('.nsp','.nca','.nso','.dll','.exe','.rar','.zip','.keys','.tik','.cert','.db','.sqlite','.gdt'):
            errors.append(dict(path=name,error='Private/binary output staged'));continue
        data=git('show',':'+name)
        try:text=data.decode('utf-8-sig')
        except UnicodeDecodeError:errors.append(dict(path=name,error='Nontext artifact staged'));continue
        if forbidden.search(text):errors.append(dict(path=name,error='Possible key material; contents not logged'))
    report=dict(staged_files=len(names),errors=errors,status='PASS' if not errors else 'FAIL',
        scope='Local checkpoint text/binary boundary and key-line pattern checks; not a general secret scanner. No remote/upload performed.')
    destination(ROOT,ROOT/'reports/git-boundary-check.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
    if errors:raise RuntimeError('Private checkpoint boundary failed')
if __name__=='__main__':main()
