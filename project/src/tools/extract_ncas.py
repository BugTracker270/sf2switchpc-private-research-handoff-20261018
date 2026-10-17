"""Evidence-driven, local NCA extraction. Preserve base/patch provenance."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from usb_boundary import destination, require_space
from inspect_ncas import summarize

ROOT=Path(__file__).resolve().parents[2]
TOOL=ROOT/'tools'/'hactool-1.4.0'/'hactool.exe'
KEYDIR=ROOT/'input'/'hactool-key-profile'/'switch'

def run(item,subdir,base=None):
    content=item['metadata']['Content Type']
    folder=destination(ROOT,ROOT/'unpacked'/subdir)
    folder.mkdir(parents=True,exist_ok=True)
    if any(folder.iterdir()):
        raise ValueError(f'Refusing extraction into nonempty folder: {folder}')
    require_space(ROOT,4*1024**3 if content=='Program' else 100*1024**2)
    args=[str(TOOL),'--suppresskeys','--disablekeywarns','-k',str(KEYDIR/'prod.keys'),'-t','nca','-x','-i','-y']
    if content=='Program':
        args += ['--exefsdir='+str(destination(ROOT,folder/'exefs')),'--romfsdir='+str(destination(ROOT,folder/'romfs'))]
    elif content=='Meta':
        args += ['--section0dir='+str(destination(ROOT,folder/'meta'))]
    else:
        args += ['--romfsdir='+str(destination(ROOT,folder/'romfs'))]
    if base: args+=['--basenca='+str(base)]
    args.append(item['file'])
    env=os.environ.copy();env['XDG_CONFIG_HOME']=str(KEYDIR.parent)
    start=time.monotonic()
    process=subprocess.run(args,cwd=KEYDIR,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=1800)
    text=process.stdout.decode('utf-8',errors='replace')
    log=destination(ROOT,ROOT/'logs'/('extract-'+subdir.replace('/','-')+'.log'))
    log.write_text(re.sub(r'(?i)\b[0-9a-f]{32,}\b','[REDACTED_HEX]',text),encoding='utf-8')
    fields,errors=summarize(text)
    signature_failures=len(re.findall(r'Signature \(FAIL\)',text))
    files=[]
    for path in sorted(folder.rglob('*')):
        if path.is_file():
            destination(ROOT,path)
            with path.open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
            files.append(dict(path=str(path),relative_path=str(path.relative_to(folder)),size=path.stat().st_size,sha256=digest,
                              source_nca=item['file'],base_nca=str(base) if base else None,
                              origin='effective_base_plus_patch' if base else item['kind']))
    success=process.returncode==0 and not errors and files
    result=dict(status='PASS' if success else 'FAIL',exit_code=process.returncode,errors=errors,
        signature_failure_count=signature_failures,command=args,source_nca=item['file'],base_nca=str(base) if base else None,
        output=str(folder),file_count=len(files),total_bytes=sum(f['size'] for f in files),
        elapsed_seconds=time.monotonic()-start,log=str(log),files=files)
    print(subdir,result['status'],result['file_count'],'files',result['total_bytes'],'bytes',flush=True)
    return result

def main():
    inspection=json.loads((ROOT/'reports'/'nca-inspection.json').read_text(encoding='utf-8-sig'))
    if any(e['status']!='PASS' for e in inspection['entries']): raise ValueError('NCA inspection has failures')
    base=next(e for e in inspection['entries'] if e['kind']=='base' and e['metadata']['Content Type']=='Program')
    operations=[]
    # Small metadata/control first to validate versions before the large export.
    selected=sorted([e for e in inspection['entries'] if e['metadata']['Content Type'] in ('Meta','Control')],key=lambda e:(e['kind'],e['metadata']['Content Type']))
    selected += [base,next(e for e in inspection['entries'] if e['kind']=='update' and e['metadata']['Content Type']=='Program')]
    for item in selected:
        content=item['metadata']['Content Type'].lower()
        subdir='effective' if item['kind']=='update' and content=='program' else item['kind']+'/'+content
        result=run(item,subdir,base['file'] if subdir=='effective' else None)
        operations.append(result)
        destination(ROOT,ROOT/'reports'/'extract-manifest.json').write_text(json.dumps(dict(operations=operations),indent=2)+'\n',encoding='utf-8')
        if result['status']!='PASS':raise RuntimeError('Extraction failed; inspect local log '+result['log'])

if __name__=='__main__':main()
