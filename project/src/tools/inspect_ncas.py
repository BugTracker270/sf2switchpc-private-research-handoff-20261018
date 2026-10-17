"""Run verified hactool locally; suppress keys and expose only metadata summaries."""
import argparse
import json
import os
import re
import subprocess
import struct
import zipfile
from pathlib import Path
from usb_boundary import destination

ROOT=Path(__file__).resolve().parents[2]
TOOL=ROOT/'tools'/'hactool-1.4.0'/'hactool.exe'

def prepare_keys(archive):
    keydir=destination(ROOT,ROOT/'input'/'keys')
    keydir.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        if set(z.namelist()) != {'prod.keys','title.keys'}:
            raise ValueError('Expected exactly prod.keys and title.keys')
        for name in ('prod.keys','title.keys'):
            content=z.read(name)
            if len(content)>1024*1024:
                raise ValueError('Unexpected key file size')
            target=destination(ROOT,keydir/name)
            if target.exists() and target.read_bytes()!=content:
                raise ValueError('Refusing to overwrite different key material')
            if not target.exists(): target.write_bytes(content)
    records={}
    parsed={}
    for name in ('prod.keys','title.keys'):
        rows=[]
        parsed[name]={}
        for line in (keydir/name).read_text(encoding='utf-8-sig').splitlines():
            line=line.split('#',1)[0].strip()
            if not line:continue
            match=re.fullmatch(r'([a-zA-Z0-9_]+)\s*=\s*([0-9a-fA-F]+)',line)
            if not match or len(match[2])%2: raise ValueError('Malformed keyset; contents not logged')
            rows.append(match[1].lower())
            parsed[name][match[1].lower()]=match[2]
        records[name]={'entries':len(rows),'contents':'REDACTED'}
        if name=='prod.keys' and 'header_key' not in rows: raise ValueError('prod.keys lacks header_key')
    # Only direct NCA keys and well-formed derivation inputs are relevant here.
    # Preserve originals; exclude malformed/irrelevant console-boot derivation entries.
    profile=destination(ROOT,ROOT/'input'/'hactool-key-profile'/'switch')
    profile.mkdir(parents=True,exist_ok=True)
    accepted={}
    for name,value in parsed['prod.keys'].items():
        allowed = name=='header_key' and len(value)==64
        allowed |= bool(re.fullmatch(r'(master_key|titlekek|key_area_key_(application|ocean|system))_[0-9a-f]{2}',name)) and len(value)==32
        allowed |= name in ('aes_kek_generation_source','aes_key_generation_source','key_area_key_application_source','key_area_key_ocean_source','key_area_key_system_source','titlekek_source') and len(value)==32
        if allowed:accepted[name]=value
    destination(ROOT,profile/'prod.keys').write_text('\n'.join(f'{name} = {value}' for name,value in accepted.items())+'\n',encoding='ascii')
    titlekeys={name:value for name,value in parsed['title.keys'].items() if len(name)==32 and len(value)==32}
    ticket_sources=[]
    # Common tickets already embedded in these supplied NSPs contain the encrypted
    # titlekey hactool expects. Personalized tickets require separate lawful input.
    # Layout reference: DarkMatterCore/nxdumptool include/core/tik.h, Switchbrew Ticket.
    for kind in ('base','update'):
        package=json.loads((ROOT/'reports'/f'package-{kind}.json').read_text(encoding='utf-8-sig'))
        with Path(package['source']).open('rb') as stream:
            for entry in package['entries']:
                if not entry['name'].endswith('.tik'):continue
                stream.seek(entry['offset'])
                ticket=stream.read(entry['size'])
                signature=struct.unpack_from('<I',ticket)[0]
                body={0x10000:0x240,0x10001:0x140,0x10002:0x80,0x10003:0x240,0x10004:0x140,0x10005:0x80,0x10006:0x40}.get(signature)
                if body is None or len(ticket)<body+0x180: raise ValueError('Unsupported/truncated ticket')
                if ticket[body+0x140]!=2 or ticket[body+0x141]!=0: raise ValueError('Not a common Switch ticket')
                rights=ticket[body+0x160:body+0x170].hex()
                if not entry['name'].lower().startswith(rights):raise ValueError('Ticket rights/filename mismatch')
                titlekeys[rights]=ticket[body+0x40:body+0x50].hex()
                ticket_sources.append({'kind':kind,'package_ticket':entry['name'],'type':'common encrypted ticket titlekey; value never logged'})
    destination(ROOT,profile/'title.keys').write_text('\n'.join(f'{name} = {value}' for name,value in titlekeys.items())+'\n',encoding='ascii')
    records['package_ticket_sources']=ticket_sources
    records['hactool_profile']={'accepted_direct_or_derivation_entries':len(accepted),'excluded_entries':len(parsed['prod.keys'])-len(accepted),'originals':'preserved'}
    return profile,records

def summarize(text):
    fields={}
    for label in ('Magic','Content Size','Title ID','SDK Version','Distribution type','Content Type','Master Key Revision','Encryption Type','Rights ID'):
        match=re.search(r'^'+re.escape(label)+r':\s*(.*)$',text,re.M)
        if match:fields[label]=match[1].strip()
    errors=[]
    for phrase in ('Invalid NCA header','Unable to match rights id','Failed to','Error:','ERROR:','hash check failed','Corrupt'):
        if phrase.lower() in text.lower(): errors.append(phrase)
    return fields,errors

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-archive',type=Path)
    args=parser.parse_args()
    keydir,validation=prepare_keys(args.key_archive) if args.key_archive else (ROOT/'input'/'hactool-key-profile'/'switch',{})
    report={'keys':validation,'entries':[],'note':'Raw local logs are confidential. Console contains allowlisted metadata only.'}
    for kind in ('base','update'):
        package=json.loads((ROOT/'reports'/f'package-{kind}.json').read_text(encoding='utf-8-sig'))
        for entry in package['entries']:
            if not entry['name'].endswith('.nca'):continue
            path=Path(entry.get('output',ROOT/'unpacked'/'nsp_pfs0'/kind/entry['name']))
            args=[str(TOOL),'--suppresskeys','--disablekeywarns','-k',str(keydir/'prod.keys'),'-t','nca','-i',str(path)]
            env=os.environ.copy()
            env['XDG_CONFIG_HOME']=str(keydir.parent)
            completed=subprocess.run(args,cwd=keydir,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
            log=destination(ROOT,ROOT/'logs'/f'hactool-{kind}-{path.name}.log')
            text=completed.stdout.decode('utf-8',errors='replace')
            log.write_text(re.sub(r'(?i)\b[0-9a-f]{32,}\b','[REDACTED_HEX]',text),encoding='utf-8')
            fields,errors=summarize(text)
            status='PASS' if completed.returncode==0 and fields.get('Title ID') and not errors else 'FAIL'
            item=dict(kind=kind,file=str(path),metadata=fields,errors=errors,exit_code=completed.returncode,status=status,log=str(log))
            report['entries'].append(item)
            destination(ROOT,ROOT/'reports'/'nca-inspection.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
            print(kind,path.name,status,json.dumps(fields),flush=True)

if __name__=='__main__': main()
