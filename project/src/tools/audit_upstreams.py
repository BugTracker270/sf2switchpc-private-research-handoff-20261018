"""Fetch public repository metadata/docs only. Never reads game material."""
import datetime
import hashlib
import json
from pathlib import Path
import time
import urllib.request
import urllib.error
from usb_boundary import destination

ROOT=Path(__file__).resolve().parents[2]
HEADERS={'User-Agent':'SF2-USB-local-research','Accept':'application/vnd.github+json'}
CATALOG=[
 ('SciresM/hactool','NSP/NCA inspection','primary'),
 ('DarkMatterCore/nxdumptool','Own-console dumping; rewrite branch','optional'),
 ('Adubbz/Ghidra-Switch-Loader','ARM64 NSO Ghidra import','primary'),
 ('NationalSecurityAgency/ghidra','Native disassembly and pseudocode','primary'),
 ('Perfare/Il2CppDumper','IL2CPP metadata/type reconstruction','conditional'),
 ('SamboyCoding/Cpp2IL','Possible ARM64/NSO control-flow reconstruction','conditional'),
 ('NepMods/Cpp2IL-Analysis','Specialized NSO analysis compatibility research','optional'),
 ('AssetRipper/AssetRipper','Unity assets if Unity proven','conditional'),
 ('nesrak1/UABEA','Second-opinion Unity serialized data inspector','optional'),
 ('nesrak1/UABEANext','Second-opinion Unity inspector','optional'),
 ('djkaty/Il2CppInspector','Legacy IL2CPP structure reference','optional'),
 ('morluto/rea','Agent-facing local Ghidra provider','primary'),
 ('onerdna/sf-2.x-guide','Android engine research; not Switch evidence','reference'),
 ('moltinginstar/sf2mod','Android save research; never execute mod workflow','reference'),
 ('onerdna/stalker','Android data representation source only','reference'),
 ('FlipThoseTitle/Gymnast-Tool-Suite','Animation tooling source; no external game assets','reference'),
 ('NikkaGames/AutoShadow','Android instrumentation source only; never inject','reference'),
 ('Unity-Technologies/InputSystem','Input API reference; implementation out of scope','deferred')]

def request(url):
    with urllib.request.urlopen(urllib.request.Request(url,headers=HEADERS),timeout=45) as response:
        return response.read()

def getjson(url): return json.loads(request(url))

def save(relative,data):
    path=destination(ROOT,ROOT/relative)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(data)
    return path

def main():
    entries=[]
    for repo,purpose,priority in CATALOG:
        item=dict(repository='https://github.com/'+repo,purpose=purpose,priority=priority,
                  acquired_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  execution='not executed',platform='upstream-dependent; see reviewed README',status='IN_PROGRESS')
        slug=repo.replace('/','--')
        try:
            metadata=getjson('https://api.github.com/repos/'+repo)
            branch='rewrite' if repo=='DarkMatterCore/nxdumptool' else metadata['default_branch']
            commit=getjson(f'https://api.github.com/repos/{repo}/commits/{branch}')
            sha=commit['sha']
            item.update(branch=branch,commit=sha,archived=metadata['archived'],
                        license=(metadata.get('license') or {}).get('spdx_id','UNSPECIFIED'),
                        upstream_pushed_at=metadata['pushed_at'],clone_url=metadata['clone_url'])
            save('reports/upstream/'+slug+'-metadata.json',json.dumps(metadata,indent=2).encode())
            for name in ('README.md','README.MD','README.rst','README'):
                try:
                    content=request(f'https://raw.githubusercontent.com/{repo}/{sha}/{name}')
                    path=save('reports/upstream/'+slug+'-'+name,content)
                    item.update(readme=str(path),readme_sha256=hashlib.sha256(content).hexdigest())
                    break
                except urllib.error.HTTPError as error:
                    if error.code!=404: raise
            if repo=='moltinginstar/sf2mod':
                content=request(f'https://raw.githubusercontent.com/{repo}/{sha}/WRITEUP.md')
                item['writeup']=str(save('reports/upstream/'+slug+'-WRITEUP.md',content))
            item['status']='PUBLIC_DOCS_FETCHED_REVIEW_REQUIRED'
        except Exception as error:
            item.update(status='FAILED',error=repr(error))
        entries.append(item)
        save('reports/toolchain-lock.json',json.dumps(dict(repositories=entries,releases=[],
             note='Docs/source only unless release records explicitly confirm acquisition; no game data transmitted.'),indent=2).encode())
        print(repo,item['status'],item.get('commit',''),flush=True)
    for repo in ('SciresM/hactool','Adubbz/Ghidra-Switch-Loader','NationalSecurityAgency/ghidra','Perfare/Il2CppDumper','AssetRipper/AssetRipper','morluto/rea'):
        try:
            releases=getjson(f'https://api.github.com/repos/{repo}/releases?per_page=3')
            save('reports/upstream/'+repo.replace('/','--')+'-releases.json',json.dumps(releases,indent=2).encode())
            print('release metadata',repo,flush=True)
        except Exception as error:
            print('release metadata failed',repo,repr(error),flush=True)

if __name__=='__main__':main()
