"""Prepare conservative source-owner candidates; unresolved mappings remain explicit."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys
ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0,str(ROOT/'src/tools'))
from usb_boundary import destination

def path(relative): return destination(ROOT,ROOT/relative)
data=json.loads(path('analysis/reconstruction/compiler-family-v38/canonical-diagnostics.json').read_text())
groups=defaultdict(list)
for assembly,rows in data.items():
    for row in rows:
        match=re.fullmatch(r"Cannot convert type '(.+\[\])' to 'nint'",row['message'])
        if row['code']!='CS0030' or not match: continue
        lines=path(row['path']).read_text(encoding='utf-8-sig').splitlines()
        near='\n'.join(lines[max(0,row['line']-4):row['line']+4])
        if 'Method not found @B5B390' not in near:continue
        groups[(assembly,row['path'],row['owner_declaration_line'],row['owner_declaration'])].append(dict(line=row['line'],type=match[1],exact_simple_cast=bool(re.fullmatch(r'\s*nint \w+ = \(nint\)\w+;',lines[row['line']-1]))))
output=[]
for (assembly,source,line,declaration),rows in groups.items():
    text=path(source).read_text(encoding='utf-8-sig')
    ns=re.search(r'^namespace ([\w.]+);',text,re.M)
    owner=re.search(r'^(?:public|internal|private|protected)[^\n]*?\b(?:class|struct)\s+(\w+)',text,re.M)
    type_name=(ns[1]+'.' if ns else '')+(owner[1] if owner else '<unknown>')
    method=None;parameters=None
    if declaration=='<file>':method='.cctor';parameters=0
    elif '(' in declaration:
        head,arguments=declaration.split('(',1)
        name=head.split()[-1].split('<',1)[0]
        method='.ctor' if owner and name==owner[1] else name
        arguments=arguments.rsplit(')',1)[0]
        if not arguments.strip():parameters=0
        else:
            depth=0;parameters=1
            for char in arguments:
                if char in '<([':depth+=1
                elif char in '>)]':depth-=1
                elif char==',' and depth==0:parameters+=1
    else:
        name=declaration.split()[-1]
        if re.fullmatch(r'\w+',name):method='get_'+name;parameters=0
    output.append(dict(assembly=assembly,source=source,declaration_line=line,type=type_name,method=method,parameter_count=parameters,diagnostic_occurrences=len(rows),diagnostic_types=dict(Counter(r['type'] for r in rows)),all_casts_simple=all(r['exact_simple_cast'] for r in rows),source_sha256=hashlib.sha256(path(source).read_bytes()).hexdigest(),private_rows=rows))
target=path('analysis/reconstruction/compiler-family-v38/array-cast-owner-candidates.json')
target.write_text(json.dumps(output,indent=2)+'\n')
print(json.dumps(dict(groups=len(output),diagnostic_occurrences=sum(r['diagnostic_occurrences'] for r in output),all_simple=sum(r['diagnostic_occurrences'] for r in output if r['all_casts_simple']))))
