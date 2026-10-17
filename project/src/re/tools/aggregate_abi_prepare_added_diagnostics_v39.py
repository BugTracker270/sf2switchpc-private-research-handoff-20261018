"""Bind six canonical additions to exact exported owner declarations."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys
ROOT=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(ROOT/'src/tools'))
from usb_boundary import destination
from compiler_diagnostic_delta import ERROR
def path(relative):return destination(ROOT,ROOT/relative)
before='nso-virtual-companion-copy-v38';after='nso-assembly-leaf-getter-v39'
files={'Unity/IO/Compression/CopyEncoder.cs':'Unity.IO.Compression.CopyEncoder','BestHTTP/HTTPManager.cs':'BestHTTP.HTTPManager','Newtonsoft/Json/Serialization/JsonSerializerInternalReader.cs':'Newtonsoft.Json.Serialization.JsonSerializerInternalReader'}
inputs={};source_bindings=[]
for run in (before,after):
 summary=json.loads(path(f'reports/recovered-source-profile-legacy-reference-check-{run}.json').read_text(encoding='utf-8-sig'))
 assembly=next(a for a in summary['assemblies'] if a['assembly']=='Assembly-CSharp-firstpass')
 manifest={row['path'].replace('\\','/'):row['sha256'] for row in assembly['source_files']}
 texts={}
 for relative in files:
  full=f'analysis/il2cpp/source-profile-project-build-{run}/Assembly-CSharp-firstpass/{relative}'
  raw=path(full).read_bytes();sha=hashlib.sha256(raw).hexdigest();assert manifest[full]==sha
  texts[relative]=raw.decode('utf-8-sig').splitlines();source_bindings.append(dict(run=run,path=full,sha256=sha))
 seen=set();rows=[]
 for line in path(assembly['compiler_log']).read_text(encoding='utf-8-sig').splitlines():
  canonical=re.sub(r'^\d+>','',line.lstrip()).strip()
  if canonical in seen:continue
  match=ERROR.match(canonical)
  if not match:continue
  seen.add(canonical)
  relative=match[1].replace('\\','/').split('/Assembly-CSharp-firstpass/',1)[-1]
  if relative not in files:continue
  code,message=match[4],match[5].strip()
  if (relative.endswith('CopyEncoder.cs') and message!="Operator '+' cannot be applied to operands of type 'byte[]' and 'int'") or (relative.endswith('HTTPManager.cs') and message!="Cannot convert type 'BestHTTP.HTTPProxy' to 'BestHTTP.HTTPConnectionStates'") or (relative.endswith('JsonSerializerInternalReader.cs') and message!="Cannot convert type 'System.Type' to 'nint'"):continue
  number=int(match[2]);declarations=[(n,t.strip())for n,t in enumerate(texts[relative],1)if n<=number and re.match(r'^\t(?:public|private|internal|protected)\s.*\([^;]*\)$',t)]
  declaration_line,declaration=declarations[-1]
  method=declaration.split('(',1)[0].split()[-1]
  rows.append(dict(file=relative,line=number,column=int(match[3]),code=code,message=message,owner=files[relative],method=method,declaration_line=declaration_line))
 inputs[run]=rows
key=lambda row:(row['file'],row['owner'],row['method'],row['code'],row['message'])
counts={run:Counter(key(row)for row in rows)for run,rows in inputs.items()}
added=counts[after]-counts[before]
records=[]
for k,count in added.items():
 candidates=[row for row in inputs[after]if key(row)==k]
 records.append(dict(file=k[0],owner=k[1],method=k[2],code=k[3],message=k[4],added_occurrences=count,before_count=counts[before][k],after_count=counts[after][k],after_locations=[dict(line=r['line'],column=r['column'])for r in candidates]))
assert sum(r['added_occurrences']for r in records)==6
target=path('analysis/reconstruction/assembly-leaf-v39/six-added-diagnostic-input.json')
target.write_text(json.dumps(dict(before=before,after=after,records=records,source_bindings=source_bindings),indent=2)+'\n')
print(json.dumps(dict(added_occurrences=6,records=records)))
