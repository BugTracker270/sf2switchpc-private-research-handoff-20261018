"""Recover the complete frozen v32 matcher source from its locked local patch."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'src/tools'))
from usb_boundary import destination

checkpoint='ae41a90e5be3da0106e4dd15aa847be0463f3dcc'
def frozen_file(relative):
    return subprocess.check_output(['git','-C',str(ROOT),'show',f'{checkpoint}:{relative}'])
lock=json.loads(frozen_file('reports/cpp2il-hfa-experimental-lock.json').decode('utf-8-sig'))
payload=frozen_file(lock['patch'].replace('\\','/'))
if hashlib.sha256(payload).hexdigest()!=lock['sha256'] or lock['sha256']!='effbf13b420f98e3687780b7c0e78b39cfd3420068ca8802c1208be6ab92991a':
    raise ValueError('Frozen v32 patch differs')
relative='Cpp2IL.Core/Utils/LegacyArm64AllocationPattern.cs'
expected=next(row['sha256'] for row in lock['files'] if row['path']==relative)
chunk=payload.decode().split(f'diff --git a/{relative} b/{relative}\n',1)[1].split('\ndiff --git ',1)[0]
if '--- /dev/null\n' not in chunk:raise ValueError('Not a complete original new-file patch')
lines=[line[1:] for line in chunk.splitlines() if line.startswith('+') and not line.startswith('+++')]
source=('\n'.join(lines)+'\n').encode()
if hashlib.sha256(source).hexdigest()!=expected:raise ValueError('Extracted complete helper does not match frozen lock')
folder=destination(ROOT,ROOT/'analysis/reference/class-guard-v32-source');folder.mkdir(parents=True,exist_ok=True)
original=destination(ROOT,folder/'LegacyArm64AllocationPattern.cs');original.write_bytes(source)
renamed=source.replace(b'namespace Cpp2IL.Core.Utils;',b'namespace Cpp2IL.Core.Utils.BaselineV32;',1)
if renamed==source:raise ValueError('Namespace anchor absent')
generated=destination(ROOT,folder/'LegacyArm64AllocationPattern-v32-namespaced.cs');generated.write_bytes(renamed)
report=dict(status='PASS_FROZEN_V32_MATCHER_SOURCE_EXTRACTED',checkpoint=checkpoint,patch_sha256=lock['sha256'],
    original_source_sha256=expected,original_source_lines=len(lines),generated_source_sha256=hashlib.sha256(renamed).hexdigest(),
    generated_source=str(generated.relative_to(ROOT)),only_generated_change='Namespace suffix BaselineV32 permits disjoint source compilation beside the unchanged current matcher.',
    scope='Original complete source is reconstructed byte-for-byte against the frozen local patch and per-file lock. Only a second derived copy changes its namespace. No game source, binary, Core output or frozen patch is modified.')
destination(ROOT,ROOT/'reports/class-guard-baseline-extract-v32.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
