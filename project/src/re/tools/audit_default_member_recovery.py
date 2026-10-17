"""Correlate native attribute evidence, emitted metadata and actual indexer source output."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',required=True)
    parser.add_argument('--source-kind',choices=['source-project-build','source-profile-project-build'],default='source-project-build')
    args=parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+',args.run):raise ValueError('Invalid run')
    native=json.loads((ROOT/'reports/native-default-member-argument.json').read_text(encoding='utf-8-sig'))
    if native['status']!='PASS_ORIGINAL_DEFAULT_MEMBER_ARGUMENT_AT_RUNTIME_BOUNDARIES' or native['recovered_member_name']!='Item' or native['text_modified']:raise ValueError('Native argument evidence is missing')
    audit_path=ROOT/f'analysis/il2cpp/attribute-contract-audit-{args.run}/summary.json'
    audit=json.loads(audit_path.read_text(encoding='utf-8-sig'))
    recovered=ROOT/f'analysis/il2cpp/cpp2il-recovery-{args.run}'
    if Path(audit.get('source_directory','')).resolve()!=recovered.resolve():raise ValueError('Attribute audit is not bound to this recovery run')
    expected={path.name for path in recovered.glob('*.dll')}
    if {row['file'] for row in audit['assemblies']}!=expected:raise ValueError('Attribute audit does not cover the exact assembly set')
    for row in audit['assemblies']:
        if hashlib.sha256((recovered/row['file']).read_bytes()).hexdigest()!=row['sha256']:raise ValueError('Attribute audit assembly digest differs')
    total=sum(row['default_member_count'] for row in audit['assemblies'])
    log=(ROOT/f'logs/cpp2il-{args.run}-recovery.log').read_text(encoding='utf-8-sig')
    counts=re.findall(r'Recovered (\d+) DefaultMember arguments from strict native generators',log)
    if len(counts)!=1 or int(counts[0])!=total or total<3:raise ValueError('Emitted attribute contracts differ from actual recovery count')
    firstpass=next(row for row in audit['assemblies'] if row['file']=='Assembly-CSharp-firstpass.dll')
    witness=next(row for row in firstpass['default_members'] if row['owner']=='Newtonsoft.Json.Utilities.ListWrapper`1')
    if witness['value']!=native['recovered_member_name']:raise ValueError('Recovered native/metadata property names differ')
    source=ROOT/f'analysis/il2cpp/{args.source_kind}-{args.run}/Assembly-CSharp-firstpass/Newtonsoft/Json/Utilities/ListWrapper.cs'
    text=source.read_text(encoding='utf-8-sig')
    if 'this[int index]' not in text or "C# has no syntax for parameterized property 'Item'" in text:raise ValueError('Actual project export did not restore indexer syntax')
    report=dict(status='PASS_NATIVE_ARGUMENT_METADATA_AND_INDEXER_SOURCE_CORRELATION',recovery_run=args.run,
        recovered_attributes=total,assemblies=[dict(file=row['file'],recovered=row['default_member_count']) for row in audit['assemblies']],
        native_generator=native['generator'],native_member_name=native['recovered_member_name'],
        actual_source=str(source.relative_to(ROOT)),actual_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        attribute_audit=str(audit_path.relative_to(ROOT)),attribute_audit_sha256=hashlib.sha256(audit_path.read_bytes()).hexdigest(),
        scope='Strict single-attribute native generator shape, constructor identity, common UTF8 wrapper consensus and matching real property names. Original native conversion/constructor path independently observed for ListWrapper at explicit allocation/libc boundaries. All emitted arguments decode and match metadata properties; actual source renders an indexer. This does not certify method bodies, all other attributes, or complete clean source.')
    destination(ROOT,ROOT/f'reports/recovered-default-member-{args.run}.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
