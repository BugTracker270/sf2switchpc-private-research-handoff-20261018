"""Materialize native-observed template precedence; retain raw section provenance.

SetMoveTemplate 0x1022590 visits pipe-separated parents depth first, adding a
parent before recursing. AddAttributes 0x10228C0 only fills absent attributes.
ParseEvents 0x1023AC0 and ParseIntervals 0x1023D00 append own section first,
then each unique visited template. This tool does not execute their factories.
"""
import collections
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def resolve(move,templates):
    name=move['attributes']['Name'];attributes=dict(move['attributes'])
    origins={key:name for key in attributes};order=[];missing=[];visited=set()
    def visit(node):
        for parent in node['attributes'].get('Template','').split('|'):
            if not parent or parent in visited:continue
            template=templates.get(parent)
            if template is None:
                missing.append(dict(owner=node['attributes']['Name'],missing=parent));continue
            visited.add(parent);order.append(parent)
            for key,value in template['attributes'].items():
                if key not in attributes:attributes[key]=value;origins[key]=parent
            visit(template)
    visit(move)
    sections={}
    for tag in ['Events','Intervals']:
        entries=[]
        for owner,node in [(name,move)]+[(p,templates[p]) for p in order]:
            matches=[c for c in node.get('children',[]) if c['tag']==tag]
            if len(matches)>1:raise ValueError('Multiple same-name sections require explicit XmlNode first-child audit')
            if matches:
                entries.extend(dict(owner=owner,ordinal=i,raw_node=child) for i,child in enumerate(matches[0].get('children',[])))
        sections[tag]=entries
    return dict(name=name,attributes=attributes,attribute_origins=origins,template_order=order,
        missing_parents=missing,ordered_section_candidates=sections)

def main():
    source=ROOT/'analysis/assets/content-v2/moves.json';data=json.loads(source.read_text(encoding='utf-8'))
    templates={t['attributes']['Name']:t for t in data['templates']}
    if len(templates)!=len(data['templates']):raise ValueError('Duplicate templates')
    output=destination(ROOT,ROOT/'analysis/assets/moves-resolved-v1');output.mkdir(exist_ok=True)
    rows=[resolve(m,templates) for m in data['moves']]
    no_explicit=[r for m,r in zip(data['moves'],rows) if not m['attributes'].get('FileName')]
    missing=sorted({(e['owner'],e['missing']) for r in rows for e in r['missing_parents']})
    for row in no_explicit:
        a=row['attributes'];row['filename_classification']='INHERITED_FILE' if a.get('FileName') else ('PHYSICS_WITHOUT_FILE' if a.get('Physics')=='1' else 'NO_ANIMATION_WITHOUT_FILE' if a.get('NoAnimation')=='1' else 'UNEXPLAINED_NO_FILE')
    if any(r['filename_classification']=='UNEXPLAINED_NO_FILE' for r in no_explicit):raise ValueError('Unexplained missing filename')
    for name,value in [('moves.json',rows),('no-explicit-file.json',no_explicit)]:
        destination(ROOT,output/name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    summary=dict(status='STATIC_NATIVE_PARSER_SCHEMA_APPLIED',moves=len(rows),templates=len(templates),
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        original_moves_payload_sha256=data['source_sha256'],
        moves_without_explicit_filename=len(no_explicit),filename_classifications=dict(collections.Counter(r['filename_classification'] for r in no_explicit)),
        missing_template_definitions=[dict(owner=a,missing=b) for a,b in missing],
        ordered_candidate_counts={tag:sum(len(r['ordered_section_candidates'][tag]) for r in rows) for tag in ['Events','Intervals']},
        native_evidence=dict(precedence='0x1022590',attributes='0x10228C0',events='0x1023AC0',intervals='0x1023D00',empty_filename_gate='0x1017400'),
        limitations='Static native control-flow interpretation applied to recovered XML. Missing parents are logged and skipped by the original parser; they are not replaced. Raw ordered section candidates are not certified instantiated events/intervals. Does not cover every action, lock, transition, trigger or interval frame rule; no full parser runtime equivalence claim.')
    destination(ROOT,output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    destination(ROOT,ROOT/'reports/move-template-resolution.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
