"""Validate animation template references without guessing merge precedence."""
import collections
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def inspect(data):
    templates={};duplicates=[]
    for row in data['templates']:
        name=row['attributes']['Name']
        if name in templates:duplicates.append(name)
        templates[name]=row
    def parents(row):return [n.strip() for n in row['attributes'].get('Template','').split('|') if n.strip()]
    missing=[];cycles=[]
    def lineage(name,trail):
        if name in trail:cycles.append(trail+[name]);return []
        if name not in templates:return []
        row=templates[name]
        return [row]+[r for parent in parents(row) for r in lineage(parent,trail+[name])]
    for row in data['templates']+data['moves']:
        for parent in parents(row):
            if parent not in templates:missing.append(dict(owner=row['attributes']['Name'],missing=parent))
    for name in templates:lineage(name,[])
    no_file=[]
    for row in data['moves']:
        attributes=row['attributes']
        if attributes.get('FileName'):continue
        ancestors=[r for parent in parents(row) for r in lineage(parent,[])]
        candidates=sorted({r['attributes']['FileName'] for r in ancestors if r['attributes'].get('FileName')})
        flags=collections.defaultdict(set)
        for r in [row]+ancestors:
            for key in ('NoAnimation','Physics'):
                if key in r['attributes']:flags[key].add(r['attributes'][key])
        classification='INHERITED_FILE_CANDIDATE' if len(candidates)==1 else ('AMBIGUOUS_FILES' if len(candidates)>1 else 'NO_FILE_IN_LINEAGE')
        no_file.append(dict(move=attributes['Name'],parents=parents(row),file_candidates=candidates,
            observed_flags={k:sorted(v) for k,v in flags.items()},classification=classification))
    return dict(templates=len(templates),duplicate_template_names=duplicates,missing_template_references=missing,
        cycles=cycles,moves_without_explicit_file=no_file,classification_counts=dict(collections.Counter(r['classification'] for r in no_file)),
        limitation='File candidates and explicit flags are recovered data. Parent precedence, event merging and physical/no-animation runtime behavior need native parser validation.')

def main():
    source=ROOT/'analysis/assets/content-v2/moves.json';report=inspect(json.loads(source.read_text(encoding='utf-8')))
    destination(ROOT,ROOT/'analysis/assets/content-v2/template-inheritance.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='moves_without_explicit_file'},indent=2))
if __name__=='__main__':main()
