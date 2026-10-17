"""Map recovered quest Includes and potential AttachQuestFile edges.

Native ParseQuests 0xD12370 deduplicates filenames before reading, processes
children in file order, constructs Quest nodes and recursively processes Include
File attributes. AttachQuestFile.RunAction 0xD74010 calls that same loader.
Potential attachment closure is not a proof that its event/conditions can run.
"""
import collections
import hashlib
import json
from pathlib import Path,PurePosixPath
import sqlite3
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]
DATA=ROOT/'analysis/assets/unity-export/ExportedProject/Assets/Resources/gamedata'

def resource_path(logical):
    name=PurePosixPath(logical.replace('\\','/'))
    if name.is_absolute() or ':' in logical or '..' in name.parts:raise ValueError('Quest path outside recovered game-data root')
    if name.suffix.lower()!='.xml':raise ValueError('Unreviewed quest resource suffix: '+logical)
    path=(DATA/Path(*name.with_suffix('.bytes').parts)).resolve()
    if not path.is_relative_to(DATA.resolve()):raise ValueError('Quest resource escaped game-data root')
    return path

def main():
    output=destination(ROOT,ROOT/'analysis/assets/quest-loading-v1');output.mkdir(exist_ok=True)
    files={};edges=[];missing=[]
    def load(logical):
        if logical in files:return files[logical]
        path=resource_path(logical)
        if not path.is_file():missing.append(dict(file=logical,status='RESOURCE_NOT_PRESENT'));return None
        raw=path.read_bytes();root=ET.fromstring(raw)
        if root.tag!='Quests':raise ValueError('Unreviewed quest document root: '+logical+' '+root.tag)
        rows=[]
        for ordinal,node in enumerate(root):
            if node.tag=='Include':
                target=node.attrib['File'];edges.append(dict(source=logical,target=target,kind='INCLUDE',ordinal=ordinal))
            elif node.tag=='Quest':
                name=node.attrib.get('Name')
                if not name:raise ValueError('Unnamed quest requires constructor default audit')
                rows.append(dict(name=name,ordinal=ordinal,attributes=dict(node.attrib),
                    event_tags=[c.tag for e in node if e.tag=='Events' for c in e],
                    condition_tags=[c.tag for e in node if e.tag=='Conditions' for c in e],
                    action_tags=[c.tag for e in node if e.tag=='Actions' for c in e]))
                for action in node.iter('AttachQuestFile'):
                    target=action.attrib.get('File','')
                    if not target:raise ValueError('Attachment without literal File requires parser audit')
                    edges.append(dict(source=logical,target=target,kind='POTENTIAL_ACTION_ATTACHMENT',quest=name))
            else:raise ValueError('Unreviewed top-level quest tag: '+node.tag)
        files[logical]=dict(logical=logical,path=str(path.relative_to(ROOT)),sha256=hashlib.sha256(raw).hexdigest(),quests=rows)
        return files[logical]
    def closure(attachments):
        seen=set();ordered=[];quests=[];suppressed=[]
        def visit(logical):
            if logical in seen:suppressed.append(logical);return
            seen.add(logical);row=load(logical)
            if row is None:return
            ordered.append(logical)
            own={q['ordinal']:q for q in row['quests']}
            includes={e['ordinal']:e for e in edges if e['source']==logical and e['kind']=='INCLUDE'}
            for ordinal in sorted(set(own)|set(includes)):
                if ordinal in includes:visit(includes[ordinal]['target'])
                else:quests.append(dict(file=logical,**own[ordinal]))
            if attachments:
                for edge in list(edges):
                    if edge['source']==logical and edge['kind']=='POTENTIAL_ACTION_ATTACHMENT':visit(edge['target'])
        visit('quests.xml')
        return dict(files=ordered,quests=quests,suppressed_duplicate_loads=suppressed)
    initial=closure(False);potential=closure(True)
    for label,value in [('initial-load.json',initial),('potential-attachment-closure.json',potential),('files.json',files),('edges.json',edges)]:
        destination(ROOT,output/label).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    if missing:raise ValueError('Quest resource references missing; details: '+json.dumps(missing))
    sensei='quest_extensions/sensei_arc.xml'
    if sensei not in initial['files']:raise ValueError('Sensei extension not reached by root Include traversal')
    names=collections.Counter(q['name'] for q in potential['quests'])
    summary=dict(status='STATIC_NATIVE_QUEST_LOADING_GRAPH_APPLIED',root='quests.xml',initial_files=len(initial['files']),initial_quest_definitions=len(initial['quests']),
        potential_files=len(potential['files']),potential_quest_definitions=len(potential['quests']),
        sensei_in_root_include_graph=True,sensei_quest_definitions=len(files[sensei]['quests']),
        edge_counts=dict(collections.Counter(e['kind'] for e in edges)),missing_resources=missing,
        duplicate_quest_names={n:c for n,c in names.items() if c>1},
        native_evidence=dict(parse_quests='0xD12370',attach_action='0xD74010'),
        limitations='Root Includes follow native load ordering and filename deduplication. Potential attachment closure ignores quest conditions, event timing and native action factories; it is an upper bound on referenced files, not playable-mode or complete story-progression certification. Resource .xml logical names map to recovered .bytes TextAssets; original payload hashes retained.')
    destination(ROOT,output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    destination(ROOT,ROOT/'reports/quest-loading-graph.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8');print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
