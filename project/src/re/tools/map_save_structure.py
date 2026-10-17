"""Map default save XML and native-observed path/slot identities locally."""
import collections
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    folder=ROOT/'analysis/assets/unity-export/ExportedProject/Assets/Resources/gamedata'
    schemas=[];private=[]
    for name,expected_root in [('usersDefault.bytes','Root'),('usersDefaultWarrior.bytes','Warrior')]:
        path=folder/name;raw=path.read_bytes();root=ET.fromstring(raw)
        if root.tag!=expected_root:raise ValueError('Unexpected default save document root')
        nodes=list(root.iter());schemas.append(dict(source=str(path.relative_to(ROOT)),sha256=hashlib.sha256(raw).hexdigest(),
            root=root.tag,elements=len(nodes),top_level_tags=[n.tag for n in root],
            tag_counts=dict(collections.Counter(n.tag for n in nodes)),root_attribute_names=sorted(root.attrib)))
        def walk(node,parent):
            current=parent+'/'+node.tag
            private.append(dict(source=name,path=current,attributes=node.attrib))
            for child in node:walk(child,current)
        walk(root,'')
    user=ET.fromstring((folder/'usersDefault.bytes').read_bytes());warrior=ET.fromstring((folder/'usersDefaultWarrior.bytes').read_bytes())
    if user.find('Warriors') is None or user.find('CurrentUser').get('LastSaveSlot')!='0' or warrior.get('SaveSlot')!='0':
        raise ValueError('Default logical-slot structure changed')
    bindings=json.loads((ROOT/'analysis/assets/save-slot-bindings.json').read_text(encoding='utf-8-sig'))
    if bindings['indices']!=[0,1,2,3]:raise ValueError('Four original menu slot bindings required')
    metadata=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    strings={row['Address']:row['Value'] for row in metadata['ScriptString']}
    selected={0x3b76f60:'data:',0x3b811a8:'/userdata',0x3b79ca8:'users.xml',0x3b7b128:'users_backup.xml',
        0x3b770f8:'{0}/{1}',0x3b6e938:'Root',0x3b7b590:'Warriors',0x3b7adc8:'SaveSlot'}
    for address,value in selected.items():
        if strings.get(address)!=value:raise ValueError('Native-observed save string identity changed')
    report=dict(status='PASS_DEFAULT_XML_AND_NATIVE_PATH_IDENTITIES',defaults=schemas,menu_slot_indices=bindings['indices'],
        paths=dict(storage='data:/userdata',primary='data:/userdata/users.xml',backup='data:/userdata/users_backup.xml'),
        native_string_slots={hex(a):s for a,s in selected.items()},
        evidence=dict(storage_init='0xE22E30',storage_getter='0xE1E2C0',users_path='0xD0F750',backup_path='0xD0F800',
            warrior_lookup='0xD26760',delete_slot='0xD25B50',slot_load_coroutine='0xE6F310'),
        scope='Default documents and native-observed path composition/slot lookup identities. Logical slots are Warrior records, with shared CurrentUser settings. Not a complete runtime schema, existing-user save export, Windows path, migration or corruption/failure parity claim.')
    destination(ROOT,ROOT/'analysis/assets/default-save-schema.json').write_text(json.dumps(private,indent=2)+'\n',encoding='utf-8')
    destination(ROOT,ROOT/'reports/save-schema-research.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
