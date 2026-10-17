"""Execute original quest lookup and comparator with recovered/synthetic names."""
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP
from usb_boundary import destination

def main():
    FUNCTIONS.update(quest_lookup=(0xe122c0,0xe12404),quest_compare=(0xe14f00,0xe14f34),int_compare_unboxed=(0x82d350,0x82d370),
        string_equal_instance=(0x3f5440,0x3f54b4),string_equal=(0x3f5250,0x3f53a4),
        get_enumerator=(0x1585f60,0x1585f84),enum_ctor=(0x11dd130,0x11dd140),enum_dispose=(0x11dd3b0,0x11dd3b8),
        enum_next=(0x11dd3e0,0x11dd488),enum_current=(0x11dd540,0x11dd548),enum_verify=(0x11dd150,0x11dd29c),class_layout_init=(0xb04f60,0xb04fd0))
    scope=CapsuleScope();vm=scope.vm;string_class=HEAP+0x10000
    slot=struct.unpack('<Q',vm.mem_read(0x3979a28,8))[0];scope.put(slot,'Q',string_class);scope.put(string_class+0x122,'B',0)
    list_class=HEAP+0x15000;list_ctx=HEAP+0x16000;enum_class=HEAP+0x18000;enum_ctx=HEAP+0x19000
    for klass,ctx in [(list_class,list_ctx),(enum_class,enum_ctx)]:scope.put(klass+0xc0,'Q',ctx);scope.put(klass+0x121,'BB',3,0)
    for got,info,klass,method in [(0x39e82e8,HEAP+0x14000,list_class,0x1585f60),(0x39e82f0,HEAP+0x17000,enum_class,0x11dd3e0),
        (0x39e82f8,HEAP+0x1c000,enum_class,0x11dd540),(0x39e8300,HEAP+0x1d000,enum_class,0x11dd3b0)]:
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',info);scope.put(info,'Q',method);scope.put(info+0x18,'Q',klass)
    ctor_info=HEAP+0x1a000;verify_info=HEAP+0x1b000
    scope.put(ctor_info,'Q',0x11dd130);scope.put(ctor_info+0x18,'Q',enum_class);scope.put(verify_info,'Q',0x11dd150);scope.put(verify_info+0x18,'Q',enum_class)
    scope.put(list_ctx+0x118,'Q',ctor_info);scope.put(enum_ctx,'Q',verify_info)
    guards=[0x3b855e7,0x3b87856,0x3a34bde]
    for address in guards:vm.mem_write(address,b'\1')
    def string(address,text):
        encoded=text.encode('utf-16-le')
        if len(encoded)+22>0x400:raise ValueError('Fixture string exceeds bounded region')
        vm.mem_write(address,b'\0'*0x400);scope.put(address,'Q',string_class);scope.put(address+0x10,'i',len(encoded)//2);vm.mem_write(address+0x14,encoded+b'\0\0')
    fixture=ROOT/'analysis/reconstruction/quest-reference/quest-fixtures-v1.jsonl';lookups=comparisons=checks=0
    rows=fixture.open(encoding='utf-8');catalog=json.loads(next(rows))
    if catalog['type']!='catalog':raise ValueError('First fixture must declare catalog')
    manager=HEAP;quests=HEAP+0x6000;query_address=HEAP+0x180000;quest_addresses=[]
    for i,name in enumerate(catalog['names']):
        quest=HEAP+0x20000+i*0x100;name_address=HEAP+0x60000+i*0x400;string(name_address,name)
        scope.put(quest+0x78,'Q',name_address);quest_addresses.append(quest)
    scope.sequence(quests,quest_addresses,'Q');scope.put(quests+0x1c,'i',0);scope.put(manager+0x198,'Q',quests)
    for text in rows:
        row=json.loads(text)
        if row['type']=='lookup':
            pointer=0
            if row['query'] is not None:string(query_address,row['query']);pointer=query_address
            actual=scope.invoke('quest_lookup',[manager,pointer,0],[],instruction_limit=200000)
            expected=0 if row['expectedIndex']<0 else quest_addresses[row['expectedIndex']]
            if actual!=expected:raise AssertionError(f'First quest-name identity differs at lookup {lookups}')
            lookups+=1;checks+=1
        elif row['type']=='compare':
            a=HEAP+0x1000;b=HEAP+0x2000
            for address,complete,priority in [(a,row['complete'],row['priority']),(b,row['otherComplete'],row['otherPriority'])]:
                scope.put(address+0x90,'i',complete);scope.put(address+0x64,'i',priority)
            actual=struct.unpack('<i',struct.pack('<I',scope.invoke('quest_compare',[a,b,0],[])))[0]
            if actual!=row['expected']:raise AssertionError(f'Quest comparator differs at pair {comparisons}: {actual} != {row["expected"]}')
            comparisons+=1;checks+=1
        else:raise ValueError('Unknown fixture kind')
    report=dict(status='PASS_COMPILED_QUEST_LOOKUP_COMPARATOR_VS_ORIGINAL_ARM64',lookups=lookups,comparisons=comparisons,checks=checks,
        catalog_entries=len(quest_addresses),fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),executed_functions=dict(scope.visited),
        game_function_mocks=0,text_modified=False,allocation_calls=dict(scope.allocations),metadata_initialization_guards=[hex(g) for g in guards],
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n in ['quest_lookup','quest_compare','int_compare_unboxed','string_equal_instance','string_equal']},
        scope='Original first ordinal name lookup over 559 recovered quest definitions plus three synthetic Unicode/empty names, including duplicate-name ordering. Comparator covers native enum states 0/1/2 and full int32 priority boundaries; ACTIONS/ACTIONS returns +1. Initialized synthetic MethodInfo/RGCTX and valid reference lists; no allocation or game-function mocks. Does not prove global queue ordering, action-state reachability, save-state linkage or story completion.')
    destination(ROOT,ROOT/'reports/native-quest-lookup.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
