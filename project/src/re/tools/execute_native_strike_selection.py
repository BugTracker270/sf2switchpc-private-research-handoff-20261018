"""Execute original strike selection, collection iteration and capsule contact."""
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP
from usb_boundary import destination

def main():
    FUNCTIONS.update(capsules=(0x15c5210,0x15c5698),segment_intersection=(0x15c4cb0,0x15c50a0),
        distance_contact=(0x15c50a0,0x15c520c),equation_line=(0x15c4a90,0x15c4b7c),allocated_equation_line=(0x15c4b80,0x15c4ca8),
        equation_ctor=(0x10eb720,0x10eb74c),object_ctor=(0x65a2a0,0x65a2a4),vector_ctor=(0x15c59a0,0x15c59cc),vector_set=(0x15c56a0,0x15c56bc),
        cross_model=(0x1005db0,0x1005fb8),get_enumerator=(0x1585f60,0x1585f84),enum_ctor=(0x11dd130,0x11dd140),
        enum_dispose=(0x11dd3b0,0x11dd3b8),enum_next=(0x11dd3e0,0x11dd488),enum_current=(0x11dd540,0x11dd548),
        enum_verify=(0x11dd150,0x11dd29c),class_layout_init=(0xb04f60,0xb04fd0))
    scope=CapsuleScope();vm=scope.vm
    for got,klass,name in [(0x3980340,HEAP+0x10000,'Mathf'),(0x39d6110,HEAP+0x11000,'Vector3f'),(0x39fb428,HEAP+0x12000,'EquationLine')]:
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',klass);scope.put(klass+0x121,'BB',3,0)
        if name!='Mathf':scope.types[klass]=name;scope.put(klass+0xe8,'I',32)
    list_class=HEAP+0x15000;list_ctx=HEAP+0x16000;enum_class=HEAP+0x18000;enum_ctx=HEAP+0x19000
    for klass,ctx in [(list_class,list_ctx),(enum_class,enum_ctx)]:scope.put(klass+0xc0,'Q',ctx);scope.put(klass+0x121,'BB',3,0)
    infos={0x39fbaa0:(HEAP+0x14000,list_class,0x1585f60),0x39fbaa8:(HEAP+0x17000,enum_class,0x11dd3e0),
        0x39fbab0:(HEAP+0x1c000,enum_class,0x11dd540),0x39fbab8:(HEAP+0x1d000,enum_class,0x11dd3b0)}
    for got,(info,klass,method) in infos.items():
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',info);scope.put(info,'Q',method);scope.put(info+0x18,'Q',klass)
    ctor_info=HEAP+0x1a000;verify_info=HEAP+0x1b000
    scope.put(ctor_info,'Q',0x11dd130);scope.put(ctor_info+0x18,'Q',enum_class)
    scope.put(verify_info,'Q',0x11dd150);scope.put(verify_info+0x18,'Q',enum_class)
    scope.put(list_ctx+0x118,'Q',ctor_info);scope.put(enum_ctx,'Q',verify_info)
    guards=[0x3b898fd,0x3b898f9,0x3b898f8,0x3b89901,0x3b898ad,0x3b898fb,0x3b898fc,0x3b8696d,0x3b87856]
    for address in guards:vm.mem_write(address,b'\1')
    model=HEAP;strike=HEAP+0x9000;point=HEAP+0xa000;point_strike=HEAP+0xb000;enemy_list=HEAP+0x6000
    scope.put(model+0x30,'Q',strike);scope.put(strike+0x20,'QQ',point,point_strike)
    def line(a,b):
        import math
        from execute_native_ai_leaves import f32
        a=list(map(f32,a));b=list(map(f32,b))
        dx=f32(a[0]-b[0]);dy=f32(a[1]-b[1]);length=f32(math.sqrt(f32(f32(dx*dx)+f32(dy*dy))))
        x=f32(dy/length);y=f32(f32(b[0]-a[0])/length)
        return [x,y,-f32(f32(x*a[0])+f32(y*a[1]))]
    def edge(row,address):
        start=address+0x100;end=address+0x200;equation=address+0x300
        scope.put(start+0x10,'3f',*row['Start']);scope.put(end+0x10,'3f',*row['End'])
        scope.put(equation+0x10,'3f',*line(row['Start'],row['End']))
        scope.put(address+0x20,'Q',equation);scope.put(address+0x5c,'f',row['Radius']);scope.put(address+0x70,'QQ',start,end)
        return address
    fixture=ROOT/'analysis/reconstruction/strike-reference/strike-fixtures-v1.jsonl';cases=checks=hits=0
    for text in fixture.open(encoding='utf-8'):
        row=json.loads(text);scope.next_allocation=HEAP+0x1c0000
        attack=edge(row['attack'],HEAP+0x20000);enemies={e['Id']:edge(e,HEAP+0x30000+e['Id']*0x1000) for e in row['enemies']}
        scope.sequence(enemy_list,[enemies[e['Id']] for e in row['enemies']],'Q');scope.put(enemy_list+0x1c,'i',0)
        scope.put(strike+0x10,'QQ',HEAP+0x190000,HEAP+0x190100)
        scope.put(point+0x10,'3f',-123,-456,7);scope.put(point_strike+0x10,'3f',-321,-654,9)
        actual=scope.invoke('cross_model',[model,enemy_list,attack,0],[]);checks+=1
        hit=row['selected']>=0
        if bool(actual)!=hit:raise AssertionError(f'Strike hit result differs at fixture {cases}')
        selected,attacker=struct.unpack('<QQ',vm.mem_read(strike+0x10,16));checks+=2
        expected_enemy=enemies[row['selected']] if hit else HEAP+0x190000
        if selected!=expected_enemy or attacker!=(attack if hit else HEAP+0x190100):raise AssertionError(f'First-contact identity differs at fixture {cases}')
        for address,key in [(point,'pointBits'),(point_strike,'pointStrikeBits')]:
            bits=list(struct.unpack('<3I',vm.mem_read(address+0x10,12)));checks+=3
            if bits!=row[key]:raise AssertionError(f'Strike contact point differs at fixture {cases}: {bits} != {row[key]}')
        cases+=1;hits+=actual
    report=dict(status='PASS_COMPILED_STRIKE_SELECTION_VS_ORIGINAL_ARM64',cases=cases,checks=checks,contacts=hits,
        fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),calls=dict(scope.calls),executed_functions=dict(scope.visited),
        runtime_allocation_model=dict(scope.allocations),allocation_hook_rva='0xB5B110',game_function_mocks=0,text_modified=False,
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n in ['cross_model','get_enumerator','enum_ctor','enum_dispose','enum_next','enum_current','enum_verify','class_layout_init']},
        metadata_initialization_guards=[hex(g) for g in guards],
        scope='Original strike selection, list iteration, class-initialization fast path and capsule/contact math. Synthetic initialized MethodInfo/RGCTX, valid lists and edges; only Vector3f/EquationLine allocation modeled. No whole-fight or GC parity claim.')
    destination(ROOT,ROOT/'reports/native-strike-selection.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
