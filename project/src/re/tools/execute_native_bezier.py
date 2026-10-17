"""Execute original animation Bezier constructor/curve with pre-sized buffers."""
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP
from usb_boundary import destination

def main():
    FUNCTIONS.update(bezier_ctor=(0xd3fe80,0xd3ff3c),bezier_curve=(0xd3ff40,0xd402e0),bezier_middle=(0xd402f0,0xd40354),
        vector_middle=(0x15c7760,0x15c77b0),object_ctor=(0x65a2a0,0x65a2a4),vector_ctor=(0x15c59a0,0x15c59cc),
        vector_get_x=(0x15c3a90,0x15c3a98),vector_get_y=(0x15c3aa0,0x15c3aa8),vector_get_z=(0x15c5a70,0x15c5a78),
        vector_set_x=(0x15c3c10,0x15c3c18),vector_set_y=(0x15c3c20,0x15c3c28),vector_set_z=(0x15c5ad0,0x15c5ad8),
        get_enumerator=(0x1585f60,0x1585f84),enum_ctor=(0x11dd130,0x11dd140),enum_dispose=(0x11dd3b0,0x11dd3b8),
        enum_next=(0x11dd3e0,0x11dd488),enum_current=(0x11dd540,0x11dd548),enum_verify=(0x11dd150,0x11dd29c),class_layout_init=(0xb04f60,0xb04fd0))
    scope=CapsuleScope();vm=scope.vm
    klass=HEAP+0x10000;slot=struct.unpack('<Q',vm.mem_read(0x39d6110,8))[0]
    scope.put(slot,'Q',klass);scope.types[klass]='Vector3f';scope.put(klass+0xe8,'I',32);scope.put(klass+0x121,'BB',3,0)
    list_class=HEAP+0x15000;list_ctx=HEAP+0x16000;enum_class=HEAP+0x18000;enum_ctx=HEAP+0x19000
    for klass,ctx in [(list_class,list_ctx),(enum_class,enum_ctx)]:scope.put(klass+0xc0,'Q',ctx);scope.put(klass+0x121,'BB',3,0)
    for got,info,klass,method in [(0x39de688,HEAP+0x14000,list_class,0x1585f60),(0x39de690,HEAP+0x17000,enum_class,0x11dd3e0),
        (0x39de698,HEAP+0x1c000,enum_class,0x11dd540),(0x39de6a0,HEAP+0x1d000,enum_class,0x11dd3b0)]:
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',info);scope.put(info,'Q',method);scope.put(info+0x18,'Q',klass)
    ctor_info=HEAP+0x1a000;verify_info=HEAP+0x1b000
    scope.put(ctor_info,'Q',0x11dd130);scope.put(ctor_info+0x18,'Q',enum_class);scope.put(verify_info,'Q',0x11dd150);scope.put(verify_info+0x18,'Q',enum_class)
    scope.put(list_ctx+0x118,'Q',ctor_info);scope.put(enum_ctx,'Q',verify_info)
    slot=struct.unpack('<Q',vm.mem_read(0x39de668,8))[0];scope.put(slot,'Q',HEAP+0x1e000)
    guards=[0x3b84dd9,0x3b84dda,0x3b87856]
    for address in guards:vm.mem_write(address,b'\1')
    this=HEAP;a=HEAP+0x2000;b=HEAP+0x3000;c=HEAP+0x4000;receiver=HEAP+0x6000
    fixture=ROOT/'analysis/reconstruction/bezier-reference/bezier-fixtures-v1.jsonl';cases=checks=samples=0
    def compare(address,expected,label):
        nonlocal checks
        actual=list(struct.unpack('<'+str(len(expected))+'I',vm.mem_read(address,len(expected)*4)));checks+=len(expected)
        if actual!=expected:raise AssertionError(f'{label} differs at fixture {cases}: {actual} != {expected}')
    for text in fixture.open(encoding='utf-8'):
        row=json.loads(text);scope.next_allocation=HEAP+0x1c0000
        for address,key in [(a,'a'),(b,'b'),(c,'c')]:scope.put(address+0x10,'3f',*row[key])
        scope.invoke('bezier_ctor',[this,row['count'],0],[]);compare(this+0x20,row['coefficientBits'],'coefficients')
        points=[HEAP+0x40000+i*0x100 for i in range(row['count'])]
        scope.sequence(receiver,points,'Q');scope.put(receiver+0x1c,'i',0)
        if row['middle']:
            scope.invoke('bezier_middle',[this,a,b,c,receiver,0],[],instruction_limit=100000)
            ab,bc=struct.unpack('<QQ',vm.mem_read(this+0x10,16));compare(ab+0x10,row['middleABBits'],'AB midpoint');compare(bc+0x10,row['middleBCBits'],'BC midpoint')
        else:scope.invoke('bezier_curve',[this,a,b,c,row['count'],receiver,0],[],instruction_limit=100000)
        for address,expected in zip(points,row['sampleBits']):compare(address+0x10,expected,'curve sample');samples+=1
        cases+=1
    report=dict(status='PASS_COMPILED_BEZIER_VS_ORIGINAL_ARM64',cases=cases,samples=samples,checks=checks,
        fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),executed_functions=dict(scope.visited),calls=dict(scope.calls),
        runtime_allocation_model=dict(scope.allocations),allocation_hook_rva='0xB5B110',game_function_mocks=0,text_modified=False,
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n in ['bezier_ctor','bezier_curve','bezier_middle','vector_middle']},
        metadata_initialization_guards=[hex(g) for g in guards],
        scope='Original Bezier coefficients, curve recurrence, midpoint helper, vector accessors and list iteration. Finite points; positive sample counts 1..120 from the listed fixture set; pre-sized non-null output vectors. Synthetic initialized generic metadata; only Vector3f allocation modeled. Resize/delegate allocation, full animation scheduling, interrupts and rendering/FPS remain unverified.')
    destination(ROOT,ROOT/'reports/native-animation-bezier.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
