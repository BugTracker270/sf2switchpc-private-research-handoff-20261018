"""Compare original ModelAnimation.DrawFrame with a compiled reference step."""
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP
from usb_boundary import destination

def main():
    FUNCTIONS.update(animation_draw=(0x1002370,0x100267c),vector_ctor=(0x15c59a0,0x15c59cc),
        vector_copy_ctor=(0x15c5a20,0x15c5a64),object_ctor=(0x65a2a0,0x65a2a4),
        vector_set=(0x15c56a0,0x15c56bc),vector_multiply=(0x15c5770,0x15c5794),vector_add=(0x15c57a0,0x15c57d0),
        rotation_angle=(0x101ab90,0x101ab98),slow_mode_getter=(0xd40b70,0xd40bd8))
    scope=CapsuleScope();vm=scope.vm
    klass=HEAP+0x10000;slot=struct.unpack('<Q',vm.mem_read(0x39d6110,8))[0]
    scope.put(slot,'Q',klass);scope.types[klass]='Vector3f';scope.put(klass+0xe8,'I',32)
    game_class=HEAP+0x11000;game_statics=HEAP+0x12000
    slot=struct.unpack('<Q',vm.mem_read(0x397ad38,8))[0];scope.put(slot,'Q',game_class);scope.put(game_class+0xb8,'Q',game_statics);scope.put(game_class+0x122,'B',0)
    for got in [0x39fbc68,0x39fbc70,0x39edc58,0x39de678,0x39de668]:
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',HEAP+0x14000)
    guards=[0x3b869c4,0x3b869cd,0x3b869ce,0x3b84de2]
    for address in guards:vm.mem_write(address,b'\1')
    this=HEAP;model=HEAP+0x2000;model_nodes=HEAP+0x3000;node_list=HEAP+0x4000;buffers=HEAP+0x6000
    shift=HEAP+0x8000;velocity=HEAP+0x9000;accel=HEAP+0xa000;animation_info=HEAP+0xb000
    scope.put(this+0xb8,'Q',model);scope.put(model+0x10,'Q',model_nodes);scope.put(model_nodes+0x28,'Q',node_list)
    scope.put(this+0x90,'QQQ',shift,velocity,accel);scope.put(this+0xd0,'Q',buffers);scope.put(this+0xf0,'Q',animation_info)
    fixture=ROOT/'analysis/reconstruction/animation-step-reference/animation-step-fixtures-v1.jsonl';cases=checks=nodes_updated=nodes_skipped=0
    def compare(address,expected,label):
        nonlocal checks
        actual=list(struct.unpack('<'+str(len(expected))+'I',vm.mem_read(address,len(expected)*4)));checks+=len(expected)
        if actual!=expected:raise AssertionError(f'{label} differs at fixture {cases}: {actual} != {expected}')
    for text in fixture.open(encoding='utf-8'):
        row=json.loads(text);scope.next_allocation=HEAP+0x1c0000
        for address,key in [(shift,'shift'),(velocity,'velocity'),(accel,'acceleration')]:scope.put(address+0x10,'3f',*row[key])
        scope.put(this+0xd8,'ii',row['index'],row['bufferSlowMode']);scope.put(this+0xa8,'f',row['factor']);scope.put(model+0x40,'B',row['shock'])
        scope.put(game_statics+0xa0,'i',row['slowMode']);node_addresses=[];buffer_addresses=[]
        for n,node in enumerate(row['nodes']):
            address=HEAP+0x20000+n*0x4000;current=address+0x1000;previous=address+0x2000;buffer=HEAP+0x50000+n*0x8000
            node_addresses.append(address);buffer_addresses.append(buffer)
            scope.put(address+0x20,'QQ',current,previous);scope.put(address+0x5b,'B',node['nodeShock']);scope.put(address+0x5e,'B',node['animated'])
            scope.put(current+0x10,'3f',*node['current']);scope.put(previous+0x10,'3f',*node['previous'])
            points=[buffer+0x1000+j*0x100 for j in range(row['sampleCount'])];scope.sequence(buffer,points,'Q')
            for point,values in zip(points,node['buffer']):scope.put(point+0x10,'3f',*values)
        scope.sequence(node_list,node_addresses,'Q');scope.sequence(buffers,buffer_addresses,'Q')
        scope.invoke('animation_draw',[this,0],[],instruction_limit=100000)
        compare(shift+0x10,row['shiftBits'],'accumulated shift');compare(velocity+0x10,row['velocityBits'],'accelerated velocity')
        index=struct.unpack('<i',vm.mem_read(this+0xd8,4))[0];first=bool(vm.mem_read(this+0x33,1)[0]);checks+=2
        if index!=row['nextIndex'] or first!=row['firstReached']:raise AssertionError('Buffer index or first-index flag differs')
        for address,node in zip(node_addresses,row['nodes']):
            current,previous=struct.unpack('<QQ',vm.mem_read(address+0x20,16));compare(current+0x10,node['expectedCurrentBits'],'current point');compare(previous+0x10,node['expectedPreviousBits'],'previous point')
            checks+=1
            if bool(vm.mem_read(address+0x5e,1)[0])!=node['expectedAnimated']:raise AssertionError('Frame-animated flag differs')
            if row['shock'] and node['nodeShock']:nodes_skipped+=1
            else:nodes_updated+=1
        cases+=1
    report=dict(status='PASS_COMPILED_ANIMATION_DRAW_VS_ORIGINAL_ARM64',cases=cases,checks=checks,nodes_updated=nodes_updated,nodes_skipped=nodes_skipped,
        fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),executed_functions=dict(scope.visited),calls=dict(scope.calls),
        runtime_allocation_model=dict(scope.allocations),game_function_mocks=0,text_modified=False,metadata_initialization_guards=[hex(g) for g in guards],
        original_text_sha256=hashlib.sha256(vm.mem_read(0x1002370,0x30c)).hexdigest(),
        scope='Original DrawFrame sample application, prior/current node state, shock exclusion, velocity/acceleration and slow-mode index logic with valid nonempty pre-populated buffers. Initialized synthetic metadata and Vector3f allocation model. Does not execute full Render/SetBufferFrame/events/interrupt scheduling, Unity rendering or gameplay FPS.')
    destination(ROOT,ROOT/'reports/native-animation-step.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
