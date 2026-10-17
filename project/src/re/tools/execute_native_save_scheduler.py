"""Exercise native save request/dispatch timing with a supplied Unity clock."""
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP,STOP
from usb_boundary import destination
from unicorn import arm64_const as reg

SAVE_FUNCTIONS=dict(save_request=(0xfc3fd0,0xfc3fec),base_save=(0xfc5870,0xfc58ec),timer_tick=(0xfe43a0,0xfe45f0),
    get_enumerator=(0x1585f60,0x1585f84),enum_ctor=(0x11dd130,0x11dd140),enum_dispose=(0x11dd3b0,0x11dd3b8),
    enum_next=(0x11dd3e0,0x11dd488),enum_current=(0x11dd540,0x11dd548),enum_verify=(0x11dd150,0x11dd29c),class_layout_init=(0xb04f60,0xb04fd0))

class SaveScope(CapsuleScope):
    def __init__(self):
        self.clock_values=[];self.save_order=[];self.clock_calls=0
        super().__init__()
    def block(self,vm,address,size,context):
        if address==0x15d6b80:
            if not self.clock_values:raise ValueError('Unexpected Unity clock read')
            self.clock_calls+=1;bits=struct.unpack('<I',struct.pack('<f',self.clock_values.pop(0)))[0]
            vm.reg_write(reg.UC_ARM64_REG_Q0,bits);vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30));return
        if address==0xfc5870:self.save_order.append(vm.reg_read(reg.UC_ARM64_REG_X0))
        super().block(vm,address,size,context)

def main():
    FUNCTIONS.update(SAVE_FUNCTIONS);scope=SaveScope();vm=scope.vm
    writer_class=HEAP+0x10000;statics=HEAP+0x11000
    slot=struct.unpack('<Q',vm.mem_read(0x39db748,8))[0];scope.put(slot,'Q',writer_class)
    scope.put(writer_class+0xb8,'Q',statics);scope.put(writer_class+0x122,'B',0);scope.put(writer_class+0x168,'QQ',0xfc5870,0)
    list_class=HEAP+0x15000;list_ctx=HEAP+0x16000;enum_class=HEAP+0x18000;enum_ctx=HEAP+0x19000
    for klass,ctx in [(list_class,list_ctx),(enum_class,enum_ctx)]:scope.put(klass+0xc0,'Q',ctx);scope.put(klass+0x121,'BB',3,0)
    for got,info,klass,method in [(0x39fb170,HEAP+0x14000,list_class,0x1585f60),(0x39fb178,HEAP+0x17000,enum_class,0x11dd3e0),
        (0x39fb180,HEAP+0x1c000,enum_class,0x11dd540),(0x39fb188,HEAP+0x1d000,enum_class,0x11dd3b0)]:
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',info);scope.put(info,'Q',method);scope.put(info+0x18,'Q',klass)
    ctor_info=HEAP+0x1a000;verify_info=HEAP+0x1b000
    scope.put(ctor_info,'Q',0x11dd130);scope.put(ctor_info+0x18,'Q',enum_class);scope.put(verify_info,'Q',0x11dd150);scope.put(verify_info+0x18,'Q',enum_class)
    scope.put(list_ctx+0x118,'Q',ctor_info);scope.put(enum_ctx,'Q',verify_info)
    guards=[0x3b86809,0x3b8689a,0x3b87856]
    for address in guards:vm.mem_write(address,b'\1')
    if struct.unpack('<f',vm.mem_read(0x2ca41e4,4))[0]!=60.0:raise ValueError('Native save reset threshold changed')
    fixture=ROOT/'analysis/reconstruction/save-scheduler-reference/save-scheduler-fixtures-v1.jsonl';cases=checks=0
    def check(actual,expected,label):
        nonlocal checks
        checks+=1
        if actual!=expected:raise AssertionError(f'{label} differs at fixture {cases}: {actual} != {expected}')
    for text in fixture.open(encoding='utf-8'):
        row=json.loads(text);writers=[HEAP+0x20000+i*0x100 for i in range(len(row['dirty']))]
        for pointer,dirty in zip(writers,row['dirty']):scope.put(pointer,'Q',writer_class);scope.put(pointer+0x10,'B',dirty)
        sequence=HEAP+0x6000;scope.sequence(sequence,writers,'Q');scope.put(sequence+0x1c,'i',0)
        scope.put(statics,'if',row['initialCount'],row['reset']);scope.put(statics+0x10,'Q',sequence)
        scope.save_order=[];scope.clock_calls=0;scope.clock_values=[row['now'],row['secondNow']]
        for request in row['requests']:scope.invoke('save_request',[writers[request['index']],int(request['force']),0],[])
        scope.invoke('timer_tick',[0,0,0],[],instruction_limit=200000)
        check([bool(vm.mem_read(p+0x10,1)[0]) for p in writers],row['flags'],'dirty flags')
        check(struct.unpack('<i',vm.mem_read(statics,4))[0],row['count'],'request budget')
        check(struct.unpack('<I',vm.mem_read(statics+4,4))[0],row['resetBits'],'clock reset bits')
        check(scope.save_order,[writers[i] for i in row['order']],'forced and timer dispatch order')
        check(scope.clock_calls,row['clockCalls'],'clock read count');cases+=1
    report=dict(status='PASS_COMPILED_SAVE_SCHEDULER_VS_ORIGINAL_ARM64',cases=cases,checks=checks,
        fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),executed_functions=dict(scope.visited),calls=dict(scope.calls),
        supplied_external_clock=dict(rva='0x15D6B80',calls='One or two fixture-supplied Unity unscaledTime reads per timer tick'),
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in SAVE_FUNCTIONS.items()},
        metadata_initialization_guards=[hex(g) for g in guards],text_modified=False,game_function_mocks=0,real_save_files_opened=0,
        scope='Original Save flag/force dispatch, complete OnTimerTick, native reference-list iteration and original base SaveToFile side effects. Virtual writers deliberately bind the original base method, not Roster.SaveToFile. Unity clock is a documented supplied boundary. Strict greater-than-60 reset, four-request budget, list order, force bypass and int32 counter edges tested. Does not execute XML/Nintendo IO, subclass failure behavior, actual Unity clock, startup listener registration or durable saves.')
    destination(ROOT,ROOT/'reports/native-save-scheduler.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
