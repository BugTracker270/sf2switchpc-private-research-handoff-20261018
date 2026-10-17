"""Test original save-hash gate functions without filesystem or real saves."""
import hashlib
import json
import struct
from execute_native_ai_leaves import NativeScope,FUNCTIONS,ROOT,HEAP
from usb_boundary import destination

def main():
    FUNCTIONS.update(hash_init=(0xe1b1c0,0xe1b228),hash_enabled=(0xe1f610,0xe1f678),
        check_hash=(0xc8aad0,0xc8ae28),hash_update_file=(0xc8aef0,0xc8b048),
        hash_update_document=(0xc8b0d0,0xc8b244),hash_delete=(0xc8b250,0xc8b364),hash_copy=(0xc8b370,0xc8b4f0))
    scope=NativeScope();vm=scope.vm;checks=[]
    # The file-backed GOT stores the runtime metadata slot's RVA. Only the
    # sandbox's data is initialized; original instruction bytes stay read-only.
    slot=struct.unpack('<Q',vm.mem_read(0x39d6070,8))[0]
    fake_class=HEAP+0x1a0000;fake_statics=HEAP+0x1a1000
    scope.put(slot,'Q',fake_class);scope.put(fake_class+0xb8,'Q',fake_statics)
    scope.put(fake_class+0x122,'B',0)
    guards=[0x3b85640,0x3b85645,0x3b84742,0x3b84853,0x3b84854,0x3b84744,0x3b84745]
    for address in guards:vm.mem_write(address,b'\1')
    def check(name,actual,want):
        if actual!=want:raise AssertionError(f'{name}: {actual} != {want}')
        checks.append(dict(name=name,actual=actual,expected=want,status='PASS'))
    for initial in (0,1):
        scope.put(fake_statics+9,'B',initial)
        check('Getter reflects initialized static field',scope.call('hash_enabled',0),initial)
        scope.call('hash_init',0)
        check('InitHashChecking clears the field',vm.mem_read(fake_statics+9,1).hex(),'00')
        check('Getter returns false after init',scope.call('hash_enabled',0),0)
        # XML/path arguments are intentionally null: this must return before
        # dereferencing either argument or invoking any hash/filesystem code.
        check('Disabled checking returns true with null inputs',scope.call('check_hash',0),1)
        for name in ['hash_update_file','hash_update_document','hash_delete','hash_copy']:
            # Returning through original instructions with null inputs proves
            # this branch avoids string/XML/hash/filesystem callees. Any such
            # call is rejected by the native execution range allowlist.
            scope.call(name,0)
            check(name+' returns without IO or flag mutation',vm.mem_read(fake_statics+9,1).hex(),'00')
    report=dict(status='PASS_BOUNDED_ORIGINAL_ARM64_GATE_EXECUTION',checks=checks,passed=len(checks),failed=0,
        metadata_slot_rva=hex(slot),static_field_offset=9,guards=[hex(a) for a in guards],
        calls=dict(scope.calls),executed_functions=dict(scope.visited),
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n.startswith('hash') or n=='check_hash'},
        game_function_mocks=0,text_modified=False,real_save_files_opened=0,
        scope='Valid synthetic metadata class/static storage, initialization guards pre-set. Original disabled CheckFileHash and UpdateFileHash(file/document)/DeleteFileHash/CopyFileHash paths return with null inputs and no string/XML/hash/IO callees. Enabled hashing and complete bootstrap ordering remain separate analyses.')
    destination(ROOT,ROOT/'reports/native-save-gate-execution.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
