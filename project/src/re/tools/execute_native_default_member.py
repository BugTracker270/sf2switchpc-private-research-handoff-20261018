"""Observe an original attribute-cache generator and UTF-8 conversion at explicit allocation/libc boundaries."""
import collections
import hashlib
import json
import struct
from execute_native_capsules import CapsuleScope
from execute_native_ai_leaves import FUNCTIONS,ROOT,HEAP,STOP
from native_unwind_inventory import Image
from usb_boundary import destination
from unicorn import arm64_const as reg

class AttributeScope(CapsuleScope):
    def __init__(self,strlen):
        self.strlen=strlen;self.boundaries=collections.Counter();self.string=HEAP+0x4000;self.length=None
        super().__init__()
    def block(self,vm,address,size,context):
        if address==self.strlen:
            pointer=vm.reg_read(reg.UC_ARM64_REG_X0);length=0
            while length<256 and vm.mem_read(pointer+length,1)!=b'\0':length+=1
            if length==256:raise ValueError('Unbounded literal strlen')
            self.boundaries['supplied_libc_strlen']+=1;vm.reg_write(reg.UC_ARM64_REG_X0,length)
            vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30));return
        if address==0xb68170:
            length=vm.reg_read(reg.UC_ARM64_REG_X0)
            if length>64:raise ValueError('Unexpected managed string allocation length')
            self.length=length;self.boundaries['supplied_managed_string_allocation']+=1
            vm.mem_write(self.string,b'\0'*(24+2*length));self.put(self.string,'Q',HEAP+0x50000);self.put(self.string+0x10,'I',length)
            vm.reg_write(reg.UC_ARM64_REG_X0,self.string);vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30));return
        if address==0x23730b8:
            target=vm.reg_read(reg.UC_ARM64_REG_X0);source=vm.reg_read(reg.UC_ARM64_REG_X1);length=vm.reg_read(reg.UC_ARM64_REG_X2)
            if length>128:raise ValueError('Unexpected bounded memcpy length')
            self.boundaries['supplied_libc_memcpy']+=1;vm.mem_write(target,bytes(vm.mem_read(source,length)))
            vm.reg_write(reg.UC_ARM64_REG_PC,vm.reg_read(reg.UC_ARM64_REG_X30));return
        super().block(vm,address,size,context)

def main():
    image=Image((ROOT/'analysis/nso/main-uncompressed.nso').read_bytes())
    frames={row['rva']:row['end_rva'] for row in map(json.loads,(ROOT/'analysis/nso/unwind-inventory-v1/frames.jsonl').open(encoding='utf-8'))}
    metadata=json.loads((ROOT/'analysis/il2cpp/effective-main/script.json').read_text(encoding='utf-8-sig'))
    base=next(row['Address'] for row in metadata['ScriptMethod'] if row['Name']=='System.Attribute$$.ctor')
    entries={'generator_list_wrapper':0xbd1480,'utf8_string_wrapper':0xb680c0,'utf8_string_length':0xb67ff0,
        'utf8_conversion':0xb666f0,'utf8_codepoint_decoder':0xb66c30,'utf16_writer':0xb667b0,'short_utf16_reserve':0xb4e0d0,
        'string_character_buffer':0xb66b40,'default_member_ctor':0x58f9a0,'attribute_base_ctor':base,'object_base_ctor':0x65a2a0}
    FUNCTIONS.clear();FUNCTIONS.update({name:(start,frames[start]) for name,start in entries.items()})
    calls=[]
    for offset in range(0,frames[0xb680c0]-0xb680c0,4):
        word=struct.unpack('<I',image.read(0xb680c0+offset,4))[0]
        if word&0xfc000000==0x94000000:
            immediate=word&0x3ffffff
            if immediate&(1<<25):immediate-=1<<26
            calls.append(0xb680c0+offset+immediate*4)
    if len(calls)!=1 or not 0x2373008<=calls[0]<0x2375908:raise ValueError('Expected sole original strlen import call')
    scope=AttributeScope(calls[0]);vm=scope.vm;cache=HEAP+0x1000;array=HEAP+0x2000;attribute=HEAP+0x3000
    scope.put(cache+8,'Q',array);scope.put(array,'Q',attribute);vm.mem_write(attribute,b'\0'*32)
    scope.invoke('generator_list_wrapper',[cache],[],instruction_limit=20000)
    pointer=struct.unpack('<Q',vm.mem_read(attribute+0x10,8))[0]
    if pointer!=scope.string or scope.length!=4:raise ValueError('Original attribute string identity/length differs')
    text=bytes(vm.mem_read(pointer+0x14,scope.length*2)).decode('utf-16-le')
    if text!='Item':raise ValueError('Original native DefaultMember argument differs')
    report=dict(status='PASS_ORIGINAL_DEFAULT_MEMBER_ARGUMENT_AT_RUNTIME_BOUNDARIES',cases=1,checks=3,
        generator='0xBD1480',owner='Newtonsoft.Json.Utilities.ListWrapper<T>',recovered_member_name=text,
        executed_functions=dict(scope.visited),runtime_boundaries=dict(scope.boundaries),
        original_text_sha256={name:hashlib.sha256(image.read(a,b-a)).hexdigest() for name,(a,b) in FUNCTIONS.items()},text_modified=False,
        scope='Original cache generator, UTF-8 conversion, string copy/buffer code and attribute/base constructors. Managed string allocation and libc strlen/memcpy are explicit supplied boundaries. Preallocated attribute cache/object are synthetic. Does not certify all attribute generators, long/unicode strings, GC or complete source recovery.')
    destination(ROOT,ROOT/'reports/native-default-member-argument.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
