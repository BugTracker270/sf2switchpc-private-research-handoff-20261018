"""Compare a documented internal damage arithmetic slice, not the whole routine."""
import hashlib
import json
import struct
from execute_native_ai_leaves import NativeScope,FUNCTIONS,ROOT,HEAP,STACK
from usb_boundary import destination
from unicorn import arm64_const as reg

def main():
    # Last instruction of the internal slice is FMUL S8 at 0xFFBEB8.
    FUNCTIONS.update(damage_combination=(0xffbe40,0xffbebc),max_float=(0x121da00,0x121da0c),
        weapon_modifier=(0xea45f0,0xea4704),interval_factors=(0x101cd40,0x101cd58),
        string_equal_operator=(0x3dd5e0,0x3dd658),string_equal=(0x3f5250,0x3f53a4))
    scope=NativeScope();vm=scope.vm
    guard=0x3b85c28;vm.mem_write(guard,b'\1');vm.mem_write(0x3a34cb3,b'\1')
    klass=HEAP+0x10000
    slot=struct.unpack('<Q',vm.mem_read(0x3979a28,8))[0];scope.put(slot,'Q',klass);scope.put(klass+0x122,'B',0)
    fists=HEAP+0x11000;other=HEAP+0x12000
    for address,text in [(fists,'Fists'),(other,'Blade')]:
        scope.put(address+0x10,'i',len(text));vm.mem_write(address+0x14,text.encode('utf-16-le')+b'\0\0')
    slot=struct.unpack('<Q',vm.mem_read(0x39dcb18,8))[0];scope.put(slot,'Q',fists)
    for got in [0x397cf90,0x397cf98]:
        slot=struct.unpack('<Q',vm.mem_read(got,8))[0];scope.put(slot,'Q',HEAP+0x14000)
    attacker=HEAP;parameters=HEAP+0x2000;interval=HEAP+0x4000;weapons=HEAP+0x6000
    pf=HEAP+0x8000;ef=HEAP+0x9000
    scope.put(attacker+0x140,'Q',parameters);scope.put(interval+0x40,'QQ',pf,ef)
    fixture=ROOT/'analysis/reconstruction/damage-reference/damage-fixtures-v1.jsonl';cases=clamped=fists_cases=0
    for text in fixture.open(encoding='utf-8'):
        row=json.loads(text);vm.reg_write(reg.UC_ARM64_REG_SP,STACK+0x80000)
        for number,value in [(0,row['intervalDamage']),(8,row['power']),(9,row['block']),(10,row['critical']),(11,row['attributeMultiplier'])]:
            vm.reg_write(getattr(reg,'UC_ARM64_REG_Q'+str(number)),struct.unpack('<I',struct.pack('<f',value))[0])
        vm.reg_write(reg.UC_ARM64_REG_X21,attacker);vm.reg_write(reg.UC_ARM64_REG_X19,interval);vm.reg_write(reg.UC_ARM64_REG_X20,1)
        scope.put(attacker+0x2ac,'f',row['additionalDamage']);scope.put(attacker+0x244,'f',row['resistance']);scope.put(attacker+0x268,'f',row['converter'])
        scope.put(parameters+0x10c,'f',row['damageMod']);scope.put(parameters+0x13c,'f',row['fistsMod']);scope.put(parameters+0x61,'B',row['isPlayer'])
        scope.put(pf+0x14,'f',row['playerFactor']);scope.put(ef+0x14,'f',row['enemyFactor'])
        values={0:[],1:[],2:[other],3:[fists],4:[other,fists]}[row['weapons']]
        scope.sequence(weapons,values,'Q');scope.put(STACK+0x80020,'Q',weapons if row['weapons'] else 0)
        scope.last_blocks=[];vm.emu_start(0xffbe40,0xffbebc,count=20000)
        if vm.reg_read(reg.UC_ARM64_REG_PC)!=0xffbebc:raise ValueError('Internal slice did not reach exact end')
        actual=vm.reg_read(reg.UC_ARM64_REG_Q8)&0xffffffff
        if actual!=row['resultBits']:raise AssertionError(f'Damage arithmetic differs at {cases}: {actual:#x} != {row["resultBits"]:#x}')
        cases+=1;clamped+=actual&0x7fffffff==0;fists_cases+=row['weapons']>=3
    report=dict(status='PASS_COMPILED_DAMAGE_SLICE_VS_ORIGINAL_ARM64',cases=cases,checks=cases,zero_results=clamped,fists_cases=fists_cases,
        fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),executed_functions=dict(scope.visited),
        original_text_sha256={n:hashlib.sha256(vm.mem_read(a,b-a)).hexdigest() for n,(a,b) in FUNCTIONS.items() if n in ['damage_combination','weapon_modifier','interval_factors','max_float','string_equal_operator','string_equal']},
        game_function_mocks=0,text_modified=False,metadata_initialization_guards=[hex(guard),'0x3A34CB3'],
        scope='Internal GetTotalDamage slice 0xFFBE40..0xFFBEBC with register inputs for earlier calculations. Original Max, weapon modifier, string equality, list helpers and interval-factor selection executed. This does not validate upstream attribute differences, exponentiation, raid-charge exception, hit eligibility or whole combat.')
    destination(ROOT,ROOT/'reports/native-damage-combination.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
