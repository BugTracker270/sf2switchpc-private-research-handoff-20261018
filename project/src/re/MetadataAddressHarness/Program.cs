using Cpp2IL.Core.Analysis;
using Cpp2IL.Core;
using Cpp2IL.Core.Utils;
using Cpp2IL.Core.ISIL;
using System.Buffers.Binary;
using System.Text.Json;

var results=new List<object>();
LocalVariable Local(string name)=>new(name,new Register(null!,name));
void Check(string name,ulong? actual,ulong? expected) {
    if(actual!=expected)throw new Exception($"{name}: {actual:X} != {expected:X}");
    results.Add(new{name,status="PASS",actual});
}
var p=Local("p");var q=Local("q");
var definitions=new Dictionary<LocalVariable,Instruction>();
ulong? Pointer(ulong address)=>address==0x1000?0x3000ul:null;
ulong? Resolve(MemoryOperand memory)=>MetadataAddressResolver.LoadAddress(memory,definitions,Pointer);
Check("direct slot",Resolve(new(null,null,0x3000)),0x3000);
Check("GOT load is not slot dereference",Resolve(new(null,null,0x1000)),0x1000);
definitions[p]=new(0,OpCode.Move,p,new MemoryOperand(null,null,0x1000));
Check("nested GOT then slot load",Resolve(new(p)),0x3000);
Check("nested address offset",Resolve(new(p,null,0xb8)),0x30b8);
definitions[q]=new(1,OpCode.Move,q,p);
Check("SSA copy chain",Resolve(new(q)),0x3000);
Check("indexed address remains unresolved",Resolve(new(p,q,0,1)),null);
definitions[p]=new(2,OpCode.Move,p,q);
Check("cycle is bounded",Resolve(new(p)),null);
definitions[p]=new(3,OpCode.Move,p,new Immediate(0x4000));
Check("constant address definition",Resolve(new(p,null,4)),0x4004);

var root=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"../../../../../.."));
var binary=File.ReadAllBytes(Path.Combine(root,"analysis/nso/main-uncompressed.nso"));
var dataOffset=BinaryPrimitives.ReadUInt32LittleEndian(binary.AsSpan(0x30));
var dataRva=BinaryPrimitives.ReadUInt32LittleEndian(binary.AsSpan(0x34));
var pointer=BinaryPrimitives.ReadUInt64LittleEndian(binary.AsSpan(checked((int)(dataOffset+0x397ad38-dataRva)),8));
Check("supplied binary GOT pointer to GameUtils metadata",pointer,0x3b37410);
Check("v24.0 64-bit vtable",(ulong)Il2CppClassUsefulOffsets.GetVtableOffset(24f,false),0x128);
Check("v24.2 64-bit vtable",(ulong)Il2CppClassUsefulOffsets.GetVtableOffset(24.2f,false),0x138);
// Offsets observed in native TacticalTableHolder readers; slots independently
// recorded by metadata and the ARM64 BinaryReader implementations.
foreach(var (offset,slot) in new[]{(0x178,5),(0x208,14),(0x218,15),(0x228,16),(0x258,19),(0x268,20),(0x2a8,24),(0x2b8,25),(0x2c8,26)})
    Check($"v24 native virtual offset {offset:X}",(ulong)((offset-Il2CppClassUsefulOffsets.GetVtableOffset(24f,false))/16),(ulong)slot);
uint textOffset=BinaryPrimitives.ReadUInt32LittleEndian(binary.AsSpan(0x10)),textRva=BinaryPrimitives.ReadUInt32LittleEndian(binary.AsSpan(0x14));
byte[] Anchor(ulong rva)=>binary.AsSpan(checked((int)(textOffset+rva-textRva)),100).ToArray();
ulong? Allocation(byte[] code,ulong rva=0x75ace0)=>LegacyArm64AllocationPattern.Match(code,rva,0xb12650,0x65a2a0);
foreach(ulong rva in new ulong[]{0x75ace0,0x74a780,0x5aacf0})Check($"native singleton allocation witness {rva:X}",Allocation(Anchor(rva),rva),0xb5b110);
var valid=Anchor(0x75ace0);
byte[] Mutate(int offset,uint value){var copy=(byte[])valid.Clone();BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(offset,4),value);return copy;}
Check("allocation witness rejects missing class argument",Allocation(Mutate(0x38,0xf9400281)),null);
Check("allocation witness rejects wrong return-value copy",Allocation(Mutate(0x44,0xaa0103f3)),null);
Check("allocation witness rejects wrong static field offset",Allocation(Mutate(0x50,0xf9406108)),null);
Check("allocation witness rejects wrong metadata slot register",Allocation(Mutate(0x4c,0xf9400268)),null);
Check("allocation witness rejects missing constructor call",Allocation(Mutate(0x48,0xd503201f)),null);
Check("allocation witness rejects truncation",Allocation(valid[..32]),null);
Check("allocation witness requires known metadata initializer",LegacyArm64AllocationPattern.Match(valid,0x75ace0,0,0x65a2a0),null);
byte[] Body(ulong rva,int count)=>binary.AsSpan(checked((int)(textOffset+rva-textRva)),count).ToArray();
if(args.Contains("--review-class-guards")) {
    foreach(var (rva,count) in new[]{(0x2222a0ul,564),(0x4a83a0ul,380),(0x4a8520ul,540)})
        foreach(var site in LegacyArm64AllocationPattern.ClassInitSites(Body(rva,count),rva)) {
            Console.WriteLine(JsonSerializer.Serialize(new{method=$"0x{rva:X}",start=$"0x{site.Start:X}",skip=$"0x{site.Skip:X}",target=$"0x{site.Target:X}"}));
            foreach(var instruction in Disarm.Disassembler.Disassemble(Body(site.Start-16,44),site.Start-16))Console.WriteLine(instruction);
        }
    return;
}
Check("native Object constructor is an immediate return",LegacyArm64AllocationPattern.IsImmediateReturn(Body(0x65a2a0,4))?1ul:0ul,1);
Check("empty constructor witness rejects missing return",LegacyArm64AllocationPattern.IsImmediateReturn(Body(0x65a2a0,3))?1ul:0ul,0);
Check("empty constructor witness rejects a side effect",LegacyArm64AllocationPattern.IsImmediateReturn(new byte[]{0x00,0x00,0x00,0xf9})?1ul:0ul,0);
Check("empty constructor witness rejects non-link return register",LegacyArm64AllocationPattern.IsImmediateReturn(new byte[]{0x00,0x00,0x5f,0xd6})?1ul:0ul,0);
foreach(ulong rva in new ulong[]{0xbd1480,0xbc91d0,0xbca200}) {
    var member=LegacyArm64DefaultMemberPattern.Match(Body(rva,56),rva,0x58f9a0);
    Check($"native DefaultMember string wrapper {rva:X}",member?.Utf8Wrapper,0xb680c0);
    Check($"native DefaultMember literal {rva:X}",member?.CString,0x2cc9909);
}
var memberBody=Body(0xbd1480,56);
for(int i=0;i<14;i++) {
    var copy=(byte[])memberBody.Clone();BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(i*4,4),0xd503201f);
    Check($"DefaultMember rejects changed required instruction {i}",LegacyArm64DefaultMemberPattern.Match(copy,0xbd1480,0x58f9a0)?.CString,null);
}
Check("DefaultMember rejects truncated generator",LegacyArm64DefaultMemberPattern.Match(memberBody[..55],0xbd1480,0x58f9a0)?.CString,null);
Check("DefaultMember rejects different constructor",LegacyArm64DefaultMemberPattern.Match(memberBody,0xbd1480,0x58f9a4)?.CString,null);
var stringWrapper=Body(0xb680c0,40);
Check("native string wrapper preserves input and forwards strlen result",LegacyArm64DefaultMemberPattern.IsStringWrapper(stringWrapper,0xb680c0)?1ul:0ul,1);
for(int i=0;i<10;i++) {
    var copy=(byte[])stringWrapper.Clone();BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(i*4,4),0xd503201f);
    Check($"string wrapper rejects changed required instruction {i}",LegacyArm64DefaultMemberPattern.IsStringWrapper(copy,0xb680c0)?1ul:0ul,0);
}
Check("string wrapper rejects truncation",LegacyArm64DefaultMemberPattern.IsStringWrapper(stringWrapper[..39],0xb680c0)?1ul:0ul,0);
ulong? ClassInitializer(byte[] code,ulong rva){var targets=LegacyArm64AllocationPattern.ClassInitTargets(code,rva).Distinct().ToArray();return targets.Length==1?targets[0]:null;}
foreach(var (rva,count) in new[]{(0xe1f610ul,104),(0xd38960ul,104),(0xfebd80ul,348)})
    Check($"native class-init macro witness {rva:X}",ClassInitializer(Body(rva,count),rva),0xb2e720);
var getter=Body(0xe1f610,104);int guard=Enumerable.Range(0,getter.Length/4).Select(i=>i*4).First(i=>BinaryPrimitives.ReadUInt32LittleEndian(getter.AsSpan(i,4))==0x39448808);
byte[] GuardMutation(int relative,uint word){var copy=(byte[])getter.Clone();BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(guard+relative,4),word);return copy;}
uint GuardWord(int relative)=>BinaryPrimitives.ReadUInt32LittleEndian(getter.AsSpan(guard+relative,4));
Check("class-init witness rejects wrong flag offset",ClassInitializer(GuardMutation(0,GuardWord(0)+(1u<<10)),0xe1f610),null);
Check("class-init witness rejects wrong finished offset",ClassInitializer(GuardMutation(8,GuardWord(8)+(1u<<10)),0xe1f610),null);
Check("class-init witness rejects wrong condition register",ClassInitializer(GuardMutation(12,(GuardWord(12)&~31u)|9),0xe1f610),null);
Check("class-init witness requires shared merge",ClassInitializer(GuardMutation(4,GuardWord(4)+(1u<<5)),0xe1f610),null);
Check("class-init witness rejects non-call branch",ClassInitializer(GuardMutation(16,GuardWord(16)&~0x80000000u),0xe1f610),null);
Check("class-init witness requires class in X0",ClassInitializer(GuardMutation(-4,GuardWord(-4)|1),0xe1f610),null);
Check("class-init witness rejects truncated macro",ClassInitializer(getter[..(guard+16)],0xe1f610),null);
var classSite=LegacyArm64AllocationPattern.ClassInitSites(getter,0xe1f610).Single();
Check("class-init outer flag branch address",classSite.Branch,0xe1f610ul+(ulong)guard+4);
Check("class-init exact skip address",classSite.Skip,0xe1f664);
Check("class-init rewrite excludes native flag load",classSite.Start,0xe1f610ul+(ulong)guard);
foreach(var (rva,count,expected) in new[]{(0x2222a0ul,564,6ul),(0x4a83a0ul,380,2ul),(0x4a8520ul,540,4ul)})
    Check($"scheduled/body class-init witnesses {rva:X}",(ulong)LegacyArm64AllocationPattern.ClassInitSites(Body(rva,count),rva).Count,expected);
foreach(var (rva,count,starts) in new[]{
    (0x2222a0ul,564,new ulong[]{0x2222fc,0x222390,0x2223c0,0x222404,0x222444,0x222498}),
    (0x4a83a0ul,380,new ulong[]{0x4a83ec,0x4a84d8}),
    (0x4a8520ul,540,new ulong[]{0x4a8570,0x4a85fc,0x4a8620,0x4a864c})}) {
    var sites=LegacyArm64AllocationPattern.ClassInitSites(Body(rva,count),rva);
    for(int i=0;i<starts.Length;i++)Check($"reviewed native macro {rva:X}/{i}",sites[i].Start,starts[i]);
}
var scheduledClass=Body(0x4a8520,540);
byte[] ScheduledMutation(int offset,uint word){var copy=(byte[])scheduledClass.Clone();BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(offset,4),word);return copy;}
Check("scheduled class-init requires unchanged X0",(ulong)LegacyArm64AllocationPattern.ClassInitSites(ScheduledMutation(0x4c,0xaa0103e0),0x4a8520).Count,3);
Check("class-init trailing reload must match class slot",(ulong)LegacyArm64AllocationPattern.ClassInitSites(ScheduledMutation(0x64,0xf94002a0),0x4a8520).Count,3);
Check("class-init trailing side effect is preserved by rejection",(ulong)LegacyArm64AllocationPattern.ClassInitSites(ScheduledMutation(0x64,0xf90002a0),0x4a8520).Count,3);
var fpScheduledClass=Body(0xa6a1f0,172);
var fpClassSites=LegacyArm64AllocationPattern.ClassInitSites(fpScheduledClass,0xa6a1f0);
Check("native scalar-FP scheduled class guard count",(ulong)fpClassSites.Count,1);
Check("native scalar-FP load remains before rewritten class guard",fpClassSites.Single().Start,0xa6a244);
Check("native scalar-FP scheduled class initializer",fpClassSites.Single().Target,0xb2e720);
byte[] FpScheduledMutation(uint word){var copy=(byte[])fpScheduledClass.Clone();BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(0x50,4),word);return copy;}
Check("FP scheduled class guard rejects a GPR W0 clobber",(ulong)LegacyArm64AllocationPattern.ClassInitSites(FpScheduledMutation(0xb9400260),0xa6a1f0).Count,0);
Check("FP scheduled class guard rejects FP writeback",(ulong)LegacyArm64AllocationPattern.ClassInitSites(FpScheduledMutation(0xbc400e6a),0xa6a1f0).Count,0);
ulong? InitFlag(byte[] code,ulong start,ulong initializer=0xb12650,ulong writableStart=0x3674000,ulong writableEnd=0x3c60000) {
    var matches=LegacyArm64InitializationPattern.Match(code,start,initializer,writableStart,writableEnd);
    return matches.Count==1?matches[0].Flag:null;
}
foreach(var (rva,count,flag) in new[]{(0x1017400ul,128,0x3b86a3cul),(0xffbae0ul,128,0x3b86915ul),(0xd3fe80ul,128,0x3b84dd9ul)})
    Check($"native method metadata guard {rva:X}",InitFlag(Body(rva,count),rva),flag);
Check("metadata guard conservatively leaves unsupported interleaved FP prefix",InitFlag(Body(0xfebd80,128),0xfebd80),null);
var legacyGuard=Body(0x1017400,128);
byte[] InitMutation(int offset,uint word){var copy=(byte[])legacyGuard.Clone();BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(offset,4),word);return copy;}
uint InitWord(int offset)=>BinaryPrimitives.ReadUInt32LittleEndian(legacyGuard.AsSpan(offset,4));
Check("metadata guard rejects bit-one test",InitFlag(InitMutation(0x1c,InitWord(0x1c)|(1u<<19)),0x1017400),null);
Check("metadata guard rejects changed skip",InitFlag(InitMutation(0x1c,InitWord(0x1c)+(1u<<5)),0x1017400),null);
Check("metadata guard rejects unknown call",InitFlag(InitMutation(0x2c,0x94000000),0x1017400),null);
Check("metadata guard rejects different flag store",InitFlag(InitMutation(0x34,InitWord(0x34)+(1u<<10)),0x1017400),null);
Check("metadata guard requires storing one",InitFlag(InitMutation(0x30,0x2a1f03e8),0x1017400),null);
Check("metadata guard requires metadata page load",InitFlag(InitMutation(0x20,0x10000008),0x1017400),null);
Check("metadata guard rejects changed slot destination",InitFlag(InitMutation(0x24,InitWord(0x24)|1),0x1017400),null);
Check("metadata guard requires handle in W0",InitFlag(InitMutation(0x28,InitWord(0x28)|1),0x1017400),null);
Check("metadata guard rejects instance flag load",InitFlag(InitMutation(0x14,InitWord(0x14)&~(31u<<5)),0x1017400),null);
Check("metadata guard rejects flag register clobber",InitFlag(InitMutation(0x18,0x2a0003e8),0x1017400),null);
Check("metadata guard requires global flag page",InitFlag(InitMutation(0x10,0xd503201f),0x1017400),null);
Check("metadata guard requires known initializer",InitFlag(legacyGuard,0x1017400,0),null);
Check("metadata guard requires writable flag",InitFlag(legacyGuard,0x1017400,0xb12650,0x1000,0x2000),null);
Check("metadata guard rejects truncated macro",InitFlag(legacyGuard[..0x38],0x1017400),null);
Check("metadata guard never scans past entry return",InitFlag(InitMutation(0,0xd65f03c0),0x1017400),null);
Check("metadata guard never scans past entry thunk",InitFlag(InitMutation(0,0x14000001),0x1017400),null);
var factoryBody=Body(0xb4d8f0,64);
ulong? Factory(byte[] bytes,ulong allocator=0xb5b110)=>LegacyArm64ExceptionFactoryPattern.Match(bytes,0xb4d8f0,allocator)?.Name;
Check("native no-argument exception factory name",Factory(factoryBody),0x2cc372c);
Check("native factory namespace",LegacyArm64ExceptionFactoryPattern.Match(factoryBody,0xb4d8f0,0xb5b110)?.Namespace,0x2cbf925);
Check("native factory initialization call",LegacyArm64ExceptionFactoryPattern.Match(factoryBody,0xb4d8f0,0xb5b110)?.Initialization,0xb2e3c0);
for(int i=0;i<16;i++) {
    var copy=(byte[])factoryBody.Clone();BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(i*4,4),0xd503201f);
    Check($"factory rejects changed required instruction {i}",Factory(copy),null);
}
Check("factory rejects unknown allocator",Factory(factoryBody,0),null);
Check("factory rejects wrong allocator",Factory(factoryBody,0xb5b490),null);
Check("factory rejects truncated return",Factory(factoryBody[..60]),null);
Check("conditional array error does not make a factory",Factory(Body(0xb5fe50,340)),null);
var arrayBody=Body(0xb5fe50,340);
ulong? ArrayAllocation(byte[] bytes,ulong raise=0xb4c880)=>LegacyArm64ArrayAllocationPattern.Match(bytes,0xb5fe50,raise)?.ElementSize;
Check("native array size/header/return witness",ArrayAllocation(arrayBody),0xb409e0);
Check("array witness atomic allocation",LegacyArm64ArrayAllocationPattern.Match(arrayBody,0xb5fe50,0xb4c880)?.AtomicAllocation,0xb5afc0);
Check("array witness descriptor allocation",LegacyArm64ArrayAllocationPattern.Match(arrayBody,0xb5fe50,0xb4c880)?.TypedAllocation,0xb5b020);
Check("array witness general allocation",LegacyArm64ArrayAllocationPattern.Match(arrayBody,0xb5fe50,0xb4c880)?.GeneralAllocation,0xb5af60);
Check("array witness clear import",LegacyArm64ArrayAllocationPattern.Match(arrayBody,0xb5fe50,0xb4c880)?.ClearMemory,0x23730a8);
byte[] ArrayMutation(int offset,uint word){var copy=(byte[])arrayBody.Clone();BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(offset,4),word);return copy;}
foreach(var offset in new[]{0x10,0x14,0x18,0x1c,0x24,0x2c,0x30,0x38,0x3c,0x54,0x60,0x64,0x68,0x6c,0x70,0x78,0x84,0x88,0x8c,0x90,0x94,0x98,0xac,0xb8,0xc0,0xe4,0xf0})
    Check($"array witness rejects changed required instruction {offset:X}",ArrayAllocation(ArrayMutation(offset,0xd503201f)),null);
Check("array witness requires independently identified raiser",ArrayAllocation(arrayBody,0),null);
Check("array witness rejects truncated normal path",ArrayAllocation(arrayBody[..240]),null);
Check("exception routine is not an array allocator",ArrayAllocation(Body(0xb4c880,252)),null);
var raiseBody=Body(0xb4c880,252);
ulong? RaiseTarget(byte[] bytes)=>LegacyArm64ExceptionRaiserPattern.Match(bytes,0xb4c880)?.NativeThrow;
Check("native exception raiser wraps and throws preserved pointer",RaiseTarget(raiseBody),0x2373088);
Check("native exception wrapper allocation",LegacyArm64ExceptionRaiserPattern.Match(raiseBody,0xb4c880)?.AllocateException,0x2373078);
Check("native exception raiser exact extent",(ulong?)LegacyArm64ExceptionRaiserPattern.Match(raiseBody,0xb4c880)?.BodyBytes,252);
byte[] RaiseMutation(int offset,uint word){var copy=(byte[])raiseBody.Clone();BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(offset,4),word);return copy;}
uint RaiseWord(int offset)=>BinaryPrimitives.ReadUInt32LittleEndian(raiseBody.AsSpan(offset,4));
Check("raiser rejects non-exception input copy",RaiseTarget(RaiseMutation(0x14,RaiseWord(0x14)|(1u<<16))),null);
Check("raiser requires preserved callee-saved exception",RaiseTarget(RaiseMutation(0x14,(RaiseWord(0x14)&~31u)|18)),null);
Check("raiser requires trace_ips field offset",RaiseTarget(RaiseMutation(0x18,RaiseWord(0x18)+(1u<<10))),null);
Check("raiser requires correct trace condition",RaiseTarget(RaiseMutation(0x20,RaiseWord(0x20)^0x1000000)),null);
Check("raiser requires shared trace register",RaiseTarget(RaiseMutation(0x20,RaiseWord(0x20)^1)),null);
Check("raiser requires exact tail destination",RaiseTarget(RaiseMutation(0x20,RaiseWord(0x20)+(1u<<5))),null);
Check("raiser requires eight-byte C++ wrapper",RaiseTarget(RaiseMutation(0xdc,0x52800200)),null);
Check("raiser requires an allocation call",RaiseTarget(RaiseMutation(0xe0,0xd503201f)),null);
Check("raiser requires preserved pointer in payload",RaiseTarget(RaiseMutation(0xe4,RaiseWord(0xe4)+1)),null);
Check("raiser requires RTTI in X1",RaiseTarget(RaiseMutation(0xe8,RaiseWord(0xe8)+1)),null);
Check("raiser requires matching RTTI load base",RaiseTarget(RaiseMutation(0xec,RaiseWord(0xec)+(1u<<5))),null);
Check("raiser requires null C++ destructor",RaiseTarget(RaiseMutation(0xf0,0xaa0103e2)),null);
Check("raiser requires native throw call",RaiseTarget(RaiseMutation(0xf4,0xd503201f)),null);
Check("raiser allocation and throw must differ",RaiseTarget(RaiseMutation(0xf4,RaiseWord(0xf4)-4)),null);
Check("raiser requires terminal trap",RaiseTarget(RaiseMutation(0xf8,0xd503201f)),null);
Check("raiser rejects truncated terminal",RaiseTarget(raiseBody[..0xf8]),null);
Check("raiser never scans through entry thunk",RaiseTarget(RaiseMutation(0,0x14000001)),null);
Check("raiser never scans through entry return",RaiseTarget(RaiseMutation(0,0xd65f03c0)),null);
Check("boxing helper is not an exception raiser",RaiseTarget(Body(0xb5b070,256)),null);
uint B(ulong source,ulong target,bool link=false)=>(link?0x94000000u:0x14000000u)|((uint)((long)target-(long)source)/4&0x3ffffff);
byte[] ThunkWords(params uint[] words){var bytes=new byte[words.Length*4];for(int i=0;i<words.Length;i++)BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(i*4),words[i]);return bytes;}
var thunkWords=ThunkWords(0xd65f03c0,0xaa1f03e1,B(0x1008,0x2000),0xd65f03c0,B(0x1010,0x1004,true));
ulong[] Thunks(byte[] bytes,uint back=4,bool preserve=true,params ulong[] ignored)=>LegacyArm64ThunkScanner.Find(bytes,0x1000,0x2000,back,ignored.ToHashSet(),preserve).ToArray();
Check("streaming thunk scanner preserves auxiliary-clear wrapper",(ulong)Thunks(thunkWords).Single(),0x1004);
Check("streaming thunk scanner respects back bound",(ulong)Thunks(thunkWords,0).Length,0);
Check("streaming thunk scanner respects ignored start",(ulong)Thunks(thunkWords,4,true,0x1004).Length,0);
Check("streaming thunk scanner does not treat BL as tail B",(ulong)Thunks(ThunkWords(0xd65f03c0,0xaa1f03e1,B(0x1008,0x2000,true))).Length,0);
Check("raiser thunk must preserve incoming X0",(ulong)Thunks(ThunkWords(0xd65f03c0,0x91004000,B(0x1008,0x2000))).Length,0);
Check("generic thunk scanner can retain setup instruction",(ulong)Thunks(ThunkWords(0xd65f03c0,0x91004000,B(0x1008,0x2000)),4,false).Single(),0x1004);
Check("streaming thunk scanner rejects wrong branch target",(ulong)Thunks(ThunkWords(0xd65f03c0,0xaa1f03e1,B(0x1008,0x2004))).Length,0);
Check("streaming thunk scanner accepts direct tail entry",(ulong)Thunks(ThunkWords(B(0x1000,0x2000))).Single(),0x1000);
if(args.Length==1 && args[0]=="--scan-raiser-thunks") {
    int textSize=(int)BinaryPrimitives.ReadUInt32LittleEndian(binary.AsSpan(0x18));
    var thunks=LegacyArm64ThunkScanner.Find(binary.AsSpan((int)textOffset,textSize),textRva,0xb4c880,4,new HashSet<ulong>{0},true);
    string output=Path.Combine(root,"analysis/il2cpp/native-raiser-thunks-v1.json");
    if(File.Exists(output))throw new IOException("Preserve prior native thunk scan");
    File.WriteAllText(output,JsonSerializer.Serialize(new{status="STRICT_NATIVE_RAISER_THUNK_CANDIDATES",raiser=0xb4c880,thunks,
        scope="Fixed-width B/BL scan, known call/terminator start, at most four bytes of setup, incoming X0 preserved. Candidate aliases need native boundary execution; not a whole-runtime or exception-unwind proof."},new JsonSerializerOptions{WriteIndented=true}));
}
if(args.Length==1 && args[0]=="--scan-init-guards") {
    using var document=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root,"analysis/il2cpp/effective-main/script.json")));
    var textEnd=(ulong)textRva+BinaryPrimitives.ReadUInt32LittleEndian(binary.AsSpan(0x18));
    var addresses=document.RootElement.GetProperty("ScriptMethod").EnumerateArray().Select(m=>m.GetProperty("Address").GetUInt64())
        .Where(a=>a>=textRva&&a<textEnd).Distinct().Order().ToArray();
    var dataStart=BinaryPrimitives.ReadUInt32LittleEndian(binary.AsSpan(0x34));
    var dataEnd=(ulong)dataStart+BinaryPrimitives.ReadUInt32LittleEndian(binary.AsSpan(0x38))+BinaryPrimitives.ReadUInt32LittleEndian(binary.AsSpan(0x3c));
    var found=new List<object>();int guardsFound=0;
    for(int i=0;i<addresses.Length;i++) {
        var rva=addresses[i];var end=i+1<addresses.Length?addresses[i+1]:textEnd;
        int length=(int)Math.Min(512ul,end-rva);length-=length%4;
        var matches=LegacyArm64InitializationPattern.Match(Body(rva,length),rva,0xb12650,dataStart,dataEnd);
        if(matches.Count==0)continue;
        found.Add(new {rva,guards=matches});guardsFound+=matches.Count;
    }
    string output=Path.Combine(root,"analysis/il2cpp/native-init-guard-coverage-v1.json");
    if(File.Exists(output))throw new IOException("Preserve prior native guard coverage");
    File.WriteAllText(output,JsonSerializer.Serialize(new {status="STRICT_NATIVE_ENTRY_GUARD_COVERAGE",methods_scanned=addresses.Length,methods_matched=found.Count,guards=guardsFound,
        initializerRva="0xB12650",methods=found,scope="Bounded first 512 bytes, stops at unconditional transfer, requires writable identical byte and exact known metadata-init macro. Pattern coverage does not certify complete method recovery."},new JsonSerializerOptions{WriteIndented=true}));
}
int allocationEmissionChecks=AllocationEmissionChecks.Run();
Console.WriteLine(JsonSerializer.Serialize(new{passed=results.Count+allocationEmissionChecks,failed=0,allocation_emission_checks=allocationEmissionChecks,checks=results,scope="Address/dereference, virtual-slot, bounded allocation/class-init/method-metadata/exception-wrapper patterns, streaming thunks, and execution of emitted separate reference allocation; no whole-method correctness claim"},new JsonSerializerOptions{WriteIndented=true}));
