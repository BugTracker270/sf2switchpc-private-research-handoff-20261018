using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using IsilOp = Cpp2IL.Core.ISIL.OpCode;

if(args.Length is <1 or >2||args.Length==2&&args[1] is not ("--v32-regression" or "--v34-regression" or "--v35-regression" or "--v36-regression" or "--v37-regression"))throw new ArgumentException("Verified USB root and optional --v32-regression/--v34-regression/--v35-regression/--v36-regression/--v37-regression required");
string reportLabel=args.Length==2?args[1][2..].Replace("-regression",""):"v31";
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative) {
    string path=Path.GetFullPath(Path.Combine(root,relative));
    if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside USB workspace");
    for(DirectoryInfo? dir=new(Path.GetDirectoryName(path)!);dir!=null;dir=dir.Parent)
        if(dir.Exists&&(dir.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");
    return path;
}
string Hash(string path) {using var input=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();}
string binary=Guard("unpacked/effective/exefs/main"),metadata=Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if(Hash(binary)!="94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"||Hash(metadata)!="f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85")throw new IOException("Input hash differs");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary,metadata,new UnityVersion(2018,1,9,UnityVersionType.Final,1));
var app=Cpp2IlApi.CurrentAppContext!;var keys=app.GetOrCreateKeyFunctionAddresses();int checks=0,cases=0;
void Check(bool test,string description) {if(!test)throw new Exception(description);checks++;}
Check(keys.il2cpp_codegen_runtime_class_init==0xB2E720,"Exact known runtime class initializer differs");
var boolean=app.SystemTypes.SystemBooleanType;
InjectedMethodAnalysisContext Fixture(string name,params Instruction[] instructions) {
    var method=new InjectedMethodAnalysisContext(boolean,name,app.SystemTypes.SystemVoidType,MethodAttributes.Public|MethodAttributes.Static,[]);
    method.ControlFlowGraph=new ISILControlFlowGraph(instructions.ToList());return method;
}
var klass=new RuntimeClassTypeAnalysisContext(boolean,boolean.DeclaringAssembly);
var local=new LocalVariable("klass",new Register(0,"X0"),klass);
bool Rewrite(Instruction instruction) {
    var method=Fixture("SelectionFixture",new Instruction(0,IsilOp.Move,local,boolean),instruction,new Instruction(2,IsilOp.Return));
    return KeyFunctionRecovery.RewriteLegacyClassInitializers(method);
}
var accepted=new Instruction(1,IsilOp.CallVoid,new Immediate(0xB2E720),local);
Check(Rewrite(accepted),"Proven runtime class operand rejected");
Check(accepted.Operands is [MethodAnalysisContext {Name:"RunClassConstructor",IsStatic:true,IsVoid:true,Parameters.Count:1} target,TypeAnalysisContext represented]
    &&target.Parameters[0].ParameterType.FullName=="System.RuntimeTypeHandle"&&ReferenceEquals(represented,boolean),"Managed target/type handle contract differs");
var targetMethod=(MethodAnalysisContext)accepted.Operands[0];
var rejected=new List<string>();
var result=new LocalVariable("unused_result",new Register(0,"RESULT"));
foreach(var (name,instruction) in new (string,Instruction)[]{
    ("wrong helper",new(0,IsilOp.CallVoid,new Immediate(0xB2E724),local)),
    ("extra semantic argument",new(0,IsilOp.CallVoid,new Immediate(0xB2E720),local,new Immediate(0))),
    ("return-bearing call",new(0,IsilOp.Call,new Immediate(0xB2E720),result,local)),
    ("unknown class",new(0,IsilOp.CallVoid,new Immediate(0xB2E720),new LocalVariable("unknown",new Register(0,"X0")))),
    ("ordinary managed Type",new(0,IsilOp.CallVoid,new Immediate(0xB2E720),new LocalVariable("type_object",new Register(0,"X0"),app.SystemTypes.SystemTypeType))),
    ("unproven direct typeof operand",new(0,IsilOp.CallVoid,new Immediate(0xB2E720),boolean)),
    ("absent argument",new(0,IsilOp.CallVoid,new Immediate(0xB2E720))),
}) {Check(!Rewrite(instruction),"Unsafe candidate accepted: "+name);rejected.Add(name);}
var open=app.GetAssemblyByName("mscorlib")!.Types.First(t=>t.FullName=="System.Collections.Generic.List`1");
var openLocal=new LocalVariable("open_class",new Register(1,"X1"),new RuntimeClassTypeAnalysisContext(open,open.DeclaringAssembly));
var openMethod=Fixture("OpenClass",new Instruction(0,IsilOp.Move,openLocal,open),new Instruction(1,IsilOp.CallVoid,new Immediate(0xB2E720),openLocal),new Instruction(2,IsilOp.Return));
Check(!KeyFunctionRecovery.RewriteLegacyClassInitializers(openMethod),"Open represented type accepted");
var inferred=new LocalVariable("dynamic_runtime_class",new Register(1,"X1"),klass);
Check(!Rewrite(new(1,IsilOp.CallVoid,new Immediate(0xB2E720),inferred)),"Unproven instance-derived RuntimeClass local accepted");
var late=Fixture("LateClassDefinition",new Instruction(0,IsilOp.CallVoid,new Immediate(0xB2E720),local),new Instruction(1,IsilOp.Move,local,boolean),new Instruction(2,IsilOp.Return));
Check(!KeyFunctionRecovery.RewriteLegacyClassInitializers(late),"Later class definition accepted");
var duplicated=Fixture("AmbiguousClassDefinitions",new Instruction(0,IsilOp.Move,local,boolean),new Instruction(1,IsilOp.Move,local,boolean),new Instruction(2,IsilOp.CallVoid,new Immediate(0xB2E720),local),new Instruction(3,IsilOp.Return));
Check(!KeyFunctionRecovery.RewriteLegacyClassInitializers(duplicated),"Ambiguous class definitions accepted");
var helper=targetMethod.DeclaringType!;
helper.Methods.Add(targetMethod);
try {Check(!Rewrite(new(1,IsilOp.CallVoid,new Immediate(0xB2E720),local)),"Ambiguous managed handle overload accepted");}
finally {helper.Methods.RemoveAt(helper.Methods.Count-1);}
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA",null);
Check(!Rewrite(new(0,IsilOp.CallVoid,new Immediate(0xB2E720),local)),"Disabled legacy experiment changed a call");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");

// An unproven class-init call must survive the exact metadata/guard-removal pipeline.
var unknownCall=new Instruction(0,IsilOp.CallVoid,new Immediate(0xB2E720),new LocalVariable("unknown",new Register(0,"X0")));
var unknown=Fixture("UnknownMustRemain",unknownCall,new Instruction(1,IsilOp.Return));
MetadataResolver.ResolveAll(unknown);KeyFunctionRecovery.Run(unknown);MetadataInitGuardRemover.Run(unknown);
Check(unknownCall.OpCode==IsilOp.CallVoid&&unknownCall.Operands[0] is Immediate {UnsignedValue:0xB2E720},"Unknown initializer effect was suppressed");

// Exercise actual class-metadata seeding and fixpoint ordering before SSA forwarding.
var classLocal=new LocalVariable("class_metadata",new Register(0,"X0"));
var seededCall=new Instruction(1,IsilOp.CallVoid,new Immediate(0xB2E720),classLocal);
var seeded=Fixture("SeededTypeHandle",new Instruction(0,IsilOp.Move,classLocal,boolean),seededCall,new Instruction(2,IsilOp.Return));
MetadataResolver.ResolveAll(seeded);KeyFunctionRecovery.Run(seeded);MetadataInitGuardRemover.Run(seeded);
Check(seededCall.Operands[0] is Immediate,"Untyped class bypassed proof gate");
LocalVariables.ResolveTypesAndFields(seeded);
Check(seededCall.Operands[0] is MethodAnalysisContext m&&ReferenceEquals(m,targetMethod),"Seeded RuntimeClass local was not lowered during the typed fixpoint");
SsaSimplifier.Run(seeded);
Check(seededCall.Operands is [MethodAnalysisContext,TypeAnalysisContext t]&&ReferenceEquals(t,boolean),"SSA altered the proven type token");

// Emit the selected ISIL through the real emitter. Only type/API tokens are rebound
// at the explicitly independent host-fixture boundary below; no game .cctor is run.
var module=new ModuleDefinition("ClassInitEmissionFixture.dll");
var assembly=new AssemblyDefinition("ClassInitEmissionFixture",new Version(1,0));assembly.Modules.Add(module);
var owner=new TypeDefinition("Fixtures","Caller",AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes.Public,module.CorLibTypeFactory.Object.Type);module.TopLevelTypes.Add(owner);
var methodDefinition=new MethodDefinition("Initialize",AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Public|AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Static,MethodSignature.CreateStatic(module.CorLibTypeFactory.Void));owner.Methods.Add(methodDefinition);
var tokenType=new TypeDefinition("Fixtures","TokenBoundary",AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes.Public,module.CorLibTypeFactory.Object.Type);module.TopLevelTypes.Add(tokenType);boolean.PutExtraData("AsmResolverType",tokenType);
var runtimeHandle=new TypeDefinition("System","RuntimeTypeHandle",AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes.Public|AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes.Sealed,module.DefaultImporter.ImportType(typeof(ValueType)));
var callDefinition=new MethodDefinition("RunClassConstructor",AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Public|AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Static,MethodSignature.CreateStatic(module.CorLibTypeFactory.Void,[runtimeHandle.ToTypeSignature(true)]));
targetMethod.PutExtraData("AsmResolverMethod",callDefinition);
var emission=Fixture("Emission",new Instruction(0,IsilOp.CallVoid,targetMethod,boolean),new Instruction(1,IsilOp.Return));
IlGenerator.GenerateIl(emission,methodDefinition);
var emitted=methodDefinition.CilMethodBody!.Instructions.Where(i=>i.OpCode!=CilOpCodes.Nop).ToArray();
Console.WriteLine("Synthetic emitter sequence: "+string.Join(",",emitted.Select(i=>i.OpCode.ToString())));
Check(emitted.Length==4&&emitted[0].OpCode==CilOpCodes.Ldtoken&&emitted[1].OpCode==CilOpCodes.Call
    &&emitted[2].OpCode==CilOpCodes.Br&&emitted[2].Operand is CilInstructionLabel label&&ReferenceEquals(label.Instruction,emitted[3])
    &&emitted[3].OpCode==CilOpCodes.Ret,"Emitter did not retain exact ldtoken/call/forward-to-ret contract");
Check(ReferenceEquals(emitted[1].Operand,callDefinition),"Emitter changed the exact handle-taking method");
Action Bind(Type type) {
    var dynamic=new DynamicMethod("ClassInitBoundary",typeof(void),Type.EmptyTypes,typeof(Program).Module,true);var il=dynamic.GetILGenerator();
    var labels=emitted.ToDictionary(instruction=>instruction,_=>il.DefineLabel());
    foreach(var instruction in emitted) {
        il.MarkLabel(labels[instruction]);
        if(instruction.OpCode==CilOpCodes.Ldtoken)il.Emit(OpCodes.Ldtoken,type);
        else if(instruction.OpCode==CilOpCodes.Call)il.Emit(OpCodes.Call,typeof(RuntimeHelpers).GetMethod(nameof(RuntimeHelpers.RunClassConstructor),[typeof(RuntimeTypeHandle)])!);
        else if(instruction.OpCode==CilOpCodes.Br)il.Emit(OpCodes.Br,labels[((CilInstructionLabel)instruction.Operand!).Instruction!]);
        else if(instruction.OpCode==CilOpCodes.Ret)il.Emit(OpCodes.Ret);
        else throw new Exception("Unapproved instruction at fixture boundary");
    }
    return dynamic.CreateDelegate<Action>();
}
Check(Effects.Normal==0&&Effects.Throws==0&&Effects.Parallel==0,"Fixture initialized prematurely");
var normal=Bind(typeof(EffectFixture));
for(int i=0;i<32;i++){normal();cases++;Check(Effects.Normal==1&&EffectFixture.Payload==0x13579BDF,"Static effect/default suppression/once contract failed");}
var throwing=Bind(typeof(ThrowFixture));
for(int i=0;i<32;i++){
    TypeInitializationException? observed=null;try{throwing();}catch(TypeInitializationException ex){observed=ex;}
    cases++;Check(observed?.InnerException is FixtureInitializationException {Message:"fixture-cctor-failed"},"Initializer exception was suppressed or changed");
    Check(Effects.Throws==1,"Throwing initializer ran more than once");
}
var concurrent=Bind(typeof(ParallelFixture));
Parallel.For(0,16,_=>concurrent());cases+=16;
Check(Effects.Parallel==1&&ParallelFixture.Payload==0x2468ACE,"Concurrent initialization did not execute exactly once");
var report=new{status="PASS_LEGACY_CLASS_INIT_TYPED_LOWERING_AND_CLR_CONTRACT",cases,checks,
    known_native_target="0xB2E720",native_target_discovery="Three agreeing corlib families in existing NewArm64KeyFunctionAddresses recovery",
    exact_managed_target=targetMethod.FullNameWithSignature,rejected_candidates=rejected,
    unproven_initializer_preserved=true,type_seeding_fixpoint_before_ssa=true,emitted_opcodes=emitted.Select(i=>i.OpCode.ToString()).ToArray(),
    fixture_effect_calls=32,fixture_throw_calls=32,fixture_concurrent_calls=16,fixture_effect_count=Effects.Normal,fixture_throw_effect_count=Effects.Throws,fixture_concurrent_effect_count=Effects.Parallel,
    core_assembly_sha256=Hash(typeof(KeyFunctionRecovery).Assembly.Location),binary_sha256=Hash(binary),metadata_sha256=Hash(metadata),
    scope="Actual metadata and the real ISIL/emitter prove the exact RuntimeTypeHandle-taking API and unchanged class-init effect. Host-fixture type/API token rebinding executes the emitted ldtoken/call/forward-branch/ret contract with independently authored .cctors, proving observable nondefault effects, once-only execution, concurrent once semantics and persistent throwing behavior. The forward branch is checked to target the sole ret and retained. It does not execute original game .cctor bodies, the native runtime initializer, or a whole recovered caller; it cannot certify gameplay or full decompilation."};
File.WriteAllText(Guard($"reports/legacy-class-init-lowering-{reportLabel}"+(args.Length==2?"-regression":"")+".json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");
Console.WriteLine(JsonSerializer.Serialize(new{report.status,cases,checks}));

public static class Effects {public static int Normal,Throws,Parallel;}
public static class EffectFixture {public static readonly int Payload;static EffectFixture(){Effects.Normal++;Payload=0x13579BDF;}}
public sealed class FixtureInitializationException(string message):Exception(message);
public static class ThrowFixture {static ThrowFixture(){Effects.Throws++;throw new FixtureInitializationException("fixture-cctor-failed");}}
public static class ParallelFixture {public static readonly int Payload;static ParallelFixture(){Interlocked.Increment(ref Effects.Parallel);Payload=0x2468ACE;}}
