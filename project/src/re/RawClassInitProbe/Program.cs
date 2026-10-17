using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;

if(args.Length is <1 or >2||args.Length==2&&args[1] is not ("--v33" or "--v34" or "--v35" or "--v36" or "--v37"))throw new ArgumentException("Verified USB root and optional --v33/--v34/--v35/--v36/--v37 required");
string reportLabel=args.Length==2?args[1][2..]:"v32";
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative){string path=Path.GetFullPath(Path.Combine(root,relative));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");return path;}
string Hash(string path){using var file=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant();}
string binary=Guard("unpacked/effective/exefs/main"),metadata=Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if(Hash(binary)!="94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"||Hash(metadata)!="f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85")throw new IOException("Input differs");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));Cpp2IlApi.InitializeLibCpp2Il(binary,metadata,new UnityVersion(2018,1,9,UnityVersionType.Final,1));
var app=Cpp2IlApi.CurrentAppContext!;var keys=app.GetOrCreateKeyFunctionAddresses();var boolean=app.SystemTypes.SystemBooleanType;
int checks=0;var rejected=new List<string>();void Check(bool value,string name){if(!value)throw new Exception(name);checks++;}
(InjectedMethodAnalysisContext Method,Instruction Call,LocalVariable Result,LocalVariable Class) Fixture(string name){
    var klass=new LocalVariable("class_metadata",new Register(null,"X0"),new RuntimeClassTypeAnalysisContext(boolean,boolean.DeclaringAssembly));
    var result=new LocalVariable("captured_result",new Register(null,"X0"));
    var operands=new List<IOperand>{new Immediate((long)keys.il2cpp_codegen_runtime_class_init),result,klass};
    for(int i=1;i<8;i++)operands.Add(new LocalVariable("stale_x"+i,new Register(null,"X"+i)));
    for(int i=0;i<8;i++)operands.Add(new LocalVariable("stale_v"+i,new Register(null,"V"+i)));
    var call=new Instruction(1,OpCode.Call,operands);var method=new InjectedMethodAnalysisContext(boolean,name,app.SystemTypes.SystemVoidType,MethodAttributes.Public|MethodAttributes.Static,[]);
    method.ControlFlowGraph=new ISILControlFlowGraph([new Instruction(0,OpCode.Move,klass,boolean),call,new Instruction(3,OpCode.Return)]);
    return(method,call,result,klass);
}
bool Rewrite(InjectedMethodAnalysisContext method)=>KeyFunctionRecovery.RewriteLegacyClassInitializers(method);
Check(keys.il2cpp_codegen_runtime_class_init==0xB2E720,"Known native initializer differs");
var accepted=Fixture("UnusedRawResult");Check(app.InstructionSet.CallingConventionResolver!.HasRawArgumentLayout(accepted.Call,app),"Fixture does not have production raw ABI layout");
Check(Rewrite(accepted.Method),"Proven unused raw call rejected");
Check(accepted.Call.OpCode==OpCode.CallVoid&&accepted.Call.Operands is [MethodAnalysisContext {Name:"RunClassConstructor",IsVoid:true},TypeAnalysisContext t]&&ReferenceEquals(t,boolean),"Raw call did not become the exact managed void initialization request");
Check(!accepted.Method.ControlFlowGraph!.Instructions.Any(i=>i.Sources.Any(o=>ReferenceEquals(o,accepted.Result))),"Discarded raw result acquired a fabricated value");
var field=app.Assemblies.SelectMany(a=>a.Types).Single(t=>t.FullName=="CodeStage.AntiCheat.ObscuredTypes.ObscuredInt").Fields.First(f=>!f.IsStatic);
foreach(var (name,use) in new (string,Func<LocalVariable,IOperand>)[]{
    ("direct",r=>r),("memory-base",r=>new MemoryOperand(r,addend:8)),("memory-index",r=>new MemoryOperand(new Immediate(0x1000),r,scale:8)),
    ("instance-field-owner",r=>new FieldReference(field,r,field.Offset)),("slot-address",r=>new AddressOf(r)),
    ("array-owner",r=>new ArrayAccess(r,new Immediate(0))),("array-index",r=>new ArrayAccess(new LocalVariable("array",new Register(null,"ARRAY")),r)),
    ("addressed-array-index",r=>new AddressOf(new ArrayAccess(new LocalVariable("array",new Register(null,"ARRAY")),r))),
    ("array-length",r=>new ArrayLength(r)),
}){
    var f=Fixture(name);var instruction=new Instruction(2,OpCode.Move,new LocalVariable("read",new Register(null,"READ")),use(f.Result));
    f.Method.ControlFlowGraph=new ISILControlFlowGraph([new Instruction(0,OpCode.Move,f.Class,boolean),f.Call,instruction,new Instruction(3,OpCode.Return)]);
    Check(!Rewrite(f.Method),"Used raw result accepted: "+name);rejected.Add(name);
}
foreach(var (name,use) in new (string,Func<LocalVariable,Instruction>)[]{
    ("destination-memory-base",r=>new Instruction(2,OpCode.Move,new MemoryOperand(r,addend:8),new Immediate(0))),
    ("destination-array-index",r=>new Instruction(2,OpCode.Move,new ArrayAccess(new LocalVariable("array",new Register(null,"ARRAY")),r),new Immediate(0))),
    ("destination-field-owner",r=>new Instruction(2,OpCode.Move,new FieldReference(field,r,field.Offset),new Immediate(0))),
    ("throw-operand",r=>new Instruction(2,OpCode.Throw,r)),
    ("indirect-call-target",r=>new Instruction(2,OpCode.IndirectCall,r,new LocalVariable("other_result",new Register(null,"OTHER")))),
    ("phi-input",r=>new Instruction(2,OpCode.Phi,new LocalVariable("merged",new Register(null,"MERGED")),r)),
    ("duplicate-result-definition",r=>new Instruction(2,OpCode.Move,r,new Immediate(0))),
}){
    var f=Fixture(name);f.Method.ControlFlowGraph=new ISILControlFlowGraph([new Instruction(0,OpCode.Move,f.Class,boolean),f.Call,use(f.Result),new Instruction(3,OpCode.Return)]);
    Check(!Rewrite(f.Method),"Nested/live or nonunique result accepted: "+name);rejected.Add(name);
}
foreach(var (name,mutate) in new (string,Action<Instruction>)[]{
    ("wrong-helper",c=>c.SetOperand(0,new Immediate(0xB2E724))),
    ("wrong-integer-register",c=>c.SetOperand(5,new LocalVariable("wrong",new Register(null,"X9")))),
    ("nonphysical-semantic-argument",c=>c.SetOperand(10,new Immediate(123))),
    ("missing-argument",c=>c.RemoveOperandAt(17)),
    ("extra-argument",c=>c.SetOperands(c.Operands.Append(new Immediate(123)).ToList())),
    ("wrong-result-register",c=>c.SetOperand(1,new LocalVariable("wrong_result",new Register(null,"X2")))),
}){var f=Fixture(name);mutate(f.Call);Check(!Rewrite(f.Method),"Invalid raw layout accepted: "+name);rejected.Add(name);}
var phi=Fixture("PhiClassMustRemain");phi.Method.ControlFlowGraph=new ISILControlFlowGraph([new Instruction(0,OpCode.Phi,phi.Class,boolean),phi.Call,new Instruction(3,OpCode.Return)]);Check(!Rewrite(phi.Method),"Phi class origin accepted");
var unknown=Fixture("UnknownClassMustRemain");unknown.Class.Type=null;Check(!Rewrite(unknown.Method),"Unknown class type accepted");
var unused=Fixture("UnusedCallVoidRawNotApproved");unused.Call.OpCode=OpCode.CallVoid;unused.Call.RemoveOperandAt(1);Check(!Rewrite(unused.Method),"Unapproved raw CallVoid expansion accepted");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA",null);var disabled=Fixture("Disabled");Check(!Rewrite(disabled.Method),"Opt-in disabled raw lowering");Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");
var report=new{status="PASS_RAW_CLASS_INIT_ABI_UNUSED_RESULT_AND_DEEP_USE_GUARDS",checks,rejected,
    raw_operands=18,raw_registers="X0-X7,V0-V7",unused_result_register="X0",preserved_existing_void_one_arg_contract=true,
    metadata_sha256=Hash(metadata),binary_sha256=Hash(binary),core_sha256=Hash(typeof(KeyFunctionRecovery).Assembly.Location),
    scope="Independent ISIL fixtures use the actual known native class-init identity, real managed API metadata and existing exact class-metadata origin proof. Only a proven raw ABI capture and unused unique X0 result are removed. Deep operand/source/store-address/throw/indirect-target uses, malformed layouts, ambiguous class origins and disabled opt-in remain unresolved. No original caller, native class initializer or game .cctor executes here; existing emitted CLR contract and actual caller-stage probes provide separate evidence."};
File.WriteAllText(Guard($"reports/raw-classinit-lowering-guards-{reportLabel}.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,checks}));
