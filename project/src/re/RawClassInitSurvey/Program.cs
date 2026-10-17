using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;

if(args.Length is <1 or >2||args.Length==2&&args[1] is not ("--after" or "--v33" or "--v34"))throw new ArgumentException("Verified USB root and optional --after/--v33/--v34 required");
bool after=args.Length==2;string suffix=after?(args[1]=="--v34"?"v34":args[1]=="--v33"?"v33":"v32-after"):"v32";
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative){string path=Path.GetFullPath(Path.Combine(root,relative));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");return path;}
string Hash(string path){using var file=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant();}
string binary=Guard("unpacked/effective/exefs/main"),metadata=Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if(Hash(binary)!="94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"||Hash(metadata)!="f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85")throw new IOException("Input differs");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));Cpp2IlApi.InitializeLibCpp2Il(binary,metadata,new UnityVersion(2018,1,9,UnityVersionType.Final,1));
var app=Cpp2IlApi.CurrentAppContext!;var keys=app.GetOrCreateKeyFunctionAddresses();var allTypes=app.Assemblies.SelectMany(a=>a.Types).ToArray();
var results=new List<object>();
bool References(IOperand operand,LocalVariable local)=>operand switch{LocalVariable l=>ReferenceEquals(l,local),MemoryOperand m=>(m.Base!=null&&References(m.Base,local))||(m.Index!=null&&References(m.Index,local)),FieldReference f=>ReferenceEquals(f.Local,local),AddressOf a=>References(a.Target,local),ArrayAccess a=>ReferenceEquals(a.Array,local)||References(a.Index,local),ArrayLength a=>ReferenceEquals(a.Array,local),_=>false};
foreach(var (typeName,methodName) in new[]{("BinaryReaderNekki","ReadBoolean"),("BundlesUtil","UnloadDependencies"),("BundlesUtil","GetAssetBundleSafe")}){
    var method=allTypes.Single(t=>t.FullName==typeName).Methods.Single(m=>m.Name==methodName);
    method.ConvertedIsil=app.InstructionSet.GetIsilFromMethod(method);method.ParameterOperands=app.InstructionSet.GetParameterOperandsFromMethod(method);method.ControlFlowGraph=new ISILControlFlowGraph(method.ConvertedIsil);
    StackAnalyzer.Analyze(method);method.DominatorInfo=new DominatorInfo(method.ControlFlowGraph);SsaForm.Build(method);LocalVariables.CreateAll(method);FlagConditionRecovery.Run(method);DeadCodeEliminator.Run(method);
    var calls=method.ControlFlowGraph.Instructions.Where(i=>i.IsCall&&i.Operands[0] is Immediate target&&target.UnsignedValue==keys.il2cpp_codegen_runtime_class_init).ToArray();
    object Snapshot(Instruction call){var result=call.Destination as LocalVariable;var graph=method.ControlFlowGraph!;var argument=call.Operands.Count>(call.OpCode==OpCode.Call?2:1)?call.Operands[call.OpCode==OpCode.Call?2:1]:null;
        var uses=result==null?Array.Empty<Instruction>():graph.Instructions.Where(i=>!ReferenceEquals(i,call)&&i.Sources.Any(o=>References(o,result))).ToArray();
        var deep=result==null?Array.Empty<Instruction>():graph.Instructions.Where(i=>i.Operands.Any(o=>!(o is LocalVariable&&ReferenceEquals(o,i.Destination))&&References(o,result))).ToArray();
        object Origin(IOperand? value,int depth=0){if(value==null||depth>8)return new{kind="unknown"};if(value is TypeAnalysisContext type)return new{kind="type_operand",type=type.FullName};if(value is LocalVariable local){var defs=graph.Instructions.Where(i=>ReferenceEquals(i.Destination,local)).ToArray();return new{kind="local",local.Name,register=local.Register.Name,version=local.Register.Version,type=local.Type?.FullName,definitions=defs.Length,definition_opcode=defs.Length==1?defs[0].OpCode.ToString():null,source=defs.Length==1&&defs[0].OpCode==OpCode.Move?Origin(defs[0].Operands[1],depth+1):null};}return new{kind=value.GetType().Name};}
        return new{index=call.Index,opcode=call.OpCode.ToString(),operand_count=call.Operands.Count,target_kind=call.Operands[0].GetType().Name,target=call.Operands[0] is MethodAnalysisContext managed?managed.FullName:call.Operands[0].ToString(),argument_origin=Origin(argument),return_local=result?.Name,return_type=result?.Type?.FullName,return_source_uses=uses.Length,return_deep_operand_reads=deep.Length,return_use_opcodes=uses.Select(i=>i.OpCode.ToString()).ToArray(),raw_argument_registers=call.Operands.Skip(call.OpCode==OpCode.Call?2:1).Select(o=>o is LocalVariable l?l.Register.Name:o.GetType().Name).ToArray(),method_info_arguments=call.Operands.OfType<LocalVariable>().Where(l=>l.Type is RuntimeMethodInfoAnalysisContext).Select(l=>((RuntimeMethodInfoAnalysisContext)l.Type!).RepresentedMethod.FullName).ToArray()};}
    var before=calls.Select(Snapshot).ToArray();
    MetadataResolver.ResolveAll(method);KeyFunctionRecovery.Run(method);var afterMetadata=calls.Select(Snapshot).ToArray();
    File.WriteAllText(Guard($"analysis/il2cpp/raw-classinit-{typeName}-{methodName}-before-type-{suffix}.txt"),string.Join("\n",method.ControlFlowGraph.Blocks.Select(b=>b.ToString())));
    // This exact production fixpoint includes MethodInfo-based fallback resolution.
    LocalVariables.ResolveTypesAndFields(method);var afterType=calls.Select(Snapshot).ToArray();
    File.WriteAllText(Guard($"analysis/il2cpp/raw-classinit-{typeName}-{methodName}-after-type-{suffix}.txt"),string.Join("\n",method.ControlFlowGraph.Blocks.Select(b=>b.ToString())));
    var fields=method.ControlFlowGraph.Instructions.SelectMany(i=>i.Operands.OfType<FieldReference>().Select(f=>new{index=i.Index,opcode=i.OpCode.ToString(),field=f.Field.Name,owner=f.Field.DeclaringType.FullName,offset=f.Offset})).ToArray();
    var runtimeMemory=method.ControlFlowGraph.Instructions.SelectMany(i=>i.Operands.OfType<MemoryOperand>().Where(m=>m.Base is LocalVariable {Type:RuntimeClassTypeAnalysisContext}).Select(m=>new{index=i.Index,addend=m.Addend})).ToArray();
    results.Add(new{method=method.FullName,rva=$"0x{method.UnderlyingPointer:X}",raw_native_class_init_calls=calls.Length,before_metadata=before,after_metadata=afterMetadata,after_type_fixpoint=afterType,resolved_field_operands=fields,remaining_runtime_class_memory_operands=runtimeMemory});
}
var aliases=app.MethodsByAddress.TryGetValue(keys.il2cpp_codegen_runtime_class_init,out var mapped)?mapped.Select(m=>m.FullName).ToArray():Array.Empty<string>();
var report=new{status="READ_ONLY_RAW_CLASS_INIT_STAGE_OBSERVATIONS",known_helper=$"0x{keys.il2cpp_codegen_runtime_class_init:X}",managed_aliases_at_helper=aliases,methods=results,core_sha256=Hash(typeof(KeyFunctionRecovery).Assembly.Location),binary_sha256=Hash(binary),metadata_sha256=Hash(metadata),survey_edits_core_source=false,scope="Selected actual methods are analyzed only through the production type/field fixpoint with stage snapshots. Native helper identities, SSA result-use counts and class-metadata origins are observations; no rewrite, default, runtime parity or portable-source claim is made. The --after mode observes the explicitly approved recovery implementation; this survey itself edits no Core source."};
File.WriteAllText(Guard($"reports/raw-classinit-stage-survey-{suffix}.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,methods=results.Count}));
