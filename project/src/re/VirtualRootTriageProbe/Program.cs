using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;

if(args.Length!=1)throw new ArgumentException("Verified USB root required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative){string p=Path.GetFullPath(Path.Combine(root,relative));if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(p)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");return p;}
string Hash(string p){using var f=File.OpenRead(p);return Convert.ToHexString(SHA256.HashData(f)).ToLowerInvariant();}
string binary=Guard("unpacked/effective/exefs/main"),metadata=Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if(Hash(binary)!="94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"||Hash(metadata)!="f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85")throw new IOException("Input mismatch");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));Cpp2IlApi.InitializeLibCpp2Il(binary,metadata,new UnityVersion(2018,1,9,UnityVersionType.Final,1));
var app=Cpp2IlApi.CurrentAppContext!;var types=app.Assemblies.SelectMany(a=>a.Types).ToArray();
var methods=new[]{
 types.Single(t=>t.FullName=="XmlExtensions").Methods.Single(m=>m.Name=="TryGetAttribute"),
 types.Single(t=>t.FullName=="XmlExtensions").Methods.Single(m=>m.Name=="FirstAttribute"),
 types.Single(t=>t.FullName=="YamlDotNet.Core.Emitter").Methods.Single(m=>m.Name=="Write"&&m.Parameters.Count==1&&m.Parameters[0].ParameterType.FullName=="System.Char")};
var reports=new List<object>();
var resolve=typeof(MetadataResolver).GetMethod("ResolveVTableSlot",BindingFlags.Static|BindingFlags.NonPublic)!;
var valid=typeof(LegacyArm64VirtualDispatch).GetMethod("ValidTarget",BindingFlags.Static|BindingFlags.NonPublic)!;
foreach(var method in methods){
 method.ConvertedIsil=app.InstructionSet.GetIsilFromMethod(method);method.ParameterOperands=app.InstructionSet.GetParameterOperandsFromMethod(method);method.ControlFlowGraph=new ISILControlFlowGraph(method.ConvertedIsil);
 StackAnalyzer.Analyze(method);method.DominatorInfo=new DominatorInfo(method.ControlFlowGraph);SsaForm.Build(method);LocalVariables.CreateAll(method);FlagConditionRecovery.Run(method);DeadCodeEliminator.Run(method);
 MetadataResolver.ResolveAll(method);KeyFunctionRecovery.Run(method);DeadCodeEliminator.Run(method);MetadataInitGuardRemover.Run(method);WriteBarrierRecovery.Run(method);InjectedCheckRemover.Run(method);InterfaceDispatchRecovery.Run(method);LocalVariables.ResolveTypesAndFields(method);
 var graph=method.ControlFlowGraph!;var definitions=graph.Instructions.Where(i=>i.Destination is LocalVariable).GroupBy(i=>(LocalVariable)i.Destination!).ToDictionary(g=>g.Key,g=>g.ToArray());
 object Describe(IOperand? o)=>o switch{
  LocalVariable l=>new{kind="local",l.Name,type=l.Type?.FullName,register=l.Register.Name,version=l.Register.Version,l.IsThis,parameter_member=method.ParameterLocals.Contains(l),l.IsMethodInfo},
  MemoryOperand mem=>new{kind="memory",mem.Addend,base_local=(mem.Base as LocalVariable)?.Name,base_type=(mem.Base as LocalVariable)?.Type?.FullName,indexed=mem.Index!=null,mem.Scale},
  MethodAnalysisContext m=>new{kind="method",m.FullName},FieldReference f=>new{kind="field",description=f.ToString()},
  _=>new{kind=o?.GetType().Name,description=o?.ToString()}};
 object Chain(IOperand? o){var rows=new List<object>();var seen=new HashSet<LocalVariable>();for(int n=0;n<32&&o is LocalVariable l&&seen.Add(l);n++){
  if(!definitions.TryGetValue(l,out var defs)){rows.Add(new{local=Describe(l),definition_count=0});break;}
  rows.Add(new{local=Describe(l),definition_count=defs.Length,definitions=defs.Select(d=>new{d.Index,opcode=d.OpCode.ToString(),sources=d.Operands.Skip(1).Select(Describe).ToArray()}).ToArray()});
  if(defs.Length!=1||defs[0].OpCode!=OpCode.Move||defs[0].Operands is not[_,LocalVariable next])break;o=next;}return rows;}
 MemoryOperand? Load(IOperand o)=>o is MemoryOperand m?m:o is LocalVariable l&&definitions.TryGetValue(l,out var ds)&&ds.Length==1&&ds[0].OpCode==OpCode.Move&&ds[0].Operands[1] is MemoryOperand mm?mm:null;
 var calls=new List<object>();
 foreach(var call in graph.Instructions.Where(i=>i.OpCode==OpCode.IndirectCall||i.NativeVirtualDispatch!=null)){
  if(call.NativeVirtualDispatch is{} existing){calls.Add(new{index=call.Index,accepted=true,target=existing.Target.FullName});continue;}
  var function=Load(call.Operands[0]);var klass=function?.Base as LocalVariable;var type=(klass?.Type as RuntimeClassTypeAnalysisContext)?.RepresentedType;long off=(function?.Addend??0)-0x128;int slot=off>=0&&off%16==0&&off/16<=int.MaxValue?(int)(off/16):-1;
  var target=type!=null&&slot>=0?resolve.Invoke(null,[app,type,slot])as MethodAnalysisContext:null;
  var classload=klass!=null?Load(klass):null;var companion=call.Operands.Count>3?Load(call.Operands[3]):null;
  var block=graph.Blocks.Single(b=>b.Instructions.Contains(call));int pos=block.Instructions.IndexOf(call);
  calls.Add(new{index=call.Index,accepted=false,target=target?.FullName,return_type=target?.ReturnType.FullName,parameters=target?.Parameters.Count,is_void=target?.IsVoid,target_scope_accepts=target!=null&&(bool)valid.Invoke(null,[target,slot])!,slot,raw_count=call.Operands.Count,
   function=function is{} ff?Describe(ff):null,companion=companion is{} cc?Describe(cc):null,klass=Describe(klass),classload=classload is{} cl?Describe(cl):null,
   receiver_chain=call.Operands.Count>2?Chain(call.Operands[2]):null,class_source_chain=classload is{} cl2?Chain(cl2.Base):null,
   preceding_window=block.Instructions.Skip(Math.Max(0,pos-8)).Take(Math.Min(8,pos)).Select(i=>new{i.Index,opcode=i.OpCode.ToString(),operands=i.Operands.Select(Describe).ToArray()}).ToArray()});
 }
 string file="analysis/il2cpp/virtual-root-triage-v37-"+method.Name+"-"+method.UnderlyingPointer.ToString("X")+".txt";File.WriteAllText(Guard(file),string.Join("\n",graph.Blocks.Select(b=>b.ToString())));
 reports.Add(new{method=method.FullName,rva="0x"+method.UnderlyingPointer.ToString("X"),calls,private_graph=file});
}
var report=new{status="READ_ONLY_ACTUAL_VIRTUAL_RECEIVER_ROOT_AND_TARGET_SCOPE_TRIAGE",core_sha256=Hash(typeof(KeyFunctionRecovery).Assembly.Location),binary_sha256=Hash(binary),metadata_sha256=Hash(metadata),loaded_binary_sha256=Convert.ToHexString(SHA256.HashData(app.Binary.GetRawBinaryContent())).ToLowerInvariant(),loaded_binary_bytes=app.Binary.GetRawBinaryContent().Length,methods=reports,core_modified=false,game_methods_invoked=0,full_clean_decompile_ready=false,limits="Three unchanged production SSA/type graphs only. Alternative witness rules are not implemented or claimed safe; original method execution and arbitrary native load width remain unproved."};
File.WriteAllText(Guard("reports/virtual-receiver-root-triage-v37.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,methods=reports.Count}));
