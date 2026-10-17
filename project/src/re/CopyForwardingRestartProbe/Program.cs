using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;

if(args.Length!=1)throw new ArgumentException("USB root required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative){string p=Path.GetFullPath(Path.Combine(root,relative));if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside USB");for(DirectoryInfo? d=new(Path.GetDirectoryName(p)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse");return p;}
string Hash(string p)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p))).ToLowerInvariant();
string core=typeof(Simplifier).Assembly.Location;
if(Hash(core)!="14232d46ca291ffb67944705e94ec5460bc8ee70c3df88ee3ef27e77b6e736d6")throw new InvalidDataException("Frozen v40 Core identity required");
var cases=new List<object>();int bad=0,controls=0;
foreach(string mode in new[]{"memory-source-overwrite","plain-source-overwrite","no-overwrite","source-overwrite-after-read","destination-overwrite"})
foreach(var values in new[]{(0x1000L,0x2000L,17L,29L),(0x3000L,0x4000L,-33L,91L),(0x5000L,0x6000L,0L,987654321L)}){
 var source=new LocalVariable("source",new Register(1,"source"));var other=new LocalVariable("other",new Register(2,"other"));
 var copy=new LocalVariable("copy",new Register(3,"copy"));var result=new LocalVariable("result",new Register(4,"result"));
 var rows=new List<Instruction>{new(0,OpCode.Move,copy,source)};
 if(mode is "memory-source-overwrite" or "plain-source-overwrite")rows.Add(new(rows.Count,OpCode.Move,source,other));
 if(mode=="destination-overwrite")rows.Add(new(rows.Count,OpCode.Move,copy,other));
 rows.Add(new(rows.Count,OpCode.Move,result,mode=="plain-source-overwrite"?copy:new MemoryOperand(copy,addend:16)));
 if(mode=="source-overwrite-after-read")rows.Add(new(rows.Count,OpCode.Move,source,other));
 rows.Add(new(rows.Count,OpCode.Return,result));
 long Execute(IEnumerable<Instruction> code){
  var slots=new Dictionary<LocalVariable,long>{{source,values.Item1},{other,values.Item2}};
  var memory=new Dictionary<long,long>{{values.Item1+16,values.Item3},{values.Item2+16,values.Item4}};
  long Value(IOperand operand)=>operand switch{LocalVariable local=>slots[local],Immediate immediate=>immediate.Value,MemoryOperand load=>memory[Value(load.Base!)+load.Addend+(load.Index==null?0:Value(load.Index)*load.Scale)],_=>throw new NotSupportedException(operand.GetType().Name)};
  foreach(var row in code){if(row.OpCode==OpCode.Nop)continue;if(row.OpCode==OpCode.Move&&row.Operands[0] is LocalVariable local)slots[local]=Value(row.Operands[1]);else if(row.OpCode==OpCode.Return)return Value(row.Operands[0]);else throw new NotSupportedException(row.ToString());}
  throw new InvalidDataException("Missing return");
 }
 long before=Execute(rows);string[] original=rows.Select(r=>r.ToString()).ToArray();
 var owner=(MethodAnalysisContext)RuntimeHelpers.GetUninitializedObject(typeof(MethodAnalysisContext));
 owner.ControlFlowGraph=new ISILControlFlowGraph(rows);owner.Locals=[source,other,copy,result];owner.ParameterLocals=[source,other];
 Simplifier.Simplify(owner);
 var transformed=owner.ControlFlowGraph.Instructions;long after=Execute(transformed);
 bool expectedCounterexample=mode is "memory-source-overwrite" or "plain-source-overwrite";
 if(expectedCounterexample&&before!=after)bad++;if(!expectedCounterexample&&before==after)controls++;
 cases.Add(new{mode,input_source=values.Item1,input_other=values.Item2,before,after,equivalent=before==after,expected_counterexample=expectedCounterexample,original,transformed=transformed.Select(r=>r.ToString()).ToArray()});
}
var report=new{status=bad==6&&controls==9?"CONFIRMED_FROZEN_V40_COPY_SOURCE_REASSIGNMENT_MISCOMPILATION":"PROBE_EXPECTATION_FAILED",counterexamples=bad,control_cases_preserved=controls,cases,core_sha256=Hash(core),probe_source_sha256=Hash(Guard("src/re/CopyForwardingRestartProbe/Program.cs")),game_methods_executed=0,game_metadata_loaded=false,current_v41_core_built=false,
 scope="Executes unchanged frozen v40 Simplifier.Simplify on minimal real ISIL/CFG/LocalVariable objects. An uninitialized method context supplies only the actual pass's Locals/ParameterLocals/CFG fields; the full production pipeline is not invoked. A bounded independent Move/Return/memory-read interpreter compares input and transformed fixture semantics. Confirms optimizer behavior only; not an actual game caller witness or production v41 NativeRead carrier test."};
string output=Guard("reports/copy-forwarding-source-reassignment-restart-v41.json");if(File.Exists(output))throw new IOException("Historical report must be preserved");File.WriteAllText(output,JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");
Console.WriteLine(JsonSerializer.Serialize(new{report.status,bad,controls,report.core_sha256,output}));return bad==6&&controls==9?0:2;
