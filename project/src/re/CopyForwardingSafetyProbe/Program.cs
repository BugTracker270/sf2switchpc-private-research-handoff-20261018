using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
if(args.Length!=2||!Regex.IsMatch(args[1],"^[a-z0-9-]+$"))throw new ArgumentException("USB root and unique label required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar),label=args[1];
string Guard(string relative){string p=Path.GetFullPath(Path.Combine(root,relative));if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside USB");for(DirectoryInfo? d=new(Path.GetDirectoryName(p)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse");return p;}
string Hash(string path)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var cases=new List<object>();int failures=0,total=0;
foreach(string mode in new[]{"memory-source-overwrite","plain-source-overwrite","no-overwrite","source-overwrite-after-read","destination-overwrite","address-source-write","load-before-memory-write","branch-overwrite-left","branch-overwrite-right"})
foreach(var values in new[]{(0x1000L,0x2000L,17L,29L),(0x3000L,0x4000L,-33L,91L),(0x5000L,0x6000L,0L,987654321L)}){
 var source=new LocalVariable("source",new Register(1,"source"));var other=new LocalVariable("other",new Register(2,"other"));var copy=new LocalVariable("copy",new Register(3,"copy"));var result=new LocalVariable("result",new Register(4,"result"));var condition=new LocalVariable("condition",new Register(5,"condition"));
 var rows=new List<Instruction>{new(0,OpCode.Move,copy,source)};
 if(mode is "memory-source-overwrite" or "plain-source-overwrite")rows.Add(new(rows.Count,OpCode.Move,source,other));
 if(mode=="destination-overwrite")rows.Add(new(rows.Count,OpCode.Move,copy,other));
 if(mode=="address-source-write")rows.Add(new(rows.Count,OpCode.CallVoid,new Immediate(0x111),new AddressOf(source)));
 rows.Add(new(rows.Count,OpCode.Move,result,mode=="plain-source-overwrite"?copy:new MemoryOperand(copy,addend:16)));
 if(mode=="source-overwrite-after-read")rows.Add(new(rows.Count,OpCode.Move,source,other));
 if(mode=="load-before-memory-write")rows.Add(new(rows.Count,OpCode.CallVoid,new Immediate(0x222)));
 rows.Add(new(rows.Count,OpCode.Return,result));
 ISILControlFlowGraph graph;
 if(mode.StartsWith("branch",StringComparison.Ordinal)){
  graph=new ISILControlFlowGraph([]);graph.EntryBlock.Successors.Clear();graph.ExitBlock.Predecessors.Clear();graph.Blocks.RemoveAll(b=>!ReferenceEquals(b,graph.EntryBlock)&&!ReferenceEquals(b,graph.ExitBlock));var left=new Block{ID=10};var right=new Block{ID=11};var join=new Block{ID=12};graph.Blocks.AddRange([left,right,join]);
  void Edge(Block a,Block b){a.Successors.Add(b);b.Predecessors.Add(a);}
  Edge(graph.EntryBlock,left);Edge(graph.EntryBlock,right);Edge(left,join);Edge(right,join);Edge(join,graph.ExitBlock);
  graph.EntryBlock.Instructions.AddRange([new(0,OpCode.Move,copy,source),new(1,OpCode.ConditionalJump,left,condition)]);
  left.Instructions.AddRange([new(2,OpCode.Move,source,other),new(3,OpCode.Jump,join)]);right.Instructions.Add(new(4,OpCode.Jump,join));join.Instructions.AddRange([new(5,OpCode.Move,result,new MemoryOperand(copy,addend:16)),new(6,OpCode.Return,result)]);
 }else graph=new ISILControlFlowGraph(rows);
 long Execute(ISILControlFlowGraph code){
  var slots=new Dictionary<LocalVariable,long>{{source,values.Item1},{other,values.Item2},{condition,mode=="branch-overwrite-left"?1:0}};var memory=new Dictionary<long,long>{{values.Item1+16,values.Item3},{values.Item2+16,values.Item4}};
  long Value(IOperand op)=>op switch{LocalVariable l=>slots[l],Immediate n=>n.Value,MemoryOperand m=>memory[Value(m.Base!)+m.Addend+(m.Index==null?0:Value(m.Index)*m.Scale)],_=>throw new NotSupportedException(op.GetType().Name)};
  Block current=code.EntryBlock;
  for(int step=0;step<128;step++){
   Block? next=null;
   foreach(var row in current.Instructions){
    if(row.OpCode==OpCode.Nop)continue;
    if(row.OpCode==OpCode.Move&&row.Operands[0] is LocalVariable local)slots[local]=Value(row.Operands[1]);
    else if(row.OpCode==OpCode.Return)return Value(row.Operands[0]);
    else if(row.OpCode==OpCode.CallVoid&&row.Operands[0] is Immediate {Value:0x111}&&row.Operands[1] is AddressOf {Target:LocalVariable addressed})slots[addressed]=values.Item2;
    else if(row.OpCode==OpCode.CallVoid&&row.Operands[0] is Immediate {Value:0x222})memory[values.Item1+16]=values.Item4;
    else if(row.OpCode==OpCode.Jump){next=(Block)row.Operands[0];break;}
    else if(row.OpCode==OpCode.ConditionalJump){var target=(Block)row.Operands[0];next=Value(row.Operands[1])!=0?target:current.Successors.Single(b=>!ReferenceEquals(b,target));break;}
    else throw new NotSupportedException(row.ToString());
   }
   current=next??current.Successors.Single();
  }
  throw new InvalidDataException("Fixture did not terminate");
 }
 string Snapshot()=>string.Join("\n",graph.Blocks.Select(b=>b.ToString()));string beforeGraph=Snapshot();
 foreach(var b in graph.Blocks){if(b.Successors.Any(n=>!graph.Blocks.Contains(n)||n.Predecessors.Count(p=>ReferenceEquals(p,b))!=1)||b.Predecessors.Any(p=>!graph.Blocks.Contains(p)||p.Successors.Count(n=>ReferenceEquals(n,b))!=1))throw new InvalidDataException("Invalid input fixture topology");}
 long before=Execute(graph);
 var owner=(MethodAnalysisContext)RuntimeHelpers.GetUninitializedObject(typeof(MethodAnalysisContext));owner.ControlFlowGraph=graph;owner.Locals=[source,other,copy,result,condition];owner.ParameterLocals=[source,other,condition];
 Simplifier.Simplify(owner);long after=Execute(graph);bool pass=before==after;if(!pass)failures++;total++;
 cases.Add(new{mode,input_source=values.Item1,input_other=values.Item2,before,after,passed=pass,before_graph=beforeGraph,after_graph=Snapshot()});
}
string core=typeof(Simplifier).Assembly.Location;var report=new{status=failures==0?"PASS_BOUNDED_COPY_FORWARDING_AND_READ_ORDER_FIXTURES":"BOUNDED_COPY_FORWARDING_OR_READ_ORDER_FAILURE",label,total,failures,cases,core_sha256=Hash(core),probe_source_sha256=Hash(Guard("src/re/CopyForwardingSafetyProbe/Program.cs")),game_methods_executed=0,game_metadata_loaded=false,scope="Actual Simplifier.Simplify on real minimal ISIL/CFG/local objects; independent bounded interpreter compares original and transformed fixtures. Both branch paths, captured source reassignment, supplied byref write, and supplied memory-write boundary are tested. No game/native helper parity, full pipeline or full source recovery is claimed."};
string output=Guard($"reports/copy-forwarding-safety-{label}.json");if(File.Exists(output))throw new IOException("Historical report must be preserved");File.WriteAllText(output,JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,label,total,failures,report.core_sha256,output}));return failures==0?0:2;
