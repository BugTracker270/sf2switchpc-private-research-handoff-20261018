using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;

if(args.Length is <1 or >2||args.Length==2&&args[1] is not ("--production" or "--production-v35" or "--production-v36" or "--production-v37" or "--proposal-expanded"))throw new ArgumentException("Verified USB root and optional --production/--production-v35/--production-v36/--production-v37/--proposal-expanded required");
bool production=args.Length==2&&args[1] is ("--production" or "--production-v35" or "--production-v36" or "--production-v37");
string reportLabel=args.Length==2&&args[1]=="--production-v37"?"v37":args.Length==2&&args[1]=="--production-v36"?"v36":args.Length==2&&args[1]=="--production-v35"?"v35":"v34";
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative){string path=Path.GetFullPath(Path.Combine(root,relative));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");return path;}
string Hash(string path){using var file=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant();}
string binary=Guard("unpacked/effective/exefs/main"),metadata=Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if(Hash(binary)!="94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"||Hash(metadata)!="f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85")throw new IOException("Original inputs differ");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));Cpp2IlApi.InitializeLibCpp2Il(binary,metadata,new UnityVersion(2018,1,9,UnityVersionType.Final,1));
var app=Cpp2IlApi.CurrentAppContext!;var klass=app.Assemblies.SelectMany(a=>a.Types).Single(t=>t.FullName=="BundlesUtil");var method=klass.Methods.Single(m=>m.Name=="GetAssetBundleSafe");
method.ConvertedIsil=app.InstructionSet.GetIsilFromMethod(method);method.ParameterOperands=app.InstructionSet.GetParameterOperandsFromMethod(method);method.ControlFlowGraph=new ISILControlFlowGraph(method.ConvertedIsil);
StackAnalyzer.Analyze(method);method.DominatorInfo=new DominatorInfo(method.ControlFlowGraph);SsaForm.Build(method);LocalVariables.CreateAll(method);FlagConditionRecovery.Run(method);DeadCodeEliminator.Run(method);MetadataResolver.ResolveAll(method);KeyFunctionRecovery.Run(method);
var graph=method.ControlFlowGraph!;var helper=app.GetOrCreateKeyFunctionAddresses().il2cpp_codegen_runtime_class_init;
var raw=graph.Instructions.Single(i=>i.OpCode==OpCode.Call&&i.Operands[0] is Immediate target&&target.UnsignedValue==helper&&i.Operands[2] is LocalVariable arg&&graph.Instructions.Any(d=>d.OpCode==OpCode.Phi&&ReferenceEquals(d.Destination,arg)));
var input=(LocalVariable)raw.Operands[2];var phi=graph.Instructions.Single(i=>ReferenceEquals(i.Destination,input));var phiOwner=graph.Blocks.Single(b=>b.Instructions.Contains(phi));
LocalVariables.ResolveTypesAndFields(method);
int checks=0;var fixtures=new List<object>();void Check(bool condition,string name){if(!condition)throw new Exception(name);checks++;}
Check(phi.OpCode==OpCode.Phi,"Actual raw class origin is not Phi");
string beforeGraph=string.Join("\n",graph.Blocks.Select(b=>b.ToString()));
var actual=new Proposal(graph,klass);Check(actual.Prove(input,raw),"Proposed edge-aware rule rejected actual identical class Phi: "+actual.Failure);
if(production)Check(raw.OpCode==OpCode.CallVoid&&raw.Operands is [MethodAnalysisContext{Name:"RunClassConstructor",IsVoid:true},TypeAnalysisContext exactClass]&&ReferenceEquals(exactClass,klass),"Actual Phi helper did not lower to the exact existing managed void contract");
else Check(raw.OpCode==OpCode.Call&&raw.Operands[0] is Immediate,"Read-only survey modified actual unresolved call");
Check(string.Join("\n",graph.Blocks.Select(b=>b.ToString()))==beforeGraph,"Proposal checker changed original graph");
var rawOwner=graph.Blocks.Single(b=>b.Instructions.Contains(raw));var reloads=rawOwner.Instructions.Skip(rawOwner.Instructions.IndexOf(raw)+1).Take(3).ToArray();
Check(reloads is [{OpCode:OpCode.Move,Operands:[_,TypeAnalysisContext reloadClass]}, {OpCode:OpCode.Move,Operands:[_,MemoryOperand{Addend:0xB8}]}, {OpCode:OpCode.Move,Operands:[_,FieldReference{Field.Name:"currentConfig"}]}]&&ReferenceEquals(reloadClass,klass),"Original post-initialization class/static-storage/currentConfig reloads differ");
var phiEdges=phiOwner.Predecessors.Select((pred,i)=>{var local=(LocalVariable)phi.Operands[i+1];var definitions=graph.Blocks.SelectMany(b=>b.Instructions.Select((instruction,index)=>(Block:b,Instruction:instruction,Position:index))).Where(r=>ReferenceEquals(r.Instruction.Destination,local)).ToArray();return new{source_index=i+1,predecessor=pred.ID,source=local.Name,definitions=definitions.Select(d=>new{block=d.Block.ID,position=d.Position,opcode=d.Instruction.OpCode.ToString(),root_type=d.Instruction.Operands.Count>1&&d.Instruction.Operands[1] is TypeAnalysisContext type?type.FullName:null,definition_dominates_predecessor=new DominatorInfo(graph).Dominates(d.Block,pred)}).ToArray()};}).ToArray();
var t=app.SystemTypes.SystemBooleanType;LocalVariable Local(string name)=>new(name,new Register(null,name),new RuntimeClassTypeAnalysisContext(t,t.DeclaringAssembly));
(ISILControlFlowGraph Graph,LocalVariable Left,LocalVariable Right,LocalVariable Merged,Instruction Phi,Instruction Use,Block Entry,Block LeftBlock,Block RightBlock,Block Merge) Diamond(){
    LocalVariable l=Local("left"),r=Local("right"),p=Local("merged");var entry=new Block{ID=0,BlockType=BlockType.Entry};var left=new Block{ID=1};var right=new Block{ID=2};var merge=new Block{ID=3};var exit=new Block{ID=4,BlockType=BlockType.Exit};
    void Edge(Block from,Block to){from.Successors.Add(to);to.Predecessors.Add(from);}Edge(entry,left);Edge(entry,right);Edge(left,merge);Edge(right,merge);Edge(merge,exit);
    left.Instructions.Add(new Instruction(1,OpCode.Move,l,t));right.Instructions.Add(new Instruction(2,OpCode.Move,r,t));var ph=new Instruction(-1,OpCode.Phi,p,l,r);var use=new Instruction(3,OpCode.CallVoid,new Immediate((long)helper),p);merge.Instructions.AddRange([ph,use]);
    var g=new ISILControlFlowGraph([]){Blocks=[entry,left,right,merge,exit],EntryBlock=entry,ExitBlock=exit};return(g,l,r,p,ph,use,entry,left,right,merge);
}
void Expect(string name,bool expected,Action<(ISILControlFlowGraph Graph,LocalVariable Left,LocalVariable Right,LocalVariable Merged,Instruction Phi,Instruction Use,Block Entry,Block LeftBlock,Block RightBlock,Block Merge)>? mutate=null){var f=Diamond();mutate?.Invoke(f);var p=new Proposal(f.Graph,t);bool result=p.Prove(f.Merged,f.Use);Check(result==expected,name+": "+p.Failure);if(production){var context=new InjectedMethodAnalysisContext(t,"PhiFixture"+fixtures.Count,app.SystemTypes.SystemVoidType,MethodAttributes.Public|MethodAttributes.Static,[]){ControlFlowGraph=f.Graph};bool lowered=KeyFunctionRecovery.RewriteLegacyClassInitializers(context);Check(lowered==expected,"Production exact-origin disagreement: "+name);Check(expected?f.Use.OpCode==OpCode.CallVoid&&f.Use.Operands[0] is MethodAnalysisContext{Name:"RunClassConstructor"}:f.Use.Operands[0] is Immediate,"Production changed unresolved identity or lost managed void request: "+name);}fixtures.Add(new{name,expected,accepted=result,rejection=p.Failure});}
Expect("two independent exact metadata roots",true);
Expect("same root reused across both incoming edges",true,f=>{var shared=Local("shared");f.Entry.Instructions.Add(new Instruction(0,OpCode.Move,shared,t));f.LeftBlock.Instructions[0].SetOperand(1,shared);f.RightBlock.Instructions[0].SetOperand(1,shared);});
Expect("conflicting original type identity despite matching propagated local type",false,f=>f.RightBlock.Instructions[0].SetOperand(1,app.SystemTypes.SystemInt32Type));
Expect("unknown incoming source",false,f=>f.RightBlock.Instructions[0].SetOperand(1,new Immediate(0)));
Expect("uninitialized incoming source",false,f=>f.RightBlock.Instructions.Clear());
Expect("duplicate incoming definition",false,f=>f.RightBlock.Instructions.Add(new Instruction(4,OpCode.Move,f.Right,t)));
Expect("swapped predecessor source positions",false,f=>f.Phi.SetOperands(f.Merged,f.Right,f.Left));
Expect("missing predecessor source",false,f=>f.Phi.RemoveOperandAt(2));
Expect("extra predecessor source",false,f=>f.Phi.AddOperands([f.Left]));
Expect("duplicate predecessor",false,f=>f.Merge.Predecessors[1]=f.LeftBlock);
Expect("asymmetric predecessor edge",false,f=>f.RightBlock.Successors.Clear());
Expect("predecessor outside graph",false,f=>{var outside=new Block{ID=999};outside.Successors.Add(f.Merge);f.Merge.Predecessors[1]=outside;});
Expect("incoming untyped local",false,f=>f.Right.Type=null);
Expect("incoming local assigned wrong represented class",false,f=>f.Right.Type=new RuntimeClassTypeAnalysisContext(app.SystemTypes.SystemInt32Type,t.DeclaringAssembly));
Expect("Phi placed after an ordinary instruction",false,f=>f.Merge.Instructions.Insert(0,new Instruction(7,OpCode.Move,Local("ordinary"),t)));
Expect("class local address escapes",false,f=>f.LeftBlock.Instructions.Add(new Instruction(8,OpCode.Move,new LocalVariable("sink",new Register(null,"sink")),new AddressOf(f.Left))));
Expect("merge Phi defined after call",false,f=>{f.Merge.Instructions.Clear();f.Merge.Instructions.AddRange([f.Use,f.Phi]);});
Expect("repeated false typing result is not cached across passes",true,f=>{f.Right.Type=null;var p=new Proposal(f.Graph,t);Check(!p.Prove(f.Merged,f.Use),"Unknown before-fixpoint source accepted");f.Right.Type=new RuntimeClassTypeAnalysisContext(t,t.DeclaringAssembly);});
foreach(var count in new[]{29,30})Expect("distinct local budget with "+count+" shared chain nodes",count==29,f=>{LocalVariable? previous=null;for(int i=0;i<count;i++){var current=Local("chain"+i);f.Entry.Instructions.Add(new Instruction(10+i,OpCode.Move,current,previous is null?t:previous));previous=current;}f.LeftBlock.Instructions[0].SetOperand(1,previous!);f.RightBlock.Instructions[0].SetOperand(1,previous!);});
var loop=Diamond();loop.Entry.Successors.Clear();loop.LeftBlock.Predecessors.Clear();loop.RightBlock.Predecessors.Clear();loop.LeftBlock.Successors.Clear();loop.RightBlock.Successors.Clear();loop.Merge.Predecessors.Clear();loop.Merge.Successors.Clear();var entryValue=Local("entryClass");loop.Entry.Instructions.Add(new Instruction(0,OpCode.Move,entryValue,t));
loop.Entry.Successors.Add(loop.Merge);loop.Merge.Predecessors.Add(loop.Entry);loop.Merge.Successors.Add(loop.LeftBlock);loop.LeftBlock.Predecessors.Add(loop.Merge);loop.LeftBlock.Successors.Add(loop.Merge);loop.Merge.Predecessors.Add(loop.LeftBlock);loop.LeftBlock.Instructions[0].SetOperands(loop.Left,loop.Merged);loop.Phi.SetOperands(loop.Merged,entryValue,loop.Left);loop.Graph.Blocks.Remove(loop.RightBlock);loop.Graph.ExitBlock.Predecessors.Clear();
var cyclic=new Proposal(loop.Graph,t);Check(!cyclic.Prove(loop.Merged,loop.Use)&&cyclic.Failure=="cyclic-origin","Origin dependency cycle was not rejected");fixtures.Add(new{name="loop-carried origin dependency cycle",expected=false,accepted=false,rejection=cyclic.Failure});
if(production){var loopContext=new InjectedMethodAnalysisContext(t,"OriginCycle",app.SystemTypes.SystemVoidType,MethodAttributes.Public|MethodAttributes.Static,[]){ControlFlowGraph=loop.Graph};Check(!KeyFunctionRecovery.RewriteLegacyClassInitializers(loopContext),"Production origin dependency cycle accepted");}
foreach(var depth in new[]{3,9}){
    var entry=new Block{ID=0,BlockType=BlockType.Entry};var exit=new Block{ID=1,BlockType=BlockType.Exit};var blocks=new List<Block>{entry,exit};var previous=Local("dagRoot");entry.Instructions.Add(new Instruction(0,OpCode.Move,previous,t));var prior=entry;
    void Edge(Block from,Block to){from.Successors.Add(to);to.Predecessors.Add(from);}
    for(int level=0;level<depth;level++){var left=new Block{ID=blocks.Count};var right=new Block{ID=blocks.Count+1};var merge=new Block{ID=blocks.Count+2};blocks.AddRange([left,right,merge]);Edge(prior,left);Edge(prior,right);Edge(left,merge);Edge(right,merge);var current=Local("dag"+level);merge.Instructions.Add(new Instruction(-1,OpCode.Phi,current,previous,previous));previous=current;prior=merge;}
    Edge(prior,exit);var use=new Instruction(100,OpCode.CallVoid,new Immediate((long)helper),previous);prior.Instructions.Add(use);var dag=new ISILControlFlowGraph([]){Blocks=blocks,EntryBlock=entry,ExitBlock=exit};var proof=new Proposal(dag,t);bool accepted=proof.Prove(previous,use),expected=depth==3;Check(accepted==expected,"Shared Phi DAG visit-budget result differs");if(!expected)Check(proof.Failure=="origin-visit-budget","Shared Phi DAG did not fail at total-work bound");
    if(production){var context=new InjectedMethodAnalysisContext(t,"SharedPhiDag"+depth,app.SystemTypes.SystemVoidType,MethodAttributes.Public|MethodAttributes.Static,[]){ControlFlowGraph=dag};Check(KeyFunctionRecovery.RewriteLegacyClassInitializers(context)==expected,"Production shared Phi DAG visit-budget result differs");}
    fixtures.Add(new{name="shared acyclic Phi DAG depth"+depth,expected,accepted,rejection=proof.Failure});
}
var report=new{status=production?"PASS_PRODUCTION_EDGE_AWARE_CLASS_METADATA_PHI_LOWERING":"PASS_READ_ONLY_EDGE_AWARE_CLASS_METADATA_PHI_PROPOSAL",checks,actual_method=method.FullName,actual_raw_call_index=raw.Index,actual_phi_block=phiOwner.ID,actual_phi_destination=input.Name,actual_phi_edges=phiEdges,actual_proposed_identity_proof=true,actual_call_stays_unresolved=!production,production_lowering=production,fixtures,
    original_post_cctor_reload_indices=reloads.Select(i=>i.Index).ToArray(),proposal_checker_left_graph_unchanged=true,
    remaining_runtime_class_flag_loads=graph.Instructions.Sum(i=>i.Operands.OfType<MemoryOperand>().Count(m=>m.Base is LocalVariable{Type:RuntimeClassTypeAnalysisContext}&&m.Addend is 0x122 or 0xD4)),
    proposed_production_location="KeyFunctionRecovery.HasExactClassMetadataOrigin only; retain existing target/ABI/unused-result/closed-type/API-overload gates.",
    proposed_rules=new[]{"Fresh dominance for the current immutable CFG pass; reachable reciprocal unique edges, unique SSA definition and available definition at each use.","Move roots must end at the same original represented TypeAnalysisContext object. Propagated names or RuntimeClass<T> alone do not prove identity.","Phi operand i+1 is checked at Block.Predecessors[i] end, with exact arity and entry-prefix placement; do not require conditional source definitions to dominate the merge.","Separate active recursion path,32-distinct-local budget and256-total-visit budget: cycles/unknowns/escapes reject, small identical shared roots may pass, excessive shared-DAG traversal fails closed. No false-result cache survives type-fixpoint iterations.","Only class identity proof changes; preserve all post-cctor field reloads, branches, fields, original call position and initialization effects."},
    core_sha256=Hash(typeof(KeyFunctionRecovery).Assembly.Location),binary_sha256=Hash(binary),metadata_sha256=Hash(metadata),
    scope=production?"The actual production type fixpoint lowers the previously unresolved original Phi helper to the exact existing managed void class-constructor contract. Original post-cctor class/static-storage/currentConfig reload instructions remain unchanged; no CFG branch is edited. Production lowering is also tested on independent positive/negative ISIL fixtures, with an independent edge-aware identity checker. No emitted recovered DLL/CIL execution, original class-constructor parity, whole-caller execution, source compilation or full-decompilation claim is made here.":"Independent proposal checker reads the current production CFG without changing Core or recovered output. It verifies exact original metadata type identity on every positionally mapped Phi predecessor edge, bounded acyclic origin dependencies, fresh dominance and strict source availability. Actual helper remains unresolved; all original post-cctor field reloads/control flow remain untouched. This is a proposed recovery rule and fixture evidence, not production acceptance, emitted CIL/runtime or full-decompilation proof."};
File.WriteAllText(Guard(production?$"reports/class-metadata-phi-production-{reportLabel}.json":args.Length==2?"reports/class-metadata-phi-proposal-v34-expanded.json":"reports/class-metadata-phi-proposal-v34.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,checks,actual_phi_edges=phiEdges}));

sealed class Proposal(ISILControlFlowGraph graph,TypeAnalysisContext type){
    DominatorInfo? dominance;int visits;readonly HashSet<LocalVariable> active=[],distinct=[];readonly HashSet<Block> reachable=Reachable(graph.EntryBlock);public string? Failure;
    static HashSet<Block> Reachable(Block start){var seen=new HashSet<Block>();var work=new Queue<Block>();work.Enqueue(start);while(work.Count>0){var b=work.Dequeue();if(seen.Add(b))foreach(var s in b.Successors)work.Enqueue(s);}return seen;}
    bool Fail(string reason){Failure??=reason;return false;}
    public bool Prove(LocalVariable local,Instruction use){if(graph.Blocks.Distinct().Count()!=graph.Blocks.Count||!graph.Blocks.Contains(graph.EntryBlock))return Fail("malformed-graph-blocks");foreach(var b in graph.Blocks){if(!reachable.Contains(b)&&!ReferenceEquals(b,graph.ExitBlock)||b.Predecessors.Distinct().Count()!=b.Predecessors.Count||b.Successors.Distinct().Count()!=b.Successors.Count)return Fail("malformed-reachable-topology");foreach(var p in b.Predecessors)if(!graph.Blocks.Contains(p)||reachable.Contains(b)&&!reachable.Contains(p)||p.Successors.Count(s=>ReferenceEquals(s,b))!=1)return Fail("unreachable-or-asymmetric-predecessor");foreach(var s in b.Successors)if(!graph.Blocks.Contains(s)||s.Predecessors.Count(p=>ReferenceEquals(p,b))!=1)return Fail("asymmetric-successor");}if(reachable.Any(b=>!graph.Blocks.Contains(b)))return Fail("reachable-block-outside-graph");var owner=graph.Blocks.Where(b=>b.Instructions.Contains(use)).ToArray();return owner.Length==1&&At(local,owner[0],owner[0].Instructions.IndexOf(use));}
    bool At(LocalVariable local,Block useBlock,int usePosition){
        if(++visits>256)return Fail("origin-visit-budget");
        if(local.Type is not RuntimeClassTypeAnalysisContext klass||!ReferenceEquals(klass.RepresentedType,type))return Fail("untyped-or-conflicting-runtime-class");
        if(!distinct.Add(local)&&active.Contains(local))return Fail("cyclic-origin");if(distinct.Count>32)return Fail("origin-budget");
        var defs=graph.Blocks.SelectMany(b=>b.Instructions.Select((i,n)=>(Block:b,Instruction:i,Position:n))).Where(d=>ReferenceEquals(d.Instruction.Destination,local)).ToArray();
        if(defs.Length!=1)return Fail("missing-or-multiple-definitions");var d=defs[0];if(!reachable.Contains(d.Block)||!reachable.Contains(useBlock))return Fail("unreachable-origin-or-use");
        if(d.Block==useBlock?d.Position>=usePosition:!(dominance??=new DominatorInfo(graph)).Dominates(d.Block,useBlock))return Fail("definition-unavailable-at-edge-or-use");
        if(graph.Blocks.SelectMany(b=>b.Instructions).Any(i=>i.Operands.Any(o=>Escapes(o,local))))return Fail("class-local-address-escapes");
        active.Add(local);bool result;
        if(d.Instruction is{OpCode:OpCode.Move,Operands:[_,var source]})result=source is TypeAnalysisContext exact?ReferenceEquals(exact,type)||Fail("conflicting-original-type-identity"):source is LocalVariable copy?At(copy,d.Block,d.Position):Fail("unknown-origin");
        else if(d.Instruction.OpCode==OpCode.Phi){
            var preds=d.Block.Predecessors;var operands=d.Instruction.Operands;
            if(preds.Count<2||operands.Count!=preds.Count+1||preds.Distinct().Count()!=preds.Count)result=Fail("malformed-phi-predecessor-arity");
            else if(d.Block.Instructions.Take(d.Position).Any(i=>i.OpCode is not(OpCode.Phi or OpCode.Nop)))result=Fail("phi-not-in-entry-prefix");
            else {result=true;for(int i=0;i<preds.Count&&result;i++){var pred=preds[i];if(!reachable.Contains(pred)||!graph.Blocks.Contains(pred)||pred.Successors.Count(s=>ReferenceEquals(s,d.Block))!=1)result=Fail("unreachable-or-asymmetric-predecessor");else result=operands[i+1] is LocalVariable incoming?At(incoming,pred,pred.Instructions.Count):Fail("nonlocal-phi-source");}}
        }else result=Fail("unsupported-origin-definition");
        active.Remove(local);return result;
    }
    static bool Escapes(IOperand operand,LocalVariable local)=>operand switch{AddressOf{Target:LocalVariable l}=>ReferenceEquals(l,local),AddressOf a=>Escapes(a.Target,local),ArrayAccess a=>Escapes(a.Index,local),MemoryOperand m=>(m.Base!=null&&Escapes(m.Base,local))||(m.Index!=null&&Escapes(m.Index,local)),_=>false};
}
