using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.OutputFormats;
using Cpp2IL.Core.Utils;
using Cpp2IL.Core.Utils.AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;

if(args.Length!=1)throw new ArgumentException("USB root required");string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative){string p=Path.GetFullPath(Path.Combine(root,relative));if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside USB");for(DirectoryInfo?d=new(Path.GetDirectoryName(p)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse");return p;}
string Hash(string relative)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Guard(relative)))).ToLowerInvariant();
var checks=new List<object>();var stages=new List<object>();var otherCallers=new List<object>();object?classInputEmission=null;string?fatal=null;string core=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(typeof(Cpp2IlApi).Assembly.Location))).ToLowerInvariant();
void Check(string name,bool passed){checks.Add(new{name,passed});if(!passed)throw new InvalidDataException(name);}
try{
 Check("exact stable40 Core",core=="14232d46ca291ffb67944705e94ec5460bc8ee70c3df88ee3ef27e77b6e736d6");
 Check("original input identities",Hash("unpacked/effective/exefs/main")=="94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"&&Hash("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat")=="f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85");
 using var baseline=JsonDocument.Parse(File.ReadAllText(Guard("reports/object-isinst-actual-ir-v38.json")));
 Check("immutable38 baseline28calls all raw18 and discovery0",baseline.RootElement.GetProperty("methods")[0].GetProperty("numeric_isinst_calls").GetInt32()==28&&baseline.RootElement.GetProperty("methods")[0].GetProperty("helper_operand_counts").EnumerateArray().All(x=>x.GetInt32()==18)&&baseline.RootElement.GetProperty("discovered_object_is_inst").GetString()=="0x0");
 Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));Cpp2IlApi.InitializeLibCpp2Il(Guard("unpacked/effective/exefs/main"),Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat"),new UnityVersion(2018,1,9,UnityVersionType.Final,1));
 var app=Cpp2IlApi.CurrentAppContext!;var types=app.Assemblies.SelectMany(a=>a.Types).ToArray();var method=types.Single(t=>t.FullName=="InControl.PlayStation4MacBTProfile").Methods.Single(m=>m.Name==".ctor");
 Check("reviewed helper recognized before generic alias selection",LegacyArm64ObjectIsInstAbi.IsKnownTarget(app,0xB5B390));
 Check("old discovery remains0 and original target has no managed aliases",app.GetOrCreateKeyFunctionAddresses().il2cpp_vm_object_is_inst==0&&!app.MethodsByAddress.ContainsKey(0xB5B390));
 method.ConvertedIsil=app.InstructionSet.GetIsilFromMethod(method);method.ParameterOperands=app.InstructionSet.GetParameterOperandsFromMethod(method);
 var raw=method.ConvertedIsil.Where(i=>i.NativeObjectIsInstAbi!=null).ToArray();
 Check("all28 raw native calls capture exact target/result/X0/X1 only",raw.Length==28&&raw.All(i=>i.OpCode==OpCode.Call&&i.Operands is[Immediate n,Register{Name:"X0"},Register{Name:"X0"},Register{Name:"X1"}]&&n.UnsignedValue==0xB5B390));
 int[] originalIndices=raw.Select(i=>i.Index).ToArray();
 method.ControlFlowGraph=new ISILControlFlowGraph(method.ConvertedIsil);StackAnalyzer.Analyze(method);method.DominatorInfo=new DominatorInfo(method.ControlFlowGraph);SsaForm.Build(method);LocalVariables.CreateAll(method);
 int seed=LegacyArm64ObjectIsInstAbi.SeedResults(method);LegacyArm64ClassLayoutAbi.SeedResults(method);LegacyArm64OverflowExceptionAbi.SeedResults(method);
 Check("all28 SSA results seeded canonicalObject with distinct original X0 input",seed==28&&method.ControlFlowGraph.Instructions.Where(i=>i.NativeObjectIsInstAbi!=null).All(i=>i.Operands[1]is LocalVariable result&&i.Operands[2]is LocalVariable original&&!ReferenceEquals(result,original)&&ReferenceEquals(result.Type,app.SystemTypes.SystemObjectType)));
 FlagConditionRecovery.Run(method);DeadCodeEliminator.Run(method);MetadataResolver.ResolveAll(method);KeyFunctionRecovery.Run(method);DeadCodeEliminator.Run(method);MetadataInitGuardRemover.Run(method);WriteBarrierRecovery.Run(method);InjectedCheckRemover.Run(method);InterfaceDispatchRecovery.Run(method);LocalVariables.ResolveTypesAndFields(method);
 void Snapshot(string stage){
  var rows=method.ControlFlowGraph!.Instructions.ToArray();var calls=rows.Where(i=>i.NativeObjectIsInstAbi!=null).ToArray();
  string privatePath=$"analysis/reconstruction/object-isinst-v40/profile-{stage}.txt";Directory.CreateDirectory(Path.GetDirectoryName(Guard(privatePath))!);File.WriteAllText(Guard(privatePath),string.Join("\n",method.ControlFlowGraph.Blocks.Select(b=>b.ToString()))+"\n");
  Check(stage+" all28 calls retain numeric target/original index/fouroperand ABI/Object results",calls.Length==28&&calls.Select(i=>i.Index).Order().SequenceEqual(originalIndices.Order())&&calls.All(i=>i.Operands.Count==4&&LegacyArm64ObjectIsInstAbi.ValidForEmission(i,method)));
  var defs=rows.Where(i=>i.Destination is LocalVariable).GroupBy(i=>(LocalVariable)i.Destination!).ToDictionary(g=>g.Key,g=>g.ToArray());
  MemoryOperand? Load(IOperand operand,long offset){var visited=new HashSet<LocalVariable>();for(int depth=0;depth<32;depth++){if(operand is MemoryOperand m)return m.Addend==offset&&m.Index==null&&m.Scale==0?m:null;if(operand is not LocalVariable local||!visited.Add(local)||!defs.TryGetValue(local,out var ds)||ds.Length!=1||ds[0].OpCode!=OpCode.Move||ds[0].Operands.Count!=2)return null;operand=ds[0].Operands[1];}return null;}
  int projected=0,unknownClasses=0;foreach(var call in calls){var element=Load(call.Operands[3],0x40);var klass=element is{}e&&e.Base!=null?Load(e.Base,0):null;if(klass is{Base:LocalVariable{Type:SzArrayTypeAnalysisContext}})projected++;if(call.Operands[3]is LocalVariable{Type:null})unknownClasses++;}
  Check(stage+" all28 real runtime-array klass/element-class chains preserved",projected==28);
  var first=calls.Single(i=>i.Index==63);var firstResult=(LocalVariable)first.Operands[1];var firstObject=first.Operands[2];
  IOperand? OriginalSource(IOperand operand){var seen=new HashSet<LocalVariable>();for(int depth=0;depth<32&&operand is LocalVariable local&&seen.Add(local);depth++){if(!defs.TryGetValue(local,out var ds)||ds.Length!=1||ds[0].OpCode!=OpCode.Move||ds[0].Operands.Count!=2)return operand;operand=ds[0].Operands[1];}return operand;}
  Check(stage+" first original string object source and result remain distinct",OriginalSource(firstObject) is StringLiteral{Value:"OS X"}&&!ReferenceEquals(firstObject,firstResult));
  var firstBlock=method.ControlFlowGraph.Blocks.Single(b=>b.Instructions.Contains(first));int place=firstBlock.Instructions.IndexOf(first);
  Check(stage+" returned Object/null check immediately follows original helper",firstBlock.Instructions.Skip(place+1).Any(i=>i.OpCode is OpCode.CheckEqual or OpCode.CheckNotEqual&&i.Operands.Skip(1).Any(o=>ReferenceEquals(o,firstResult)))&&firstBlock.Instructions.Skip(place+1).Any(i=>i.OpCode==OpCode.ConditionalJump&&i.Index==65));
  var originalElement=Load(first.Operands[3],0x40);var originalKlass=originalElement is{}oe&&oe.Base!=null?Load(oe.Base,0):null;
  var array=originalKlass?.Base as LocalVariable;
  bool SameArray(LocalVariable candidate)=>array!=null&&ReferenceEquals(OriginalSource(candidate),OriginalSource(array));
  bool preservedBounds=rows.Any(i=>i.Index==67&&i.OpCode==OpCode.Move&&i.Operands[1]is MemoryOperand{Addend:0x18,Index:null,Scale:0,Base:LocalVariable a}&&SameArray(a))
      ||rows.Any(i=>i.Index==68&&i.OpCode==OpCode.CheckEqual&&i.Operands.Skip(1).Any(o=>o is ArrayLength length&&SameArray(length.Array)));
  bool preservedStore=rows.Any(i=>i.Index==75&&i.OpCode==OpCode.Move&&(i.Operands[0]is MemoryOperand{Addend:0x20,Index:null,Scale:0,Base:LocalVariable a}&&SameArray(a)
      ||i.Operands[0]is ArrayAccess{Array:var a2,Index:Immediate index}&&index.Value==0&&SameArray(a2)));
  Check(stage+" same original runtime array feeds element-class, preserved bounds and original element store",array?.Type is SzArrayTypeAnalysisContext{ElementType:{FullName:"System.String"}}&&preservedBounds&&preservedStore);
  var nullCheck=rows.Single(i=>i.Index==64);var nullBranch=rows.Single(i=>i.Index==65);var store=rows.Single(i=>i.Index==75);
  Check(stage+" original null comparison is exact result==0 and true edge still reaches ArrayTypeMismatch throw",nullCheck.OpCode==OpCode.CheckEqual&&ReferenceEquals(nullCheck.Operands[1],firstResult)&&nullCheck.Operands[2]is Immediate zero&&zero.Value==0&&nullBranch.OpCode==OpCode.ConditionalJump&&ReferenceEquals(nullBranch.Operands[1],nullCheck.Destination)&&nullBranch.Operands[0]is Block failure&&failure.Instructions.Any(i=>i.OpCode==OpCode.Newobj&&i.Operands[1]is TypeAnalysisContext{FullName:"System.ArrayTypeMismatchException"})&&failure.Instructions.Last().OpCode==OpCode.Throw);
  var boundsBlock=method.ControlFlowGraph.Blocks.Single(b=>b.Instructions.Any(i=>i.Index==68));
  Check(stage+" original type-test block falls through to bounds only after its failure edge",firstBlock.Successors.Contains(boundsBlock)&&!firstBlock.Instructions.Any(i=>i.Index is 67 or 68 or 75)&&firstBlock.Instructions.IndexOf(nullCheck)>place&&firstBlock.Instructions.IndexOf(nullBranch)>firstBlock.Instructions.IndexOf(nullCheck));
  int valueVisits=0;var activeValues=new HashSet<LocalVariable>();
  bool OnlyOriginalString(IOperand value){if(++valueVisits>256)return false;if(value is StringLiteral literal)return literal.Value=="OS X";if(value is not LocalVariable local||!activeValues.Add(local)||!defs.TryGetValue(local,out var definitions))return false;try{return definitions.All(d=>d.OpCode==OpCode.Move&&d.Operands.Count==2&&OnlyOriginalString(d.Operands[1])||d.OpCode==OpCode.Phi&&d.Operands.Skip(1).All(OnlyOriginalString));}finally{activeValues.Remove(local);}}
  Check(stage+" original first store keeps exact index0 and OS X value along all local/Phi definitions",OnlyOriginalString(store.Operands[1]));
  if(stage=="emitter-input")Check("known ArrayRecovery inlines original row67 into row68 ArrayLength without changing its array identity",!rows.Any(i=>i.Index==67)&&rows.Any(i=>i.Index==68&&i.Operands.Any(o=>o is ArrayLength length&&SameArray(length.Array))));
  stages.Add(new{stage,calls=calls.Length,operand_counts=calls.Select(i=>i.Operands.Count).Distinct().ToArray(),dynamic_array_class_projections=projected,untyped_original_class_locals=unknownClasses,private_graph=privatePath,private_graph_sha256=Hash(privatePath)});
 }
 Snapshot("after-type");
 MetadataInitGuardRemover.RunRgctx(method);MetadataInitGuardRemover.RewriteUnguardedInits(method);DelegateInvokeRecovery.Run(method);BooleanFlagSimplifier.Run(method);DeadCodeEliminator.Run(method);SsaSimplifier.Run(method);for(int i=0;i<8&&ConstantFolder.Run(method);i++)SsaSimplifier.Run(method);Snapshot("simplified-ssa");
 InternalCallGuardRemover.Run(method);KeyFunctionRecovery.Run(method);SsaForm.Remove(method);CopyCoalescer.Run(method);Simplifier.Simplify(method);FloatLiteralRecovery.Run(method);ArrayRecovery.Run(method);LocalVariables.TypeAddressedLocals(method);ConstantBranchFolder.Run(method);EqualityBranchInverter.Run(method);CallArgumentTrimmer.Run(method);DeadCodeEliminator.Run(method);LocalVariables.RemoveUnused(method);Snapshot("emitter-input");
 foreach(var spec in new[]{(Name:"get_swapper",Rva:0x6EA510UL,Calls:3),(Name:"int_swapper",Rva:0x6EC200UL,Calls:1),(Name:"obj_swapper",Rva:0x6EC310UL,Calls:3),(Name:"double_swapper",Rva:0x6EC4F0UL,Calls:1),(Name:"compare",Rva:0x6EC650UL,Calls:1)}){
  var other=types.Single(t=>t.FullName=="System.Array").Methods.Single(m=>m.Name==spec.Name&&m.UnderlyingPointer==spec.Rva);other.Analyze();var calls=other.ControlFlowGraph!.Instructions.Where(i=>i.NativeObjectIsInstAbi!=null).ToArray();
  Check("broader original System.Array caller retains exact numeric ABI: "+spec.Name,calls.Length==spec.Calls&&calls.All(i=>i.Operands.Count==4&&LegacyArm64ObjectIsInstAbi.ValidForEmission(i,other)));
  string privatePath=$"analysis/reconstruction/object-isinst-v40/Array-{spec.Name}-emitter-input.txt";File.WriteAllText(Guard(privatePath),string.Join("\n",other.ControlFlowGraph.Blocks.Select(b=>b.ToString()))+"\n");otherCallers.Add(new{owner="System.Array",method=spec.Name,original_rva="0x"+spec.Rva.ToString("X"),numeric_helper_calls=calls.Length,all_object_results=true,private_graph=privatePath,private_graph_sha256=Hash(privatePath)});
 }
 IlGenerator.InjectHelpersType(app);var stub=typeof(AsmResolverDllOutputFormat).GetMethod("BuildStubAssemblies",BindingFlags.NonPublic|BindingFlags.Instance)!;stub.Invoke(new AsmResolverDllOutputFormatEmpty(),[app]);foreach(var a in app.Assemblies)AsmResolverAssemblyPopulator.ConfigureHierarchy(a);foreach(var a in app.Assemblies)AsmResolverAssemblyPopulator.CopyDataFromIl2CppToManaged(a);
 var definition=method.GetExtraData<MethodDefinition>("AsmResolverMethod")!;IlGenerator.GenerateIl(method,definition);var il=definition.CilMethodBody!.Instructions;
 Check("actual original constructor emission retains all28 unresolved numeric diagnostics",il.Count(i=>i.OpCode==CilOpCodes.Ldstr&&i.Operand?.ToString()=="Method not found @B5B390")==28);
 Check("actual original constructor introduces no CIL isinst semantic lowering",!il.Any(i=>i.OpCode==CilOpCodes.Isinst));
 const string baselineAssembly="analysis/il2cpp/cpp2il-recovery-nso-virtual-companion-copy-v38/Assembly-CSharp.dll";
 var oldModule=ModuleDefinition.FromFile(Guard(baselineAssembly));var oldCtor=oldModule.GetAllTypes().Single(t=>t.FullName=="InControl.PlayStation4MacBTProfile").Methods.Single(m=>m.Name==".ctor");var oldIl=oldCtor.CilMethodBody!.Instructions;
 int OldHelperCount()=>oldIl.Count(i=>i.OpCode==CilOpCodes.Ldstr&&i.Operand?.ToString()=="Method not found @B5B390");
 int ClassLoadCount(IEnumerable<AsmResolver.PE.DotNet.Cil.CilInstruction> rows)=>rows.Count(i=>i.OpCode==CilOpCodes.Ldstr&&i.Operand?.ToString()?.Contains("Unmanaged memory load:",StringComparison.Ordinal)==true&&i.Operand.ToString()!.Contains("+40]",StringComparison.Ordinal));
 int beforeClass=ClassLoadCount(oldIl),afterClass=ClassLoadCount(il);
 Check("original complete38 CIL already had28 unresolved helper diagnostics and no inline class-input diagnostic",OldHelperCount()==28&&beforeClass==0);
 Check("ABI-only40 does not claim class-input evaluation restored by numeric diagnostic emission",afterClass==0);
 classInputEmission=new{baseline_assembly=baselineAssembly,baseline_assembly_sha256=Hash(baselineAssembly),original_method_token=oldCtor.MetadataToken.ToString(),before_helper_diagnostic_count=OldHelperCount(),before_inline_class_input_diagnostic_count=beforeClass,after_helper_diagnostic_count=28,after_inline_class_input_diagnostic_count=afterClass,original_ir_class_projection_retained=true,emitted_class_input_evaluation_recovered=false,emitted_helper_return_semantics_recovered=false,explanation="Existing unknown numeric-call emitter does not evaluate argument operands. The exact dynamic class+40 operand is retained in IR but inline argument evaluation is omitted in emitted diagnostic CIL, as it was in complete38 output. Numeric diagnostics and nominal Object typing provide no executable helper/class-effect semantics."};
}
catch(Exception error){fatal=error.ToString();}
string status=fatal==null?"PASS_ORIGINAL_ISINST_ABI_ONLY_PRODUCTION_DATAFLOW_AND_DIAGNOSTICS":"OBJECT_ISINST_PRODUCTION_GATE_FAILED";
var report=new{status,checks=checks.Count,tests=checks,stages,other_callers=otherCallers,class_input_emission=classInputEmission,fatal,core_sha256=core,source_sha256=Hash("src/re/ObjectIsInstProductionProbe/Program.cs"),helper_source_sha256=Hash("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64ObjectIsInstAbi.cs"),baseline_report_sha256=Hash("reports/object-isinst-actual-ir-v38.json"),native_source_proposal_sha256=Hash("reports/object-isinst-native-source-proposal-v40.json"),original_constructor_rva="0x11A4CC0",before_calls=28,before_raw_operand_count=18,expected_after_calls=28,expected_after_operand_count=4,original_game_methods_invoked=0,native_functions_executed=0,semantic_isinst_recovered=false,production_outputs_written=false,full_clean_decompile_ready=false,scope="Original constructor native/metadata analysis through existing production SSA/type/simplification/emitter stages, then real IlGenerator in-memory only. Exact numeric ABI capture shrinks28x18 to28x4; real X1 runtime array klass+40 inputs and returned-object/null checks before original same-array bounds/index0/OS X store remain in IR. All28 unresolved helper diagnostics persist. Five original System.Array callers preserve the same exact ABI. Existing numeric-call CIL omits argument evaluation, so class-input/helper-return semantics remain explicitly unresolved just as in baseline38. No game constructor execution, managed isinst, array-store translation or restored class-effect claim is made."};
File.WriteAllText(Guard("reports/object-isinst-abi-production-v40.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{status,checks=checks.Count,fatal}));return fatal==null?0:2;
