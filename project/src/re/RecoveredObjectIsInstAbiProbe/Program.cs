using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Reflection.PortableExecutable;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.Metadata;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using MethodDefinition = AsmResolver.DotNet.MethodDefinition;
using ModuleDefinition = AsmResolver.DotNet.ModuleDefinition;

if(args.Length is <1 or >2)throw new ArgumentException("USB root [--baseline] required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
bool baselineOnly=args.Length==2&&args[1]=="--baseline";
bool inspectOnly=args.Length==2&&args[1]=="--inspect";
const string before="nso-assembly-leaf-getter-v39",after="nso-object-isinst-abi-v40",expectedCore="14232d46ca291ffb67944705e94ec5460bc8ee70c3df88ee3ef27e77b6e736d6";
string Guard(string relative){string p=Path.GetFullPath(Path.Combine(root,relative));if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside USB");for(DirectoryInfo? d=new(Path.GetDirectoryName(p)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse");return p;}
string Hash(string relative)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Guard(relative)))).ToLowerInvariant();
string Digest(string value)=>Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
var tests=new List<object>();var observations=new List<object>();var details=new List<object>();var diagnosticHelpers=new List<object>();string? fatal=null;object? constructorAlignment=null;object? implicitResults=null;
void Check(string name,bool pass){tests.Add(new{name,passed=pass});if(!pass)throw new InvalidDataException(name);}
var infrastructure=Assembly.LoadFrom(Guard("src/re/RecoveredAssemblyLeafProbe/bin/Release/net10.0/RecoveredAssemblyLeafProbe.dll"));
var helper=infrastructure.GetType("Program",true)!;
var normalizer=helper.GetMethods(BindingFlags.Static|BindingFlags.NonPublic).Single(m=>m.Name.Contains("g__Normalize|",StringComparison.Ordinal));
var shape=helper.GetMethods(BindingFlags.Static|BindingFlags.NonPublic).Single(m=>m.Name.Contains("g__Shape|",StringComparison.Ordinal));
List<string> Normalize(MethodDefinition m)=>(List<string>)normalizer.Invoke(null,[m])!;
string Shape(MethodDefinition m)=>(string)shape.Invoke(null,[m])!;
var modules=new Dictionary<(string,string),ModuleDefinition>();
ModuleDefinition Module(string run,string assembly){var k=(run,assembly);if(!modules.TryGetValue(k,out var module))modules[k]=module=ModuleDefinition.FromFile(Guard($"analysis/il2cpp/cpp2il-recovery-{run}/{assembly}.dll"));return module;}
string[] Diagnostics(MethodDefinition m)=>m.CilMethodBody!.Instructions.Where(i=>i.OpCode==CilOpCodes.Ldstr&&i.Operand is string s&&(s.StartsWith("Method not found @",StringComparison.Ordinal)||s.Contains("Unmanaged",StringComparison.Ordinal)||s.Contains("unmanaged",StringComparison.Ordinal)||s.Contains("unimplemented",StringComparison.OrdinalIgnoreCase))).Select(i=>(string)i.Operand!).ToArray();
object Inventory(MethodDefinition m)=>new{token=m.MetadataToken.ToString(),rows=m.CilMethodBody!.Instructions.Count,locals=m.CilMethodBody.LocalVariables.Count,local_types=m.CilMethodBody.LocalVariables.GroupBy(l=>l.VariableType.FullName).Select(g=>new{type=g.Key,count=g.Count()}).ToArray(),numeric_diagnostics=Diagnostics(m),isinst=m.CilMethodBody.Instructions.Count(i=>i.OpCode==CilOpCodes.Isinst),initobj=m.CilMethodBody.Instructions.Count(i=>i.OpCode==CilOpCodes.Initobj),ldnull=m.CilMethodBody.Instructions.Count(i=>i.OpCode==CilOpCodes.Ldnull),shape=Shape(m)};
object PublicInventory(MethodDefinition m)=>new{token=m.MetadataToken.ToString(),rows=m.CilMethodBody!.Instructions.Count,locals=m.CilMethodBody.LocalVariables.Count,local_types=m.CilMethodBody.LocalVariables.GroupBy(l=>l.VariableType.FullName).Select(g=>new{type=g.Key,count=g.Count()}).ToArray(),numeric_diagnostics=Diagnostics(m).Count(d=>d.StartsWith("Method not found @",StringComparison.Ordinal)),diagnostic_sequence_sha256=Digest(JsonSerializer.Serialize(Diagnostics(m))),helper_diagnostics=Diagnostics(m).Count(d=>d=="Method not found @B5B390"),isinst=m.CilMethodBody.Instructions.Count(i=>i.OpCode==CilOpCodes.Isinst),initobj=m.CilMethodBody.Instructions.Count(i=>i.OpCode==CilOpCodes.Initobj),ldnull=m.CilMethodBody.Instructions.Count(i=>i.OpCode==CilOpCodes.Ldnull),m.CilMethodBody.InitializeLocals,m.CilMethodBody.MaxStack,eh_handlers=m.CilMethodBody.ExceptionHandlers.Count};
byte[] Raw(MethodDefinition method,string run,string assembly){using var stream=File.OpenRead(Guard($"analysis/il2cpp/cpp2il-recovery-{run}/{assembly}.dll"));using var pe=new PEReader(stream);var reader=pe.GetMetadataReader();var definition=reader.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle((int)method.MetadataToken.Rid));return pe.GetMethodBody(definition.RelativeVirtualAddress).GetILBytes()!;}
bool Local(CilInstruction i)=>i.OpCode.Code.ToString().StartsWith("Ldloc",StringComparison.Ordinal)||i.OpCode.Code.ToString().StartsWith("Stloc",StringComparison.Ordinal);
bool Argument(CilInstruction i)=>i.OpCode.Code.ToString().StartsWith("Ldarg",StringComparison.Ordinal)||i.OpCode.Code.ToString().StartsWith("Starg",StringComparison.Ordinal);
string OpKind(CilInstruction i){string s=i.OpCode.Code.ToString();return s is "Ldloc" or "Ldloc_S" or "Ldloc_0" or "Ldloc_1" or "Ldloc_2" or "Ldloc_3"?"Ldloc":s is "Stloc" or "Stloc_S" or "Stloc_0" or "Stloc_1" or "Stloc_2" or "Stloc_3"?"Stloc":s is "Ldarg" or "Ldarg_S" or "Ldarg_0" or "Ldarg_1" or "Ldarg_2" or "Ldarg_3"?"Ldarg":s.EndsWith("_S",StringComparison.Ordinal)?s[..^2]:s;}
string LocalType(MethodDefinition method,int index){var type=method.CilMethodBody!.LocalVariables[index].VariableType;return type.ElementType+":"+type.FullName+":"+type;}
object AlignConstructor(MethodDefinition old,MethodDefinition current,string assembly){
 var a=old.CilMethodBody!.Instructions;var b=current.CilMethodBody!.Instructions;var left=Normalize(old);var right=Normalize(current);
 var pairs=new List<(int Old,int New)>();var rowMap=new Dictionary<int,int>();var localMap=new Dictionary<int,int>();var inverse=new Dictionary<int,int>();var removed=new List<(int Old,int New,int Local)>();
 int i=0,j=0;while(i<a.Count&&j<b.Count){
  if(OpKind(a[i])!=OpKind(b[j])){
   if(left[i]!="Ldc_I4:0"||i+1>=a.Count||OpKind(a[i+1])!="Stloc"||b[j].OpCode!=CilOpCodes.Nop)throw new InvalidDataException("Unexpected constructor operation change");
   int local=a[i+1].GetLocalVariableIndex();
   if(a.Any(r=>Local(r)&&r.GetLocalVariableIndex()==local&&OpKind(r)!="Stloc"))throw new InvalidDataException("Removed store has load/address escape");
   removed.Add((i,j,local));rowMap.Add(i,j);rowMap.Add(i+1,j);i+=2;j++;continue;
  }
  pairs.Add((i,j));rowMap.Add(i,j);
  if(Local(a[i])){int x=a[i].GetLocalVariableIndex(),y=b[j].GetLocalVariableIndex();if(localMap.TryGetValue(x,out int prior)&&prior!=y||inverse.TryGetValue(y,out int reverse)&&reverse!=x)throw new InvalidDataException("Non-bijective local identity change");localMap[x]=y;inverse[y]=x;}
  i++;j++;
 }
 Check("complete constructor operation alignment consumes both bodies",i==a.Count&&j==b.Count);
 Check("only four proven unused zero stores become Nop",removed.Count==4&&removed.Select(r=>r.Local).Distinct().Count()==1&&removed[0].Local==39);
 var removedStoreRows=removed.Select(r=>r.Old+1).ToHashSet();
 int branches=0,metadata=0,relocatedTokens=0,rawExact=0;var relocatedKinds=new Dictionary<string,int>();
 byte[] rawOld=Raw(old,before,assembly),rawNew=Raw(current,after,assembly);
 int Index(CilInstructionCollection rows,ICilLabel target)=>target.Offset==rows.EndLabel.Offset?rows.Count:rows.ToList().FindIndex(r=>r.Offset==target.Offset);
 rowMap.Add(a.Count,b.Count);
 foreach(var (x,y) in pairs){var p=a[x];var q=b[y];
  if(Local(p)){if(LocalType(old,p.GetLocalVariableIndex())!=LocalType(current,q.GetLocalVariableIndex()))throw new InvalidDataException("Mapped local type/pinning changed");continue;}
  if(Argument(p)){if(p.GetParameterIndex()!=q.GetParameterIndex())throw new InvalidDataException("Argument identity changed");continue;}
  if(p.Operand is ICilLabel target){int oldTarget=Index(a,target);if(q.Operand is not ICilLabel next||removedStoreRows.Contains(oldTarget)||rowMap[oldTarget]!=Index(b,next))throw new InvalidDataException("Branch target changed");branches++;continue;}
  if(p.Operand is IEnumerable<ICilLabel> targets){var oldTargets=targets.Select(t=>Index(a,t)).ToArray();if(q.Operand is not IEnumerable<ICilLabel> nextTargets||oldTargets.Any(removedStoreRows.Contains)||!oldTargets.Select(t=>rowMap[t]).SequenceEqual(nextTargets.Select(t=>Index(b,t))))throw new InvalidDataException("Switch target changed");branches++;continue;}
  if(left[x]!=right[y])throw new InvalidDataException("Nonlocal resolved instruction/member/string identity changed");
  int oldEnd=x+1<a.Count?a[x+1].Offset:rawOld.Length,newEnd=y+1<b.Count?b[y+1].Offset:rawNew.Length;
  var oldBytes=rawOld.AsSpan(p.Offset,oldEnd-p.Offset);var newBytes=rawNew.AsSpan(q.Offset,newEnd-q.Offset);
  bool token=p.OpCode.OperandType.ToString() is "InlineMethod" or "InlineField" or "InlineType" or "InlineTok" or "InlineString" or "InlineSig";
  if(token){if(oldBytes.Length!=newBytes.Length||oldBytes.Length<5||!oldBytes[..^4].SequenceEqual(newBytes[..^4]))throw new InvalidDataException("Metadata opcode/width changed");if(!oldBytes[^4..].SequenceEqual(newBytes[^4..])){relocatedTokens++;string kind=p.OpCode.OperandType.ToString();relocatedKinds[kind]=relocatedKinds.GetValueOrDefault(kind)+1;}metadata++;}
  else{if(!oldBytes.SequenceEqual(newBytes))throw new InvalidDataException("Non-token operand bytes changed");rawExact++;}
 }
 Check("all constructor locals retain bijective type/pinning identities",localMap.Count==506);
 Check("all constructor nonlocal operands/raw bytes and original branch targets retained",branches>0&&metadata>0&&rawExact>0);
 Check("relocated metadata operands are only identical literal strings",relocatedKinds.Count==1&&relocatedKinds.GetValueOrDefault("InlineString")==relocatedTokens);
 var usedOld=localMap.Keys.ToHashSet();var usedNew=localMap.Values.ToHashSet();
 var unusedOld=old.CilMethodBody.LocalVariables.Select((l,n)=>(l,n)).Where(p=>!usedOld.Contains(p.n)).Select(p=>LocalType(old,p.n)).ToList();
 var unusedNew=current.CilMethodBody.LocalVariables.Select((l,n)=>(l,n)).Where(p=>!usedNew.Contains(p.n)).Select(p=>LocalType(current,p.n)).ToList();
 foreach(string type in unusedNew)if(!unusedOld.Remove(type))throw new InvalidDataException("New unused local type");
 Check("only fourteen unreferenced Object locals disappear",unusedOld.Count==14&&unusedOld.All(t=>t=="Object:System.Object:System.Object"));
 Check("method flags/signature/InitLocals/MaxStack and absent EH remain unchanged",old.Attributes==current.Attributes&&old.Signature!.ToString()==current.Signature!.ToString()&&old.CilMethodBody.InitializeLocals&&current.CilMethodBody.InitializeLocals&&old.CilMethodBody.MaxStack==current.CilMethodBody.MaxStack&&old.CilMethodBody.ExceptionHandlers.Count==0&&current.CilMethodBody.ExceptionHandlers.Count==0);
 details.Add(new{constructor_local_map=localMap,row_map=rowMap,removed_dead_zero_stores=removed.Select(r=>new{old_row=r.Old,new_row=r.New,old_local=r.Local})});
 return new{matched_rows=pairs.Count,branches,metadata_operands=metadata,relocated_metadata_tokens=relocatedTokens,relocated_operand_kinds=relocatedKinds,other_raw_exact_rows=rawExact,bijective_used_locals=localMap.Count,removed_dead_zero_stores=removed.Count,removed_unused_object_locals=unusedOld.Count,all_other_opcodes_operands_raw_bytes_and_control_preserved=true};
}
try{
 var cases=new[]{("Assembly-CSharp","InControl.PlayStation4MacBTProfile",".ctor",28),("mscorlib","System.Array","get_swapper",3),("mscorlib","System.Array","int_swapper",1),("mscorlib","System.Array","obj_swapper",3),("mscorlib","System.Array","double_swapper",1),("mscorlib","System.Array","compare",1)};
 if(!baselineOnly){
  using var invocation=JsonDocument.Parse(File.ReadAllText(Guard($"logs/cpp2il-{after}-result.json")));
  Check("completed exact v40 invocation/Core/input identities",invocation.RootElement.GetProperty("exit_code").GetInt32()==0&&invocation.RootElement.GetProperty("tool_assembly_sha256").GetProperty("Cpp2IL.Core.dll").GetString()==expectedCore&&invocation.RootElement.GetProperty("source_metadata_sha256").GetString()=="f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85"&&invocation.RootElement.GetProperty("source_binary_sha256").GetString()=="94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238");
  Check("full invocation contains44 output assemblies",Directory.GetFiles(Guard($"analysis/il2cpp/cpp2il-recovery-{after}"),"*.dll").Length==44);
  using var production=JsonDocument.Parse(File.ReadAllText(Guard("reports/object-isinst-abi-production-v40.json")));
  Check("frozen actual production41 and unresolved class/helper semantics bound",production.RootElement.GetProperty("status").GetString()=="PASS_ORIGINAL_ISINST_ABI_ONLY_PRODUCTION_DATAFLOW_AND_DIAGNOSTICS"&&production.RootElement.GetProperty("checks").GetInt32()==41&&production.RootElement.GetProperty("core_sha256").GetString()==expectedCore&&!production.RootElement.GetProperty("class_input_emission").GetProperty("emitted_class_input_evaluation_recovered").GetBoolean()&&!production.RootElement.GetProperty("class_input_emission").GetProperty("emitted_helper_return_semantics_recovered").GetBoolean());
 }
 foreach(var (assembly,owner,name,count) in cases){
  if(owner!="System.Array")foreach(var run in new[]{before,after})if(!baselineOnly||run==before){
   var note=Module(run,assembly).GetAllTypes().Single(t=>t.FullName=="Cpp2ILInjected.Cpp2ILHelpers").Methods.Single(m=>m.Name=="NoteDecompilerIssue");
   Check("actual injected diagnostic helper is only a no-op ret: "+run,note.IsStatic&&note.Signature!.ReturnType.FullName=="System.Void"&&note.Signature.ParameterTypes.Count==1&&note.Signature.ParameterTypes[0].FullName=="System.String"&&Normalize(note).SequenceEqual(new[]{"Ret:"})&&note.CilMethodBody!.LocalVariables.Count==0&&note.CilMethodBody.ExceptionHandlers.Count==0);
   byte[] bytes=Raw(note,run,assembly);Check("actual diagnostic helper exact ret byte: "+run,bytes.SequenceEqual(new byte[]{0x2A}));
   diagnosticHelpers.Add(new{run,method_token=note.MetadataToken.ToString(),body_bytes_hex=Convert.ToHexString(bytes),body_sha256=Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),no_throw_or_log=true,recovered_runtime_effects=false});
   details.Add(new{run,diagnostic_helper=Normalize(note)});
  }
  MethodDefinition Find(string run)=>Module(run,assembly).GetAllTypes().Single(t=>t.FullName==owner).Methods.Single(m=>m.Name==name&&m.GenericParameters.Count==0&&(name!=".ctor"||m.Signature!.ParameterTypes.Count==0));
  var old=Find(before);
  if(baselineOnly){details.Add(new{assembly,owner,method=name,inventory=Inventory(old),rows=Normalize(old)});continue;}
  var current=Find(after);
  details.Add(new{assembly,owner,method=name,before=Inventory(old),after=Inventory(current),before_rows=Normalize(old),after_rows=Normalize(current)});
  Check("no semantic isinst translation in actual output: "+owner+"::"+name,!old.CilMethodBody!.Instructions.Any(i=>i.OpCode==CilOpCodes.Isinst)&&!current.CilMethodBody!.Instructions.Any(i=>i.OpCode==CilOpCodes.Isinst));
  Check("all unresolved numeric/effect diagnostic strings stay ordered: "+owner+"::"+name,Diagnostics(old).SequenceEqual(Diagnostics(current)));
  if(owner=="System.Array"){
   string[] expected=name=="get_swapper"?["Ldnull:","Ret:"]:name=="compare"?["Ldc_I4_0:","Ret:"]:["Ret:"];
   Check("actual Array body is only unchanged pre-existing default scaffold: "+name,Normalize(old).SequenceEqual(expected)&&Normalize(old).SequenceEqual(Normalize(current))&&Shape(old)==Shape(current)&&Raw(old,before,assembly).SequenceEqual(Raw(current,after,assembly)));
   Check("forced-stage Array calls are not claimed present in full output: "+name,Diagnostics(old).Length==0&&Diagnostics(current).Length==0);
  }else{
   Check("all28 original helper diagnostics retain exact emitted count",Diagnostics(old).Count(s=>s=="Method not found @B5B390")==28&&Diagnostics(current).Count(s=>s=="Method not found @B5B390")==28);
   Check("constructor adds no explicit ldnull/initobj substitution",!old.CilMethodBody!.Instructions.Any(i=>i.OpCode==CilOpCodes.Ldnull||i.OpCode==CilOpCodes.Initobj)&&!current.CilMethodBody!.Instructions.Any(i=>i.OpCode==CilOpCodes.Ldnull||i.OpCode==CilOpCodes.Initobj));
   constructorAlignment=AlignConstructor(old,current,assembly);
   var scopes=new List<object>();
   foreach(var (method,run) in new[]{(old,before),(current,after)}){
    var rows=method.CilMethodBody!.Instructions;var resultLocals=new HashSet<int>();int diagnosticCalls=0;
    for(int row=0;row<rows.Count;row++)if(rows[row].OpCode==CilOpCodes.Ldstr&&Equals(rows[row].Operand,"Method not found @B5B390")){
     var call=rows[row+1];if(call.OpCode!=CilOpCodes.Call||call.Operand is not IMethodDescriptor md||md.FullName!="System.Void Cpp2ILInjected.Cpp2ILHelpers::NoteDecompilerIssue(System.String)")throw new InvalidDataException("Unexpected diagnostic member/call");
     if(OpKind(rows[row+2])!="Ldloc"||Normalize(method)[row+3]!="Ldc_I4:0"||rows[row+4].OpCode!=CilOpCodes.Ceq||OpKind(rows[row+5])!="Stloc"||OpKind(rows[row+6])!="Ldloc"||rows[row+5].GetLocalVariableIndex()!=rows[row+6].GetLocalVariableIndex()||OpKind(rows[row+7])!="Brtrue")throw new InvalidDataException("Helper-result null-check shape changed");
     int result=rows[row+2].GetLocalVariableIndex();
     if(method.CilMethodBody.LocalVariables[result].VariableType.FullName!="System.Object"||rows.Any(r=>Local(r)&&r.GetLocalVariableIndex()==result&&OpKind(r)!="Ldloc")||!resultLocals.Add(result))throw new InvalidDataException("Helper result has an actual write/escape or wrong type");
     diagnosticCalls++;
    }
    Check("actual28 distinct unassigned result locals/null checks and implicit InitLocals boundary: "+run,diagnosticCalls==28&&resultLocals.Count==28&&method.CilMethodBody.InitializeLocals);
    int allCalls=rows.Count(r=>r.OpCode==CilOpCodes.Call&&r.Operand is IMethodDescriptor member&&member.FullName=="System.Void Cpp2ILInjected.Cpp2ILHelpers::NoteDecompilerIssue(System.String)");
    scopes.Add(new{run,helper_diagnostic_calls=diagnosticCalls,all_issue_helper_calls=allCalls,distinct_unassigned_object_results=resultLocals.Count,implicit_initlocals_null=true,no_op_issue_helper_does_not_stop_result_read=true});
   }
   implicitResults=scopes;
  }
  observations.Add(new{assembly,owner,method=name,forced_production_ir_helper_calls=count,actual_helper_diagnostics=Diagnostics(current).Count(s=>s=="Method not found @B5B390"),full_output_array_body_recovered=false,before=PublicInventory(old),after=PublicInventory(current),baseline_assembly_sha256=Hash($"analysis/il2cpp/cpp2il-recovery-{before}/{assembly}.dll"),actual_assembly_sha256=Hash($"analysis/il2cpp/cpp2il-recovery-{after}/{assembly}.dll"),baseline_body_sha256=Convert.ToHexString(SHA256.HashData(Raw(old,before,assembly))).ToLowerInvariant(),actual_body_sha256=Convert.ToHexString(SHA256.HashData(Raw(current,after,assembly))).ToLowerInvariant()});
 }
 if(!baselineOnly)Check("all six original callers inspected without executing any method",observations.Count==6);
}catch(Exception error){fatal=error.ToString();}
string privatePath=$"analysis/reconstruction/object-isinst-v40/fresh-output/{(baselineOnly?"baseline39":"correlation40")}.json";
File.WriteAllText(Guard(privatePath),JsonSerializer.Serialize(details,new JsonSerializerOptions{WriteIndented=true})+"\n");
string status=fatal!=null?"FRESH_OBJECT_ISINST_ABI_CIL_CORRELATION_FAILED":baselineOnly?"BASELINE_OBJECT_ISINST_ABI_CIL_INVENTORY":"PASS_FRESH_ABI_ONLY_CIL_CORRELATION_WITH_EXPLICIT_UNRECOVERED_SCAFFOLD_LIMITATIONS";
var report=new{status,recovery_run=after,baseline_run=before,checks=tests.Count,tests,methods=observations,constructor_alignment=constructorAlignment,diagnostic_helpers=diagnosticHelpers,implicit_result_boundary=implicitResults,fatal,expected_core_sha256=expectedCore,source_sha256=Hash("src/re/RecoveredObjectIsInstAbiProbe/Program.cs"),invocation_report_sha256=baselineOnly?null:Hash($"logs/cpp2il-{after}-result.json"),baseline_invocation_report_sha256=Hash($"logs/cpp2il-{before}-result.json"),production_report_sha256=Hash("reports/object-isinst-abi-production-v40.json"),private_evidence=privatePath,private_evidence_sha256=Hash(privatePath),reused_infrastructure_dll_sha256=Hash("src/re/RecoveredAssemblyLeafProbe/bin/Release/net10.0/RecoveredAssemblyLeafProbe.dll"),core_dependency_loaded=false,recovered_game_methods_invoked=0,constructors_invoked=0,semantic_isinst_recovered=false,emitted_class_input_evaluation_recovered=false,emitted_helper_return_semantics_recovered=false,original_cil_modified=false,new_explicit_default_substitution=false,existing_implicit_defaults_unresolved=true,array_forced_analysis_does_not_match_full_output_body_recovery=true,full_clean_decompile_ready=false,scope="Offline actual v39/v40 CIL only. The original profile constructor retains28 unresolved numeric-helper diagnostics and the full remaining operation/member/control sequence under bijective typed local renaming, except four zero stores into a never-read/address-taken local becoming Nop and fourteen unreferenced Object locals disappearing. The injected issue helper is a single ret, not a trap/logger; each unresolved helper result has no emitted assignment, so InitLocals supplies implicit null if reached. No execution/JIT validity, class-input evaluation, helper return/effect or IsInst semantics are established. The five Array methods keep their pre-existing default stubs unchanged; their nine calls exist only in the separately forced production-stage analysis, not actual full-run emitted CIL. No Array body recovery credit, original constructor execution, managed isinst or new default substitution is claimed. A separate fail-loud unknown-operation emitter contract should be considered; it would expose missing semantics, not recover them."};
if(!baselineOnly&&!inspectOnly)File.WriteAllText(Guard($"reports/recovered-object-isinst-abi-{after}.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");
Console.WriteLine(JsonSerializer.Serialize(new{status,checks=tests.Count,fatal,private_evidence=privatePath}));return fatal==null?0:2;
