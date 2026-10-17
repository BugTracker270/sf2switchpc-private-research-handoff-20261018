using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using MethodDefinition = AsmResolver.DotNet.MethodDefinition;
using ModuleDefinition = AsmResolver.DotNet.ModuleDefinition;
using FieldDefinition = AsmResolver.DotNet.FieldDefinition;

if(args.Length!=1)throw new ArgumentException("USB root required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative){string p=Path.GetFullPath(Path.Combine(root,relative));if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside USB");for(DirectoryInfo? d=new(Path.GetDirectoryName(p)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse");return p;}
string Hash(string relative)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Guard(relative)))).ToLowerInvariant();
var tests=new List<object>();var methods=new List<object>();var details=new List<object>();string? fatal=null;int occurrences=0;
void Check(string name,bool passed){tests.Add(new{name,passed});if(!passed)throw new InvalidDataException(name);}
try{
 using var input=JsonDocument.Parse(File.ReadAllText(Guard("analysis/reconstruction/assembly-leaf-v39/six-added-diagnostic-input.json")));
 using var contract=JsonDocument.Parse(File.ReadAllText(Guard("reports/assembly-leaf-accessor-contract-v39.json")));
 using var fresh=JsonDocument.Parse(File.ReadAllText(Guard("reports/recovered-assembly-leaves-nso-assembly-leaf-getter-v39.json")));
 Check("original78checks and fresh27getter/two-constructor gates passed",contract.RootElement.GetProperty("checks").GetInt32()==78&&fresh.RootElement.GetProperty("status").GetString()=="PASS_FRESH_ORIGINAL_ASSEMBLY_GETTERS_AND_CONSTRUCTOR_CALL_CORRELATION");
 foreach(var binding in input.RootElement.GetProperty("source_bindings").EnumerateArray())Check("exact compiler source hash "+binding.GetProperty("path").GetString(),Hash(binding.GetProperty("path").GetString()!)==binding.GetProperty("sha256").GetString());
 // Reuse the already frozen original offline probe's exact normalizer/shape code.
 var infrastructure=Assembly.LoadFrom(Guard("src/re/RecoveredAssemblyLeafProbe/bin/Release/net10.0/RecoveredAssemblyLeafProbe.dll"));
 var helper=infrastructure.GetType("Program",true)!;
 var normalizer=helper.GetMethods(BindingFlags.Static|BindingFlags.NonPublic).Single(m=>m.Name.Contains("g__Normalize|",StringComparison.Ordinal));
 var shape=helper.GetMethods(BindingFlags.Static|BindingFlags.NonPublic).Single(m=>m.Name.Contains("g__Shape|",StringComparison.Ordinal));
 List<string> Normalize(MethodDefinition m)=>(List<string>)normalizer.Invoke(null,[m])!;
 string Shape(MethodDefinition m)=>(string)shape.Invoke(null,[m])!;
 const string before="nso-virtual-companion-copy-v38",after="nso-assembly-leaf-getter-v39";
 byte[] RawCode(MethodDefinition method,string recovery) { using var stream=File.OpenRead(Guard($"analysis/il2cpp/cpp2il-recovery-{recovery}/Assembly-CSharp-firstpass.dll"));using var pe=new PEReader(stream);var reader=pe.GetMetadataReader();var definition=reader.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle((int)method.MetadataToken.Rid));return pe.GetMethodBody(definition.RelativeVirtualAddress).GetILBytes()!; }
 var oldModule=ModuleDefinition.FromFile(Guard($"analysis/il2cpp/cpp2il-recovery-{before}/Assembly-CSharp-firstpass.dll"));var newModule=ModuleDefinition.FromFile(Guard($"analysis/il2cpp/cpp2il-recovery-{after}/Assembly-CSharp-firstpass.dll"));
 var accepted=new Dictionary<FieldDefinition,MethodDefinition>();
 foreach(var item in contract.RootElement.GetProperty("eligible_getter_inventory").EnumerateArray()){
  if(item.GetProperty("assembly").GetString()!="Assembly-CSharp-firstpass")continue;
  string owner=item.GetProperty("owner").GetString()!,field=item.GetProperty("field").GetString()!,getter=item.GetProperty("getter").GetString()!;
  var ot=oldModule.GetAllTypes().Single(t=>t.FullName==owner);var nt=newModule.GetAllTypes().Single(t=>t.FullName==owner);
  accepted.Add(ot.Fields.Single(f=>f.Name==field),nt.Methods.Single(m=>m.Name==getter&&m.Signature!.ParameterTypes.Count==0));
 }
 foreach(var record in input.RootElement.GetProperty("records").EnumerateArray()){
  string owner=record.GetProperty("owner").GetString()!,name=record.GetProperty("method").GetString()!;
  var old=oldModule.GetAllTypes().Single(t=>t.FullName==owner).Methods.Single(m=>m.Name==name);var current=newModule.GetAllTypes().Single(t=>t.FullName==owner).Methods.Single(m=>m.Name==name);
  var left=Normalize(old);var right=Normalize(current);var oldRows=old.CilMethodBody!.Instructions;var newRows=current.CilMethodBody!.Instructions;
  Check(owner+"::"+name+" complete original opcode row count/shape unchanged",left.Count==right.Count&&Shape(old)==Shape(current));
  var changes=new List<object>();int substituted=0;var changedRows=new HashSet<int>();
  for(int index=0;index<left.Count;index++){
   if(left[index]==right[index])continue;
   var a=oldRows[index];var b=newRows[index];
   Check(owner+"::"+name+" every changed row is exact native-proven same-field internal getter",a.OpCode==CilOpCodes.Ldfld&&a.Operand is FieldDefinition field&&accepted.TryGetValue(field,out var getter)&&b.OpCode==CilOpCodes.Call&&ReferenceEquals(b.Operand,getter));
   substituted++;changedRows.Add(index);changes.Add(new{index,before=left[index],after=right[index]});
  }
  Check(owner+"::"+name+" uses at least one newly accessible native-proven getter",substituted>0);
  byte[] rawBefore=RawCode(old,before),rawAfter=RawCode(current,after),normalizedBefore=(byte[])rawBefore.Clone(),normalizedAfter=(byte[])rawAfter.Clone();
  Check(owner+"::"+name+" exact original byte length and instruction offsets",rawBefore.Length==rawAfter.Length&&oldRows.Zip(newRows).All(pair=>pair.First.Offset==pair.Second.Offset));
  int matchedTokens=0,changedTokens=0;
  for(int index=0;index<oldRows.Count;index++){
   var a=oldRows[index];var b=newRows[index];int end=index+1<oldRows.Count?oldRows[index+1].Offset:rawBefore.Length;int length=end-a.Offset;
   bool token=a.OpCode.OperandType.ToString() is "InlineMethod" or "InlineField" or "InlineType" or "InlineTok" or "InlineString";
   if(changedRows.Contains(index)){Check("exact one-byte field/call opcode substitution",length==5);normalizedBefore[a.Offset]=0;normalizedAfter[b.Offset]=0;}
   if(!token)continue;
   Check("metadata-only operand has exact four-byte width",length is 5 or 6);matchedTokens++;if(!rawBefore.AsSpan(end-4,4).SequenceEqual(rawAfter.AsSpan(end-4,4)))changedTokens++;
   normalizedBefore.AsSpan(end-4,4).Clear();normalizedAfter.AsSpan(end-4,4).Clear();
  }
  Check(owner+"::"+name+" every non-token byte including64bit operands preserved outside proven substitutions",normalizedBefore.SequenceEqual(normalizedAfter));
  int added=record.GetProperty("added_occurrences").GetInt32();occurrences+=added;
  int[] adds=Enumerable.Range(0,oldRows.Count).Where(i=>oldRows[i].OpCode==CilOpCodes.Add).ToArray();
  int[] conversions=Enumerable.Range(0,oldRows.Count).Where(i=>oldRows[i].OpCode==CilOpCodes.Conv_I||oldRows[i].OpCode==CilOpCodes.Conv_U).ToArray();
  Check(owner+"::"+name+" original arithmetic/conversion opcodes and neighboring normalized operand rows retained",adds.All(i=>newRows[i].OpCode==oldRows[i].OpCode)&&conversions.All(i=>newRows[i].OpCode==oldRows[i].OpCode));
  details.Add(new{owner,method=name,before=left,after=right,changes,unchanged_add_rows=adds,unchanged_native_int_conversion_rows=conversions,original_locals=old.CilMethodBody.LocalVariables.Select(l=>l.VariableType.FullName).ToArray()});
  methods.Add(new{owner,method=name,added_occurrences=added,code=record.GetProperty("code").GetString(),message=record.GetProperty("message").GetString(),after_locations=record.GetProperty("after_locations").Clone(),rows=left.Count,only_native_proven_field_to_getter_substitutions=substituted,all_other_original_rows_and_shape_equal=true,raw_before_sha256=Convert.ToHexString(SHA256.HashData(rawBefore)).ToLowerInvariant(),raw_after_sha256=Convert.ToHexString(SHA256.HashData(rawAfter)).ToLowerInvariant(),matched_metadata_operands=matchedTokens,changed_metadata_tokens=changedTokens,all_other_raw_non_token_bytes_equal=true,original_add_rows_unchanged=adds.Length,original_native_int_conversion_rows_unchanged=conversions.Length,classification="Existing invalid original recovered operation newly diagnosed after its receiver field became accessible through the exact getter; no new arithmetic/cast/control/local instruction was introduced."});
 }
 Check("all six added diagnostic occurrences and three owner methods accounted",occurrences==6&&methods.Count==3);
}catch(Exception error){fatal=error.ToString();}
string privatePath="analysis/reconstruction/assembly-leaf-v39/six-added-diagnostic-cil.json";File.WriteAllText(Guard(privatePath),JsonSerializer.Serialize(details,new JsonSerializerOptions{WriteIndented=true})+"\n");
string status=fatal==null?"PASS_SIX_ADDED_DIAGNOSTICS_EXPOSE_EXISTING_UNCHANGED_OPERATIONS":"SIX_ADDED_DIAGNOSTIC_CIL_ATTRIBUTION_FAILED";
var output=new{status,checks=tests.Count,tests,added_occurrences=occurrences,methods,fatal,source_sha256=Hash("src/re/RecoveredAssemblyLeafDiagnosticProbe/Program.cs"),source_input_sha256=Hash("analysis/reconstruction/assembly-leaf-v39/six-added-diagnostic-input.json"),reused_infrastructure_dll_sha256=Hash("src/re/RecoveredAssemblyLeafProbe/bin/Release/net10.0/RecoveredAssemblyLeafProbe.dll"),fresh_gate_report_sha256=Hash("reports/recovered-assembly-leaves-nso-assembly-leaf-getter-v39.json"),canonical_delta_sha256=Hash("reports/compiler-diagnostic-delta-v39.json"),private_cil=privatePath,private_cil_sha256=Hash(privatePath),core_dependency_loaded=false,recovered_game_methods_invoked=0,cil_modified=false,compiler_errors_repaired=false,full_clean_decompile_ready=false,scope="Six canonical added firstpass diagnostics in exactly three original methods. Complete offline38→39 CIL compares normalized arg/local macros, branch row labels, metadata identities and full locals/pinning/InitLocals/MaxStack/EH/signature shape, allowing only selected native-proven private field-to-same-field internal getter replacements. Arithmetic/conversion instructions and every other operand/control row were already present. Their original invalid semantics remain unresolved; reduced accessibility errors do not imply complete compilation or behavioral parity."};
File.WriteAllText(Guard("reports/assembly-leaf-added-diagnostics-attribution-v39.json"),JsonSerializer.Serialize(output,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{status,checks=tests.Count,added_occurrences=occurrences,methods=methods.Count,fatal}));return fatal==null?0:2;
