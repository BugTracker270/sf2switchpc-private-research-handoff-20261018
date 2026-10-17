using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if(args.Length!=2||!Regex.IsMatch(args[1],"^[a-z0-9-]+$"))throw new ArgumentException("Verified USB root and recovery run required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar),run=args[1];
string Guard(string relative){string path=Path.GetFullPath(Path.Combine(root,relative));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");return path;}
string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
string folder=Guard($"analysis/il2cpp/cpp2il-recovery-{run}"),assemblyPath=Path.Combine(folder,"Assembly-CSharp-firstpass.dll");
var context=new AssemblyLoadContext("ReferenceZero_"+run,true);
context.Resolving+=(c,name)=>File.Exists(Path.Combine(folder,name.Name+".dll"))?c.LoadFromAssemblyPath(Path.Combine(folder,name.Name+".dll")):null;
var assembly=context.LoadFromAssemblyPath(assemblyPath);
var type=assembly.GetType("BestHTTP.WebSocket.Frames.WebSocketFrameReader",true)!;
var method=type.GetMethods(BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance|BindingFlags.DeclaredOnly).Single(m=>m.Name=="Read"&&m.GetParameters() is[{ParameterType:var t}]&&t.FullName=="System.IO.Stream");
var body=method.GetMethodBody()!;var bytes=body.GetILAsByteArray()!;
var opcodes=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static).Where(f=>f.FieldType==typeof(OpCode)).Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>unchecked((ushort)o.Value));
var rows=new List<Row>();
for(int at=0;at<bytes.Length;){int offset=at;ushort code=bytes[at++];if(code==0xFE)code=(ushort)(0xFE00|bytes[at++]);var op=opcodes[code];int operand=at;int size=op.OperandType switch{OperandType.InlineNone=>0,OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget=>1,OperandType.InlineVar=>2,OperandType.InlineI8 or OperandType.InlineR=>8,OperandType.InlineSwitch=>4+4*BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(at,4)),_=>4};at+=size;if(at>bytes.Length)throw new IOException("Truncated unchanged CIL");int? value=size is 1?bytes[operand]:size is 2?BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(operand,2)):size is 4?BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(operand,4)):null;rows.Add(new(offset,op,value));}
int LocalIndex(Row row)=>row.Op==OpCodes.Stloc_0?0:row.Op==OpCodes.Stloc_1?1:row.Op==OpCodes.Stloc_2?2:row.Op==OpCodes.Stloc_3?3:row.Op==OpCodes.Stloc||row.Op==OpCodes.Stloc_S?row.Value!.Value:-1;
var meaningful=rows.Where(row=>row.Op!=OpCodes.Nop).ToArray();var witnesses=new List<object>();int checks=0;
void Check(bool value,string message){if(!value)throw new Exception(message);checks++;}
for(int i=0;i+4<meaningful.Length;i++){
    var start=meaningful[i];if(start.Op!=OpCodes.Ldstr)continue;
    string diagnostic=method.Module.ResolveString(start.Value!.Value);
    if(!diagnostic.StartsWith("Unmanaged memory load:",StringComparison.Ordinal))continue;
    var call=meaningful[i+1];var zero=meaningful[i+2];var conversion=meaningful[i+3];var store=meaningful[i+4];
    if(call.Op!=OpCodes.Call||!(zero.Op==OpCodes.Ldc_I4_0||zero.Op==OpCodes.Ldc_I4&&zero.Value==0)||conversion.Op!=OpCodes.Conv_I)continue;
    int local=LocalIndex(store);if(local<0)continue;
    var localType=body.LocalVariables[local].LocalType;if(!localType.IsArray)continue;
    var helper=method.Module.ResolveMethod(call.Value!.Value)!;
    Check(helper.DeclaringType?.FullName=="Cpp2ILInjected.Cpp2ILHelpers"&&helper.Name=="NoteDecompilerIssue"&&helper.IsStatic&&helper.GetParameters() is [{ParameterType:var diagnosticType}]&&diagnosticType==typeof(string),"Diagnostic helper identity differs");
    Check(localType==typeof(byte[]),"Selected fallback array is not byte[]");
    witnesses.Add(new{diagnostic_offset=start.Offset,helper_call_offset=call.Offset,zero_offset=zero.Offset,native_int_conversion_offset=conversion.Offset,store_offset=store.Offset,local_index=local,local_type=localType.FullName,source_is_unmanaged_load_fallback=true,original_native_zero_proven=false,original_slot_0x260=diagnostic.Contains("+260]",StringComparison.Ordinal)});
}
Check(witnesses.Count>0,"Actual method contains no selected diagnostic-to-array-zero fallback");
Check(Hash(method.GetMethodBody()!.GetILAsByteArray()!)==Hash(bytes),"Read-only inspection changed original CIL");
var report=new{status="PASS_ACTUAL_ARRAY_ZERO_DIAGNOSTIC_FALLBACK_CORRELATION",recovery_run=run,checks,assembly_sha256=Hash(File.ReadAllBytes(assemblyPath)),cil_sha256=Hash(bytes),method=method.DeclaringType!.FullName+"::"+method.Name,method_token=$"0x{method.MetadataToken:X8}",witnesses,game_methods_invoked=0,cil_or_source_modified=false,tokens_remapped=0,full_clean_decompile_ready=false,scope="Read-only inspection of unchanged actual recovered CIL. A byte[] local receives ldc.i4.0/conv.i immediately after the exact Cpp2IL unmanaged-load diagnostic helper. This zero is a recovery placeholder, not proof of an original native null. No game method, fixture substitute or class initializer is executed. Native original slot reads and emitter expected-type handling are separate evidence; replacing these diagnostic fallbacks with ldnull would not recover their missing load semantics."};
File.WriteAllText(Guard("reports/recovered-reference-zero-triage-v36.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,checks,witnesses=witnesses.Count}));context.Unload();

sealed record Row(int Offset,OpCode Op,int? Value);
