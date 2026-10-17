using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if(args.Length!=2||!Regex.IsMatch(args[1],"^[a-z0-9-]+$"))throw new ArgumentException("Verified USB root and recovery run required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar),run=args[1];
string Guard(string relative){string path=Path.GetFullPath(Path.Combine(root,relative));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");return path;}
string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
var folder=Guard($"analysis/il2cpp/cpp2il-recovery-{run}");
AssemblyLoadContext.Default.Resolving+=(context,name)=>File.Exists(Path.Combine(folder,name.Name+".dll"))?context.LoadFromAssemblyPath(Path.Combine(folder,name.Name+".dll")):null;
var assemblyPath=Path.Combine(folder,"Assembly-CSharp-firstpass.dll");var assembly=Assembly.LoadFrom(assemblyPath);
var owner=assembly.GetType("CodeStage.AntiCheat.Detectors.ObscuredCheatingDetector",true)!;
var field=owner.GetField("<Instance>k__BackingField",BindingFlags.NonPublic|BindingFlags.Static)!;
var getter=owner.GetProperty("Instance",BindingFlags.Public|BindingFlags.Static)!.GetMethod!;
var caller=assembly.GetType("CodeStage.AntiCheat.ObscuredTypes.ObscuredInt",true)!.GetMethod("InternalDecrypt",BindingFlags.NonPublic|BindingFlags.Instance)!;
int checks=0,cases=0;void Check(bool test,string message){if(!test)throw new Exception(message);checks++;}
Check(owner.TypeInitializer==null&&field.IsPrivate&&field.IsStatic,"Original owner/field initialization or visibility differs");
Check(getter.IsPublic&&getter.IsStatic&&getter.ReturnType==owner&&getter.GetParameters().Length==0,"Original getter contract differs");
var ops=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static).Where(f=>f.FieldType==typeof(OpCode)).Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>unchecked((ushort)o.Value));
List<(int Offset,OpCode Op,int? Token)> Decode(MethodInfo method){var bytes=method.GetMethodBody()!.GetILAsByteArray()!;var rows=new List<(int,OpCode,int?)>();for(int at=0;at<bytes.Length;){int start=at;ushort code=bytes[at++];if(code==0xFE)code=(ushort)(0xFE00|bytes[at++]);var op=ops[code];int operand=at;int size=op.OperandType switch{OperandType.InlineNone=>0,OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget=>1,OperandType.InlineVar=>2,OperandType.InlineI8 or OperandType.InlineR=>8,OperandType.InlineSwitch=>4+4*BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(at,4)),_=>4};at+=size;if(at>bytes.Length)throw new Exception("Truncated original CIL");int? token=op.OperandType is OperandType.InlineField or OperandType.InlineMethod?BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(operand,4)):null;rows.Add((start,op,token));}return rows;}
bool Same(MemberInfo? actual,MemberInfo expected)=>actual?.Module.ModuleVersionId==expected.Module.ModuleVersionId&&actual.MetadataToken==expected.MetadataToken;
var getterRows=Decode(getter);Check(getter.GetMethodBody()!.ExceptionHandlingClauses.Count==0,"Original getter has EH effects");
Console.WriteLine("Actual getter sequence: "+string.Join(",",getterRows.Select(r=>$"{r.Offset}:{r.Op.Name}")));
Check(getterRows.Count(r=>r.Op==OpCodes.Ldsfld&&Same(getter.Module.ResolveField(r.Token!.Value),field))==1,"Getter does not read exact original private static field once");
var getterBytes=getter.GetMethodBody()!.GetILAsByteArray()!;
bool directEntry=getterRows.Count==3&&(getterRows[0].Op==OpCodes.Br||getterRows[0].Op==OpCodes.Br_S)
    &&getterRows[1].Op==OpCodes.Ldsfld&&getterRows[2].Op==OpCodes.Ret;
if(directEntry){var entry=getterRows[0];int operand=entry.Offset+entry.Op.Size;int size=entry.Op==OpCodes.Br?4:1;int delta=size==4?BinaryPrimitives.ReadInt32LittleEndian(getterBytes.AsSpan(operand,4)):unchecked((sbyte)getterBytes[operand]);directEntry=operand+size+delta==getterRows[1].Offset;}
Check(directEntry,"Getter has effects beyond its exact forward-entry/private-static-field/return sequence");
var original=field.GetValue(null);
try{
    var objects=new List<object?>{null};for(int i=0;i<8;i++)objects.Add(RuntimeHelpers.GetUninitializedObject(owner));
    foreach(var value in objects){field.SetValue(null,value);var actual=getter.Invoke(null,null);cases++;Check(ReferenceEquals(actual,value),"Actual getter lost field reference identity");Check(ReferenceEquals(field.GetValue(null),value),"Actual getter mutated field");}
}finally{field.SetValue(null,original);}
Check(field.IsPrivate&&field.IsStatic,"Original field visibility changed");
var callerRows=Decode(caller);
int privateLoads=callerRows.Count(r=>r.Op==OpCodes.Ldsfld&&Same(caller.Module.ResolveField(r.Token!.Value),field));
int accessorCalls=callerRows.Count(r=>r.Op==OpCodes.Call&&Same(caller.Module.ResolveMethod(r.Token!.Value),getter));
bool integrated=privateLoads==0&&accessorCalls>0;
var report=new{status=integrated?"PASS_ACTUAL_STATIC_GETTER_AND_CALLER_ACCESSOR_CORRELATION":"PASS_ACTUAL_GETTER_PRIVATE_CALLER_LOAD_STILL_UNRESOLVED",recovery_run=run,cases,checks,caller_private_static_loads=privateLoads,caller_public_getter_calls=accessorCalls,caller_accessor_integrated=integrated,
    getter_cil_sha256=Hash(getter.GetMethodBody()!.GetILAsByteArray()!),caller_cil_sha256=Hash(caller.GetMethodBody()!.GetILAsByteArray()!),assembly_sha256=Hash(File.ReadAllBytes(assemblyPath)),
    source_or_cil_edited=false,tokens_remapped=0,field_visibility_changed=false,owner_cctor=false,
    scope="Actual unchanged recovered public getter executes directly with null and eight constructor-free allocated instances as explicit static-field fixtures. It returns the exact original field reference and leaves storage unchanged; owner has no .cctor. Original caller is inspected only for exact private-field/getter tokens. Full caller runtime/active detector behavior, constructors, native metadata assurance and whole-game source are not certified."};
File.WriteAllText(Guard($"reports/recovered-static-getter-{run}.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,cases,checks,privateLoads,accessorCalls}));
