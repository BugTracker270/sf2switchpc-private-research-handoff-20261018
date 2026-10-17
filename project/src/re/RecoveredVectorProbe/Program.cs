using System.Reflection;
using System.Reflection.Emit;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if(args.Length is <2 or >3||!Regex.IsMatch(args[1],"^[a-z0-9-]+$"))throw new ArgumentException("USB root and recovery run, optional relative assembly path required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar),run=args[1];
string Guard(string relative){var path=Path.GetFullPath(Path.Combine(root,relative));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside USB workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point forbidden");return path;}
string assemblyPath=Guard(args.Length==3?args[2]:$"analysis/il2cpp/cpp2il-recovery-{run}/UnityEngine.CoreModule.dll");
string fixture=Guard("analysis/il2cpp/vector3-native-fixtures-v1.json");
var failures=new List<object>();string? fatal=null;int cases=0,checks=0;string? ilHash=null;
try {
    var assembly=Assembly.LoadFrom(assemblyPath);var type=assembly.GetType("UnityEngine.Vector3",true)!;
    if(!type.IsValueType)throw new Exception("Recovered Vector3 declaration is not a value type");
    var fields=type.GetFields(BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance);
    if(fields.Length!=3||fields.Any(f=>f.FieldType!=typeof(float))||!fields.Select(f=>f.Name).Order().SequenceEqual(new[]{"x","y","z"}))throw new Exception("Recovered Vector3 field shape differs");
    var method=type.GetMethod("op_Addition",BindingFlags.Static|BindingFlags.Public)!;
    var body=method.GetMethodBody()!;if(body.ExceptionHandlingClauses.Count!=0)throw new Exception("Unexpected exception region");
    var code=body.GetILAsByteArray()!;ilHash=Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant();
    var dynamic=new DynamicMethod("Recovered_Vector3_Addition",typeof(Vec3),[typeof(Vec3),typeof(Vec3)],typeof(Program).Module,true);
    var info=dynamic.GetDynamicILInfo();var signature=SignatureHelper.GetLocalVarSigHelper();
    foreach(var local in body.LocalVariables)signature.AddArgument(local.LocalType==type?typeof(Vec3):local.LocalType,local.IsPinned);
    info.SetLocalSignature(signature.GetSignature());
    var operations=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static).Where(f=>f.FieldType==typeof(OpCode)).Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>unchecked((ushort)o.Value));
    int offset=0;
    while(offset<code.Length){
        ushort value=code[offset++];if(value==0xfe)value=(ushort)(0xfe00|code[offset++]);var op=operations[value];
        switch(op.OperandType){case OperandType.InlineNone:continue;case OperandType.ShortInlineI:case OperandType.ShortInlineVar:case OperandType.ShortInlineBrTarget:offset++;continue;case OperandType.InlineVar:offset+=2;continue;case OperandType.InlineI8:case OperandType.InlineR:offset+=8;continue;case OperandType.InlineI:case OperandType.ShortInlineR:case OperandType.InlineBrTarget:offset+=4;continue;case OperandType.InlineSwitch:offset+=4+4*BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(offset,4));continue;}
        int token=BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(offset,4)),replacement;
        if(op.OperandType==OperandType.InlineField){var field=method.Module.ResolveField(token)!;if(field.DeclaringType!=type||field.FieldType!=typeof(float))throw new Exception("Unexpected field");replacement=info.GetTokenFor(typeof(Vec3).GetField(field.Name)!.FieldHandle);}
        else if(op.OperandType==OperandType.InlineType){if(method.Module.ResolveType(token)!=type)throw new Exception("Unexpected type token");replacement=info.GetTokenFor(typeof(Vec3).TypeHandle);}
        else throw new Exception("Unexpected operand "+op.OperandType);
        BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(offset,4),replacement);offset+=4;
    }
    info.SetCode(code,body.MaxStackSize);var add=dynamic.CreateDelegate<Func<Vec3,Vec3,Vec3>>();
    using var document=JsonDocument.Parse(File.ReadAllText(fixture));
    foreach(var row in document.RootElement.EnumerateArray()){
        var a=row.GetProperty("a").EnumerateArray().Select(v=>v.GetUInt32()).ToArray();var b=row.GetProperty("b").EnumerateArray().Select(v=>v.GetUInt32()).ToArray();var want=row.GetProperty("result").EnumerateArray().Select(v=>v.GetUInt32()).ToArray();
        var result=add(Vec3.From(a),Vec3.From(b));var got=result.Bits();checks+=3;if(!got.SequenceEqual(want))failures.Add(new{index=cases,got,want});cases++;
    }
}catch(Exception ex){fatal=ex.GetType().FullName+": "+ex.Message;}
var report=new{status=fatal==null&&failures.Count==0&&cases>0?"PASS_RECOVERED_VECTOR3_VS_ORIGINAL_FP_ABI":"RECOVERED_VECTOR3_ABI_LIMITATION",recovery_run=run,cases,checks,failure_count=failures.Count,first_failures=failures.Take(8),fatal,body_il_sha256=ilHash,
    assembly_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assemblyPath))).ToLowerInvariant(),fixture_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fixture))).ToLowerInvariant(),
    scope="Recovered addition CIL in a DynamicMethod with the same-size three-float struct substituted only for the Unity value type and exact x/y/z field/type tokens. Arithmetic, control-flow bytes and scalar locals remain. Avoids Unity class initialization; no game DLL edits, runtime method mocks or whole-game/other-ABI certification."};
var text=JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true});File.WriteAllText(Guard($"reports/recovered-vector3-{run}.json"),text+"\n");Console.WriteLine(text);return report.status=="PASS_RECOVERED_VECTOR3_VS_ORIGINAL_FP_ABI"?0:2;

public struct Vec3{public float x,y,z;public static Vec3 From(uint[] b)=>new(){x=BitConverter.Int32BitsToSingle(unchecked((int)b[0])),y=BitConverter.Int32BitsToSingle(unchecked((int)b[1])),z=BitConverter.Int32BitsToSingle(unchecked((int)b[2]))};public uint[] Bits()=>[unchecked((uint)BitConverter.SingleToInt32Bits(x)),unchecked((uint)BitConverter.SingleToInt32Bits(y)),unchecked((uint)BitConverter.SingleToInt32Bits(z))];}
