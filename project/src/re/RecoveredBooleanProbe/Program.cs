using System.Reflection;
using System.Reflection.Emit;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if(args.Length is <2 or >3||!Regex.IsMatch(args[1],"^[a-z0-9-]+$"))throw new ArgumentException("USB root and recovery run, optional relative assembly path required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar),run=args[1];
string Guard(string relative) {
    var path=Path.GetFullPath(Path.Combine(root,relative));
    if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside USB workspace");
    for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)
        if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point forbidden");
    return path;
}
var reference=typeof(ReferenceSetter);var flags=BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static;
var referenceSet=(Action<bool>)Clone(reference.GetMethod("Set",flags)!,reference.GetField("Flag",flags)!,reference.GetMethod("Init",flags)!,false);
var referenceGet=(Func<bool>)Clone(reference.GetMethod("Get",flags)!,reference.GetField("Flag",flags)!,reference.GetMethod("Init",flags)!,true);
foreach(bool before in new[]{false,true})foreach(bool value in new[]{false,true}) {
    Boundary.Flag=before;Boundary.Calls=0;referenceSet(value);
    if(referenceGet()!=value||Boundary.Calls!=(!before&&value?1:0))throw new Exception("Isolation reference failed");
}
string assemblyPath=Guard(args.Length==3?args[2]:$"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp-firstpass.dll");
var fixture=Guard("analysis/il2cpp/boolean-native-fixtures-v1.json");
var failures=new List<object>();int cases=0;string? fatal=null;
try {
var assembly=Assembly.LoadFrom(assemblyPath);var type=assembly.GetType("AdvLog",true)!;
var property=type.GetProperty("LogNow",flags)!;var field=type.GetField("_logNow",flags)!;var init=type.GetMethod("Init",flags)!;
var setter=(Action<bool>)Clone(property.SetMethod!,field,init,false);var getter=(Func<bool>)Clone(property.GetMethod!,field,init,true);
using var document=JsonDocument.Parse(File.ReadAllText(fixture));
foreach(var row in document.RootElement.EnumerateArray()) {
    bool before=row.GetProperty("current").GetBoolean(),requested=row.GetProperty("requested").GetBoolean();
    Boundary.Flag=before;Boundary.Calls=0;setter(requested);bool actualGet=getter();
    if(Boundary.Flag!=row.GetProperty("stored").GetBoolean()||actualGet!=row.GetProperty("getter").GetBoolean()||Boundary.Calls!=row.GetProperty("initialization_calls").GetInt32())
        failures.Add(new{before,requested,stored=Boundary.Flag,getter=actualGet,calls=Boundary.Calls});
    cases++;
}
}catch(Exception ex){fatal=ex.GetType().FullName+": "+ex.Message;}
var report=new{status=fatal==null&&failures.Count==0&&cases>0?"PASS_RECOVERED_BOOLEAN_DECISIONS_VS_ORIGINAL_NATIVE":"RECOVERED_BOOLEAN_BEHAVIOR_MISMATCH",recovery_run=run,
    cases,checks=cases*3,isolation_reference_cases=4,failures,fatal,
    assembly_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assemblyPath))).ToLowerInvariant(),
    fixture_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fixture))).ToLowerInvariant(),
    scope="Executes recovered getter/setter CIL in DynamicMethods. Exact field tokens map to a same-type boolean test field and the sole Init callback maps to an observable counter. All other instruction and branch bytes/local types remain. No game DLL modification; class initialization, Init contents and complete-game parity are outside scope."};
var text=JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true});
File.WriteAllText(Guard($"reports/recovered-boolean-setter-{run}.json"),text+"\n");Console.WriteLine(text);
return report.status=="PASS_RECOVERED_BOOLEAN_DECISIONS_VS_ORIGINAL_NATIVE"?0:2;

static Delegate Clone(MethodInfo method,FieldInfo sourceField,MethodInfo sourceInit,bool getter) {
    var body=method.GetMethodBody()!;if(body.ExceptionHandlingClauses.Count!=0)throw new Exception("Unexpected exception region");
    var code=body.GetILAsByteArray()!;
    var dynamic=new DynamicMethod("Recovered_"+method.Name,getter?typeof(bool):typeof(void),getter?Type.EmptyTypes:[typeof(bool)],typeof(Program).Module,true);
    var info=dynamic.GetDynamicILInfo();var signature=SignatureHelper.GetLocalVarSigHelper();
    foreach(var local in body.LocalVariables)signature.AddArgument(local.LocalType,local.IsPinned);
    info.SetLocalSignature(signature.GetSignature());
    var operations=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static).Where(f=>f.FieldType==typeof(OpCode))
        .Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>unchecked((ushort)o.Value));
    int offset=0,fields=0,calls=0;
    while(offset<code.Length) {
        ushort value=code[offset++];if(value==0xfe)value=(ushort)(0xfe00|code[offset++]);var op=operations[value];
        switch(op.OperandType) {
            case OperandType.InlineNone:continue;
            case OperandType.ShortInlineI:case OperandType.ShortInlineVar:case OperandType.ShortInlineBrTarget:offset++;continue;
            case OperandType.InlineVar:offset+=2;continue;
            case OperandType.InlineI8:case OperandType.InlineR:offset+=8;continue;
            case OperandType.InlineI:case OperandType.ShortInlineR:case OperandType.InlineBrTarget:offset+=4;continue;
            case OperandType.InlineSwitch:offset+=4+4*BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(offset,4));continue;
        }
        int token=BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(offset,4)),replacement;
        if(op.OperandType==OperandType.InlineField) {
            var field=method.Module.ResolveField(token)!;
            if(field.Module!=sourceField.Module||field.MetadataToken!=sourceField.MetadataToken||op!=OpCodes.Ldsfld&&op!=OpCodes.Stsfld)throw new Exception("Unexpected field");
            replacement=info.GetTokenFor(typeof(Boundary).GetField(nameof(Boundary.Flag))!.FieldHandle);fields++;
        } else if(op.OperandType==OperandType.InlineMethod) {
            var called=method.Module.ResolveMethod(token)!;
            if(called.Module!=sourceInit.Module||called.MetadataToken!=sourceInit.MetadataToken||op!=OpCodes.Call)throw new Exception("Unexpected callback");
            replacement=info.GetTokenFor(typeof(Boundary).GetMethod(nameof(Boundary.Init))!.MethodHandle);calls++;
        } else throw new Exception("Unexpected operand "+op.OperandType);
        BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(offset,4),replacement);offset+=4;
    }
    if(fields==0||calls!=(getter?0:1))throw new Exception("Expected field/callback contract differs");
    info.SetCode(code,body.MaxStackSize);return getter?dynamic.CreateDelegate<Func<bool>>():dynamic.CreateDelegate<Action<bool>>();
}

public static class Boundary { public static bool Flag;public static int Calls;public static void Init()=>Calls++; }
static class ReferenceSetter { public static bool Flag=false;public static bool Get()=>Flag;public static void Init(){}public static void Set(bool value){if(Flag!=value){Flag=value;if(Flag)Init();}} }
