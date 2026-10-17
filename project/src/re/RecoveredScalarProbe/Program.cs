using System.Reflection;
using System.Reflection.Emit;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if(args.Length is <2 or >3||!Regex.IsMatch(args[1],"^[a-z0-9-]+$")||(args.Length==3&&args[2]!="--isolate-accessors"))throw new ArgumentException("USB root, recovery run and optional --isolate-accessors required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar),run=args[1];
bool isolated=args.Length==3;
string Guard(string relative) {
    var path=Path.GetFullPath(Path.Combine(root,relative));
    if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside USB workspace");
    for(DirectoryInfo? dir=new(Path.GetDirectoryName(path)!);dir!=null;dir=dir.Parent)
        if(dir.Exists&&(dir.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point forbidden");
    return path;
}
string assemblyPath=Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp-firstpass.dll");
string fixture=Guard("analysis/il2cpp/scalar-native-fixtures-v1.jsonl");
int cases=0,checks=0,isolationSelfChecks=0;var failures=new List<object>();string? fatal=null,staticZeroType=null,staticZeroError=null;var methodHeaders=new List<object>();
try {
    if(isolated) {
        var reference=typeof(IsolationReference);var referenceField=reference.GetField("values",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var get=(Func<int[],int>)Isolate(reference.GetProperty("Value")!.GetMethod!,referenceField,true);
        var set=(Action<int[],int>)Isolate(reference.GetProperty("Value")!.SetMethod!,referenceField,false);
        int[] sample=[17];if(get(sample)!=17)throw new InvalidProgramException("Isolation reference getter failed");isolationSelfChecks++;
        set(sample,-2);if(sample[0]!=-2)throw new InvalidProgramException("Isolation reference setter failed");isolationSelfChecks++;
        try {get([]);throw new InvalidProgramException("Isolation reference bounds check failed");}catch(IndexOutOfRangeException){isolationSelfChecks++;}
    }
    var assembly=Assembly.LoadFrom(assemblyPath);var type=assembly.GetType("VersionContainer",throwOnError:true)!;
    var field=type.GetField("_versionSource",BindingFlags.Instance|BindingFlags.NonPublic)!;
    var clones=new Dictionary<string,Delegate>();
    foreach(var line in File.ReadLines(fixture)) {
        using var document=JsonDocument.Parse(line);var row=document.RootElement;
        var source=row.GetProperty("source").EnumerateArray().Select(v=>v.GetInt32()).ToArray();
        var expected=row.GetProperty("after").EnumerateArray().Select(v=>v.GetInt32()).ToArray();
        string name=row.GetProperty("property").GetString()!,operation=row.GetProperty("operation").GetString()!;
        int? actual=null;string? exception=null;var exceptionChain=new List<string>();
        try {
            var property=type.GetProperty(name)!;
            if(isolated) {
                string key=operation+name;
                if(!clones.TryGetValue(key,out var clone)) {
                    var recovered=operation=="get"?property.GetMethod!:property.SetMethod!;
                    var recoveredBody=recovered.GetMethodBody()!;
                    methodHeaders.Add(new{method=recovered.Name,max_stack=recoveredBody.MaxStackSize,locals=recoveredBody.LocalVariables.Select(l=>l.LocalType.FullName),init_locals=recoveredBody.InitLocals});
                    clone=Isolate(recovered,field,operation=="get");clones.Add(key,clone);
                }
                if(operation=="get")actual=((Func<int[],int>)clone)(source);
                else ((Action<int[],int>)clone)(source,row.GetProperty("value").GetInt32());
            } else {
                var instance=RuntimeHelpers.GetUninitializedObject(type);field.SetValue(instance,source);
                if(operation=="get")actual=(int)property.GetValue(instance)!;
                else property.SetValue(instance,row.GetProperty("value").GetInt32());
            }
        } catch(Exception ex) {
            while(ex.InnerException!=null) {exceptionChain.Add(ex.GetType().FullName+": "+ex.Message);ex=ex.InnerException;}
            exceptionChain.Add(ex.GetType().FullName+": "+ex.Message);
            exception=ex.GetType().FullName;
        }
        var wantedException=row.GetProperty("exception").GetString();checks+=2;
        bool matches=exception==wantedException&&source.SequenceEqual(expected);
        if(operation=="get"&&wantedException==null) {checks++;matches&=actual==row.GetProperty("result").GetInt32();}
        if(!matches)failures.Add(new{index=cases,property=name,operation,actual,exception,exception_chain=exceptionChain,expected_exception=wantedException,array_matches=source.SequenceEqual(expected)});
        cases++;
    }
    if(!isolated) {
        try {staticZeroType=type.GetField("Zero",BindingFlags.Static|BindingFlags.Public)!.GetValue(null)?.GetType().FullName;}
        catch(Exception ex) {staticZeroError=ex.GetType().FullName+": "+ex.Message;}
    }
} catch(Exception ex) {fatal=ex.GetType().FullName+": "+ex.Message;}
string status=fatal==null&&failures.Count==0&&cases>0?"PASS_RECOVERED_SCALARS_VS_ORIGINAL_NATIVE_FIXTURES":"RECOVERY_EXECUTION_LIMITATION_CONFIRMED";
var report=new{status,recovery_run=run,isolated_accessors=isolated,isolation_self_checks=isolationSelfChecks,method_headers=methodHeaders,cases,checks,failure_count=failures.Count,first_failures=failures.Take(16),fatal,
    separate_static_identity_witness=new{expected="VersionContainer",actual=staticZeroType,error=staticZeroError,tested=!isolated,matches=!isolated&&staticZeroType=="VersionContainer"},
    assembly_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assemblyPath))).ToLowerInvariant(),
    fixture_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fixture))).ToLowerInvariant(),
    scope=isolated?"Recovered accessor CIL isolated in DynamicMethods: the sole _versionSource field load becomes a same-size NOP span, and an int[] argument supplies that field directly; metadata tokens are remapped to their same runtime targets. All other instruction/branch bytes and local types are retained. Class initialization and constructors are deliberately outside this experiment. This is a bounded CIL comparison, not executable recovered whole-game source.":"Executes recovered CIL accessors directly in the installed .NET runtime against original ARM64 fixtures. Constructor bypass via uninitialized object and private field injection is explicit; class initialization can still block execution. No Windows game, original-runtime parity, constructor/static-initialization, UI or combat claim."};
var text=JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true});
File.WriteAllText(Guard($"reports/recovered-scalars-{(isolated?"isolated-":"")}{run}.json"),text+"\n");Console.WriteLine(text);
return status.StartsWith("PASS")?0:2;

static Delegate Isolate(MethodInfo method,FieldInfo sourceField,bool getter) {
    var body=method.GetMethodBody()??throw new InvalidDataException("Missing recovered method body");
    if(body.ExceptionHandlingClauses.Count!=0)throw new InvalidDataException("Unexpected exception region");
    byte[] code=body.GetILAsByteArray()!;
    var dynamic=new DynamicMethod("Recovered_"+method.Name,getter?typeof(int):typeof(void),getter?[typeof(int[])]:[typeof(int[]),typeof(int)],typeof(Program).Module,true);
    var info=dynamic.GetDynamicILInfo();var signature=SignatureHelper.GetLocalVarSigHelper();
    foreach(var local in body.LocalVariables)signature.AddArgument(local.LocalType,local.IsPinned);
    info.SetLocalSignature(signature.GetSignature());
    var operations=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static).Where(f=>f.FieldType==typeof(OpCode))
        .Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>unchecked((ushort)o.Value));
    int offset=0,fieldLoads=0;
    while(offset<code.Length) {
        int start=offset;ushort value=code[offset++];if(value==0xfe)value=(ushort)(0xfe00|code[offset++]);var op=operations[value];
        int token=0,newToken=0;
        switch(op.OperandType) {
            case OperandType.InlineNone:continue;
            case OperandType.ShortInlineI:case OperandType.ShortInlineVar:case OperandType.ShortInlineBrTarget:offset++;continue;
            case OperandType.InlineVar:offset+=2;continue;
            case OperandType.InlineI8:case OperandType.InlineR:offset+=8;continue;
            case OperandType.InlineSwitch:offset+=4+4*BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(offset,4));continue;
        }
        token=BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(offset,4));
        switch(op.OperandType) {
            case OperandType.InlineField:
                var field=method.Module.ResolveField(token)!;
                if(op!=OpCodes.Ldfld||field.MetadataToken!=sourceField.MetadataToken||field.Module!=sourceField.Module)throw new InvalidDataException("Unexpected isolated field operation");
                Array.Clear(code,start,offset+4-start);fieldLoads++;break;
            case OperandType.InlineMethod:
                var called=method.Module.ResolveMethod(token)!;newToken=info.GetTokenFor(called.MethodHandle,called.DeclaringType!.TypeHandle);break;
            case OperandType.InlineType:newToken=info.GetTokenFor(method.Module.ResolveType(token).TypeHandle);break;
            case OperandType.InlineString:newToken=info.GetTokenFor(method.Module.ResolveString(token));break;
            case OperandType.InlineTok:
                newToken=method.Module.ResolveMember(token) switch {
                    Type tokenType=>info.GetTokenFor(tokenType.TypeHandle),
                    FieldInfo tokenField=>info.GetTokenFor(tokenField.FieldHandle,tokenField.DeclaringType!.TypeHandle),
                    MethodBase tokenMethod=>info.GetTokenFor(tokenMethod.MethodHandle,tokenMethod.DeclaringType!.TypeHandle),
                    _=>throw new InvalidDataException("Unexpected isolated metadata token target")
                };break;
            case OperandType.InlineSig:throw new InvalidDataException("Unexpected isolated signature token");
        }
        if(newToken!=0)BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(offset,4),newToken);
        offset+=4;
    }
    if(fieldLoads!=1)throw new InvalidDataException("Expected one array field load");
    info.SetCode(code,body.MaxStackSize);return getter?dynamic.CreateDelegate<Func<int[],int>>():dynamic.CreateDelegate<Action<int[],int>>();
}

sealed class IsolationReference {
    private int[] values=null!;
    public int Value {
        get {GC.KeepAlive(typeof(IsolationReference));var source=values;if(source.Length==0)throw new IndexOutOfRangeException();return source[0];}
        set {var source=values;if(source.Length==0)throw new IndexOutOfRangeException();source[0]=value;}
    }
}
