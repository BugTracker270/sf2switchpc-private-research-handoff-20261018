using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if(args.Length!=3||!Regex.IsMatch(args[1],"^[a-z0-9-]+$")||!Regex.IsMatch(args[2],"^[a-z0-9-]+$"))throw new ArgumentException("Verified USB root, baseline run and current run required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar),baseline=args[1],run=args[2];
string Guard(string relative){string path=Path.GetFullPath(Path.Combine(root,relative));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");for(DirectoryInfo? d=new(Path.GetDirectoryName(path)!);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point");return path;}
string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
var ops=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static).Where(f=>f.FieldType==typeof(OpCode)).Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>unchecked((ushort)o.Value));
int checks=0;void Check(bool condition,string name){if(!condition)throw new Exception(name);checks++;}
Snapshot Inspect(string selectedRun){
    string folder=Guard($"analysis/il2cpp/cpp2il-recovery-{selectedRun}");var context=new AssemblyLoadContext("ClassPhi_"+selectedRun,true);
    context.Resolving+=(c,name)=>File.Exists(Path.Combine(folder,name.Name+".dll"))?c.LoadFromAssemblyPath(Path.Combine(folder,name.Name+".dll")):null;
    string assemblyPath=Path.Combine(folder,"Assembly-CSharp-firstpass.dll");var assembly=context.LoadFromAssemblyPath(assemblyPath);var type=assembly.GetType("BundlesUtil",true)!;
    var method=type.GetMethods(BindingFlags.NonPublic|BindingFlags.Public|BindingFlags.Static|BindingFlags.DeclaredOnly).Single(m=>m.Name=="GetAssetBundleSafe"&&m.GetParameters() is[{ParameterType.IsByRef:true}p]&&p.ParameterType.GetElementType()==typeof(string));
    var field=type.GetField("currentConfig",BindingFlags.NonPublic|BindingFlags.Static)!;Check(field.DeclaringType==type&&field.IsStatic,"Original currentConfig field differs");
    var body=method.GetMethodBody()!;var bytes=body.GetILAsByteArray()!;var rows=new List<Row>();
    for(int at=0;at<bytes.Length;){int offset=at;ushort code=bytes[at++];if(code==0xFE)code=(ushort)(0xFE00|bytes[at++]);var op=ops[code];int operand=at;int size=op.OperandType switch{OperandType.InlineNone=>0,OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget=>1,OperandType.InlineVar=>2,OperandType.InlineI8 or OperandType.InlineR=>8,OperandType.InlineSwitch=>4+4*BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(at,4)),_=>4};at+=size;if(at>bytes.Length)throw new IOException("Truncated original CIL");int? token=op.OperandType is OperandType.InlineField or OperandType.InlineMethod or OperandType.InlineType or OperandType.InlineTok or OperandType.InlineString?BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(operand,4)):null;rows.Add(new(offset,op,token));}
    bool Same(MemberInfo? actual,MemberInfo expected)=>actual?.Module.ModuleVersionId==expected.Module.ModuleVersionId&&actual.MetadataToken==expected.MetadataToken;
    bool Initializer(Row row){if(row.Op!=OpCodes.Call||row.Token==null)return false;var called=method.Module.ResolveMethod(row.Token.Value);return called is MethodInfo m&&m.Name=="RunClassConstructor"&&m.IsStatic&&m.ReturnType==typeof(void)&&m.DeclaringType?.FullName=="System.Runtime.CompilerServices.RuntimeHelpers"&&m.GetParameters() is[{ParameterType:var parameter}]&&parameter==typeof(RuntimeTypeHandle);}
    var meaningful=rows.Where(r=>r.Op!=OpCodes.Nop).ToArray();var pairs=new List<object>();int postFieldReads=0;
    for(int i=0;i<meaningful.Length;i++)if(Initializer(meaningful[i])){
        Check(i>0&&meaningful[i-1].Op==OpCodes.Ldtoken&&Same(method.Module.ResolveType(meaningful[i-1].Token!.Value),type),"Class request does not take exact original BundlesUtil ldtoken");
        var following=meaningful.Skip(i+1).TakeWhile(r=>r.Op.FlowControl is not(FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw)).ToArray();
        var reload=following.FirstOrDefault(r=>r.Op==OpCodes.Ldsfld&&r.Token!=null&&Same(method.Module.ResolveField(r.Token.Value),field));
        bool post=reload!=null;if(post)postFieldReads++;
        pairs.Add(new{token_offset=meaningful[i-1].Offset,call_offset=meaningful[i].Offset,owner_token=$"0x{type.MetadataToken:X8}",helper_token=$"0x{meaningful[i].Token:X8}",original_current_config_reload_before_next_branch=post,reload_offset=reload?.Offset});
    }
    var strings=rows.Where(r=>r.Op==OpCodes.Ldstr).Select(r=>method.Module.ResolveString(r.Token!.Value)).ToArray();
    int raw=strings.Count(s=>s.Contains("Method not found @B2E720",StringComparison.Ordinal));
    int flags=strings.Count(s=>s.Contains("Unmanaged memory load:",StringComparison.Ordinal)&&s.Contains("Il2CppClass<",StringComparison.Ordinal)&&Regex.IsMatch(s,@"\+(122|D4)\]"));
    Check(Hash(method.GetMethodBody()!.GetILAsByteArray()!)==Hash(bytes),"Inspection changed original CIL");
    var snapshot=new Snapshot(selectedRun,Hash(File.ReadAllBytes(assemblyPath)),Hash(bytes),method.MetadataToken,type.MetadataToken,field.MetadataToken,pairs.Count,raw,flags,postFieldReads,pairs);
    context.Unload();return snapshot;
}
var before=Inspect(baseline);var after=Inspect(run);
Check(before.ConstructorRequests==2&&before.RawHelperDiagnostics==1,"Baseline does not retain two exact requests plus one raw helper diagnostic");
Check(after.ConstructorRequests==3&&after.RawHelperDiagnostics==0,"Current body does not contain three exact requests and zero raw-helper diagnostics");
Check(before.RawClassFlagDiagnostics==4&&after.RawClassFlagDiagnostics==4,"Unresolved original class flag diagnostics changed");
Check(before.PostConstructorFieldReloads==1&&after.PostConstructorFieldReloads==2,"Post-constructor currentConfig field-read correlation differs");
var report=new{status="PASS_ACTUAL_GETSAFE_CLASS_INITIALIZER_CIL_CORRELATION",recovery_run=run,baseline_run=baseline,checks,before,after,
    assembly_sha256=after.AssemblySha256,baseline_assembly_sha256=before.AssemblySha256,cil_sha256=after.CilSha256,baseline_cil_sha256=before.CilSha256,
    recovered_cil_or_source_modified=false,tokens_remapped=0,game_methods_invoked=0,class_initializers_invoked=0,whole_method_executed=false,
    scope="Inspects unchanged actual recovered GetAssetBundleSafe bodies in separate collectible contexts. Every emitted RunClassConstructor request takes the exact original BundlesUtil ldtoken and real RuntimeTypeHandle API signature. The formerly raw request becomes a third exact pair, with its original currentConfig static-field reload retained before the next branch. Four raw class-flag diagnostics remain; original methods/.cctors are never invoked. This is structural CIL/native-IR correlation, not whole-method execution, complete semantic recovery, source buildability or full decompilation."};
File.WriteAllText(Guard($"reports/recovered-class-phi-{run}.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true})+"\n");Console.WriteLine(JsonSerializer.Serialize(new{report.status,checks,before_requests=before.ConstructorRequests,after_requests=after.ConstructorRequests,before_raw=before.RawHelperDiagnostics,after_raw=after.RawHelperDiagnostics}));

sealed record Row(int Offset,OpCode Op,int? Token);
sealed record Snapshot(string Run,string AssemblySha256,string CilSha256,int MethodToken,int OwnerToken,int FieldToken,int ConstructorRequests,int RawHelperDiagnostics,int RawClassFlagDiagnostics,int PostConstructorFieldReloads,List<object> Pairs);
