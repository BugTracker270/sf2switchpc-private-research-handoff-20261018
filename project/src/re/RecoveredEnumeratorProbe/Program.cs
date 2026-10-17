using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if(args.Length!=2||!Regex.IsMatch(args[1],"^[a-z0-9-]+$"))throw new ArgumentException("Verified USB root and recovery run required");
string root=Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar),run=args[1];
string Guard(string relative)
{
    string p=Path.GetFullPath(Path.Combine(root,relative));
    if(!p.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside workspace");
    for(DirectoryInfo? d=new(Path.GetDirectoryName(p)!);d!=null;d=d.Parent)
        if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point forbidden");
    return p;
}
string Hash(byte[] data)=>Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
var options=new JsonSerializerOptions{WriteIndented=true};
var tests=new List<CheckRow>();var cases=new List<object>();var fragments=new List<object>();var boundaries=new List<object>();
var evidence=new Dictionary<string,object?>();string? fatal=null;
int successfulCases=0,totalRuntimeChecks=0;
void Check(string name,bool ok)=>tests.Add(new(name,ok?"PASS":"FAIL"));
string folder=Guard($"analysis/il2cpp/cpp2il-recovery-{run}"),assemblyPath=Path.Combine(folder,"Assembly-CSharp.dll");
var loadContext=new AssemblyLoadContext("recovered-enumerator-"+run,true);
loadContext.Resolving+=(c,n)=>File.Exists(Path.Combine(folder,n.Name+".dll"))?c.LoadFromAssemblyPath(Path.Combine(folder,n.Name+".dll")):null;
try
{
    var nativeImage=File.ReadAllBytes(Guard("analysis/nso/main-uncompressed.nso"));
    using var native=JsonDocument.Parse(File.ReadAllText(Guard("reports/enumerator-native-return-v31.json")));
    var witness=native.RootElement;
    Check("original native indirect-return witness",witness.GetProperty("status").GetString()=="PASS_ORIGINAL_NATIVE_INDIRECT_ENUMERATOR_RETURN_ONLY"
        &&witness.GetProperty("cases").GetInt32()==6&&witness.GetProperty("checks").GetInt32()==36
        &&witness.GetProperty("native_source_sha256").GetString()==Hash(nativeImage)
        &&witness.GetProperty("getenumerator_code_sha256").GetString()==Hash(nativeImage.AsSpan(0x1585F60+0x100,36).ToArray())
        &&witness.GetProperty("constructor_code_sha256").GetString()==Hash(nativeImage.AsSpan(0x11DD130+0x100,16).ToArray()));
    var assembly=loadContext.LoadFromAssemblyPath(assemblyPath);
    var type=assembly.GetType("Nekki.SF2.Core.Fights.Fight",true)!;
    var method=type.GetMethods(BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.DeclaredOnly).Single(m=>m.Name=="SetStage");
    var body=method.GetMethodBody()!;byte[] bytes=body.GetILAsByteArray()!;
    var opcodes=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static).Where(f=>f.FieldType==typeof(OpCode)).Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>unchecked((ushort)o.Value));
    var rows=new List<Row>();
    for(int at=0;at<bytes.Length;)
    {
        int start=at;ushort code=bytes[at++];if(code==0xFE)code=(ushort)(0xFE00|bytes[at++]);
        var op=opcodes[code];int operandAt=at;
        int width=op.OperandType switch{OperandType.InlineNone=>0,OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget=>1,
            OperandType.InlineVar=>2,OperandType.InlineI8 or OperandType.InlineR=>8,OperandType.InlineSwitch=>4+4*BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(at,4)),_=>4};
        at+=width;if(at>bytes.Length)throw new InvalidDataException("Truncated CIL");
        int operand=op.OperandType==OperandType.ShortInlineVar?bytes[operandAt]:op.OperandType==OperandType.InlineVar?BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(operandAt,2)):width==4?BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(operandAt,4)):0;
        if(op.OperandType==OperandType.InlineNone&&(op.Name!.StartsWith("stloc.")||op.Name.StartsWith("ldloc.")))operand=int.Parse(op.Name[^1..]);
        MemberInfo? member=op.OperandType is OperandType.InlineMethod or OperandType.InlineType or OperandType.InlineField or OperandType.InlineTok?method.Module.ResolveMember(operand):null;
        rows.Add(new(start,at,operandAt,op,operand,member));
    }
    Row Before(Row row)=>rows.Take(rows.IndexOf(row)).Last(r=>r.Op!=OpCodes.Nop);
    Row After(Row row)=>rows.Skip(rows.IndexOf(row)+1).First(r=>r.Op!=OpCodes.Nop);
    bool IsEnum(int slot)=>body.LocalVariables[slot].LocalType.IsGenericType&&body.LocalVariables[slot].LocalType.GetGenericTypeDefinition().FullName=="System.Collections.Generic.List`1+Enumerator";
    var get=rows.Single(r=>r.Member is MethodInfo m&&m.Name=="GetEnumerator"&&m.DeclaringType!.IsGenericType&&m.DeclaringType.GetGenericTypeDefinition()==typeof(List<>));
    var getMethod=(MethodInfo)get.Member!;var sourceList=getMethod.DeclaringType!;var sourceEnum=getMethod.ReturnType;var model=sourceList.GetGenericArguments().Single();
    var inputField=Before(get);var inputThis=Before(inputField);var store=After(get);
    if(inputThis.Op!=OpCodes.Ldarg_0||inputField.Op!=OpCodes.Ldfld||inputField.Member is not FieldInfo models||models.FieldType!=sourceList
        ||!store.Op.Name!.StartsWith("stloc")||!IsEnum(store.Operand))throw new InvalidDataException("Exact GetEnumerator input field/call/store shape changed");
    var allConsumers=rows.Where(r=>r.Member is MethodInfo m&&m.DeclaringType==sourceEnum&&m.Name is "MoveNext" or "get_Current" or "Dispose")
        .Select(r=>new Consumer(Before(r),r,r.Member!.Name=="Dispose"?null:After(r))).ToArray();
    if(allConsumers.Any(c=>!c.Receiver.Op.Name!.StartsWith("ldloca")||!IsEnum(c.Receiver.Operand)))throw new InvalidDataException("Exact direct-address consumer shape changed");
    var move=allConsumers.Single(c=>c.Call.Member!.Name=="MoveNext");var current=allConsumers.Single(c=>c.Call.Member!.Name=="get_Current");
    var disposes=allConsumers.Where(c=>c.Call.Member!.Name=="Dispose").ToArray();
    if(disposes.Length is <1 or >2||allConsumers.Length!=2+disposes.Length)throw new InvalidDataException("Expected one or two original Dispose sites");
    var dispose=disposes[0];
    if(move.Store==null||current.Store==null||!move.Store.Op.Name!.StartsWith("stloc")||!current.Store.Op.Name!.StartsWith("stloc"))throw new InvalidDataException("Actual result storage changed");
    int moveSlot=move.Store.Operand,currentSlot=current.Store.Operand;
    Check("original InitLocals contract",body.InitLocals);
    Check("concrete game Model provenance",model.FullName=="Nekki.SF2.Core.Fights.Model.Model"&&models.DeclaringType==type&&getMethod.ReturnType.GetGenericArguments().Single()==model
        &&((MethodInfo)current.Call.Member!).ReturnType==model);
    Check("actual consumer slot equals actual returned slot",allConsumers.All(c=>c.Receiver.Operand==store.Operand));
    Check("actual returned and consumed local types agree",allConsumers.All(c=>body.LocalVariables[c.Receiver.Operand].LocalType==sourceEnum));
    Check("MoveNext original scalar result type",body.LocalVariables[moveSlot].LocalType==typeof(bool)||body.LocalVariables[moveSlot].LocalType==typeof(int));
    Check("Current original result local type",body.LocalVariables[currentSlot].LocalType==model);
    var scalarEnumStores=rows.Where(r=>r.Op.Name!.StartsWith("stloc")&&IsEnum(r.Operand)).Where(r=>Before(r).Op.Name!.StartsWith("ldc.i4")).ToArray();
    Check("no scalar stores into enumerator locals",scalarEnumStores.Length==0);
    var enumSlots=body.LocalVariables.Where(v=>IsEnum(v.LocalIndex)).Select(v=>v.LocalIndex).ToArray();
    evidence["method_token"]=$"0x{method.MetadataToken:X8}";evidence["method_cil_sha256"]=Hash(bytes);evidence["method_cil_bytes"]=bytes.Length;
    evidence["source_model_type"]=model.AssemblyQualifiedName;evidence["source_models_field_token"]=$"0x{models.MetadataToken:X8}";
    evidence["source_list_type"]=sourceList.ToString();evidence["source_enumerator_type"]=sourceEnum.ToString();
    evidence["enum_local_slots"]=enumSlots;evidence["return_store_slot"]=store.Operand;evidence["consumer_slots"]=allConsumers.GroupBy(c=>c.Call.Member!.Name).ToDictionary(g=>g.Key,g=>g.First().Receiver.Operand);
    evidence["all_consumer_sites"]=allConsumers.Select(c=>new{name=c.Call.Member!.Name,call=c.Call.Offset,receiver=c.Receiver.Offset,slot=c.Receiver.Operand}).ToArray();
    evidence["native_indirect_return_buffer_bytes"]=24;evidence["host_enumerator_size"]=System.Runtime.CompilerServices.Unsafe.SizeOf<List<object>.Enumerator>();
    evidence["scalar_enum_store_offsets"]=scalarEnumStores.Select(r=>r.Offset).ToArray();
    evidence["local_signature_boundaries"]=body.LocalVariables.Select(local=>new{index=local.LocalIndex,source_type=local.LocalType.ToString(),
        host_type=IsEnum(local.LocalIndex)?typeof(List<object>.Enumerator).ToString():local.LocalIndex==moveSlot?local.LocalType.ToString():typeof(object).ToString(),
        role=IsEnum(local.LocalIndex)?"original enumerator storage":local.LocalIndex==moveSlot?"original MoveNext result":local.LocalIndex==currentSlot?"explicit Model output boundary":"unused opaque storage"}).ToArray();
    var hostEnum=typeof(List<object>.Enumerator);
    Dictionary<MemberInfo,MemberInfo> mapping=new(){[models]=typeof(HostFightInput).GetField(nameof(HostFightInput.Models))!,[getMethod]=typeof(List<object>).GetMethod("GetEnumerator")!,
        [move.Call.Member!]=hostEnum.GetMethod("MoveNext")!,[current.Call.Member!]=hostEnum.GetMethod("get_Current")!,[dispose.Call.Member!]=hostEnum.GetMethod("Dispose")!};
    foreach(var pair in mapping)boundaries.Add(new{source_token=$"0x{pair.Key.MetadataToken:X8}",source=pair.Key.ToString(),source_owner=pair.Key.DeclaringType!.ToString(),host=pair.Value.ToString(),host_owner=pair.Value.DeclaringType!.ToString()});
    Row[] GetRows(Row first,Row last)=>rows.Where(r=>r.Offset>=first.Offset&&r.End<=last.End).ToArray();
    var sourceFragments=new Dictionary<string,Row[]>{["get-input-call-store"]=GetRows(inputThis,store),["move-receiver-call-store"]=GetRows(move.Receiver,move.Store),
        ["current-receiver-call-store"]=GetRows(current.Receiver,current.Store),["dispose-receiver-call"]=GetRows(dispose.Receiver,dispose.Call)};
    if(disposes.Length==2)sourceFragments["dispose-receiver-call-1"]=GetRows(disposes[1].Receiver,disposes[1].Call);
    foreach(var pair in sourceFragments)
    {
        Check(pair.Key+" contains no unresolved helper or branch",pair.Value.All(r=>r.Op.FlowControl is not (FlowControl.Branch or FlowControl.Cond_Branch)&&
            (r.Member==null||mapping.ContainsKey(r.Member))));
        fragments.Add(new{name=pair.Key,start=pair.Value[0].Offset,end=pair.Value[^1].End,sha256=Hash(bytes[pair.Value[0].Offset..pair.Value[^1].End]),
            instructions=pair.Value.Select(r=>new{offset=r.Offset,op=r.Op.Name,operand=r.Member?.ToString()??r.Operand.ToString(),cil_member_token=r.Member!=null?$"0x{r.Operand:X8}":null})});
    }
    foreach(int count in new[]{0,1,3,8})RunCase(count,false);
    RunCase(3,true);

    void RunCase(int count,bool mutate)
    {
        var dynamic=new DynamicMethod($"actual_enumerator_{run}_{count}_{mutate}",typeof(void),[typeof(HostFightInput),typeof(ObservedTrace)],typeof(Program).Module,true){InitLocals=body.InitLocals};
        var info=dynamic.GetDynamicILInfo();var signature=SignatureHelper.GetLocalVarSigHelper();
        foreach(var local in body.LocalVariables)
            signature.AddArgument(IsEnum(local.LocalIndex)?hostEnum:local.LocalIndex==moveSlot?local.LocalType:typeof(object));
        info.SetLocalSignature(signature.GetSignature());
        var code=new List<byte>();var labels=new Dictionary<string,int>();var jumps=new List<(int At,string Label)>();int remappedOccurrences=0;
        void EmitFragment(string name)
        {
            var selected=sourceFragments[name];int first=selected[0].Offset;var fragment=bytes[first..selected[^1].End];
            foreach(var row in selected.Where(r=>r.Member!=null))
            {
                var replacement=mapping[row.Member!];
                int token=replacement is MethodInfo m?info.GetTokenFor(m.MethodHandle,m.DeclaringType!.TypeHandle):replacement is FieldInfo f?info.GetTokenFor(f.FieldHandle,f.DeclaringType!.TypeHandle):throw new InvalidDataException("Unexpected boundary member");
                BinaryPrimitives.WriteInt32LittleEndian(fragment.AsSpan(row.OperandAt-first,4),token);remappedOccurrences++;
            }
            code.AddRange(fragment);
        }
        void Call(MethodInfo m){code.Add(0x28);code.AddRange(BitConverter.GetBytes(info.GetTokenFor(m.MethodHandle,m.DeclaringType!.TypeHandle)));}
        void LoadLocal(int slot){code.AddRange([0xFE,0x0C,(byte)slot,(byte)(slot>>8)]);}
        void Branch(byte op,string label){code.Add(op);jumps.Add((code.Count,label));code.AddRange(new byte[4]);}
        void Move(){EmitFragment("move-receiver-call-store");code.Add(0x03);LoadLocal(moveSlot);Call(typeof(ObservedTrace).GetMethod(nameof(ObservedTrace.RecordMove))!);}
        void Current(){EmitFragment("current-receiver-call-store");code.Add(0x03);LoadLocal(currentSlot);Call(typeof(ObservedTrace).GetMethod(nameof(ObservedTrace.RecordCurrent))!);}
        void Dispose(int site){EmitFragment(site==1&&disposes.Length==2?"dispose-receiver-call-1":"dispose-receiver-call");code.Add(0x03);Call(typeof(ObservedTrace).GetMethod(nameof(ObservedTrace.RecordDispose))!);}
        EmitFragment("get-input-call-store");
        if(mutate){code.Add(0x02);Call(typeof(ObservedTrace).GetMethod(nameof(ObservedTrace.Mutate))!);}
        labels["loop"]=code.Count;Move();LoadLocal(moveSlot);Branch(0x39,"done");Current();Current();Branch(0x38,"loop");
        labels["done"]=code.Count;Move();Move();Current();Dispose(0);Dispose(1);Move();Current();code.Add(0x2A);
        foreach(var jump in jumps)BinaryPrimitives.WriteInt32LittleEndian(CollectionsMarshalSpan(code,jump.At,4),labels[jump.Label]-(jump.At+4));
        byte[] emitted=code.ToArray();info.SetCode(emitted,3);
        var values=Enumerable.Range(0,count).Select(_=>new object()).ToList();var input=new HostFightInput{Models=values};var actual=new ObservedTrace();string? exception=null,exceptionDetail=null;
        try{dynamic.CreateDelegate<Action<HostFightInput,ObservedTrace>>()(input,actual);}catch(Exception error){exception=error.GetType().FullName;exceptionDetail=error.ToString();}
        bool passed=mutate?exception==typeof(InvalidOperationException).FullName&&actual.Moves.Count==0&&actual.Currents.Count==0&&actual.Disposals==0:
            exception==null&&actual.Moves.SequenceEqual(Enumerable.Repeat(true,count).Concat(Enumerable.Repeat(false,4)))
            &&actual.Currents.Count==2*count+2&&actual.Currents.Take(2*count).Select((v,i)=>ReferenceEquals(v,values[i/2])).All(x=>x)
            &&actual.Currents.Skip(2*count).All(v=>v==null)&&actual.Disposals==2;
        int checks=mutate?4:6;totalRuntimeChecks+=checks;if(passed)successfulCases++;
        cases.Add(new{element_count=count,version_mutation=mutate,passed,exception,exception_detail=exceptionDetail,moves=actual.Moves,
            current_element_indices=actual.Currents.Select(v=>v==null?-1:values.FindIndex(x=>ReferenceEquals(v,x))),dispose_calls=actual.Disposals,
            fragment_cil_sha256=Hash(emitted),member_token_remap_occurrences=remappedOccurrences,original_local_indices_retained=true,
            injected_default_or_initobj=false,return_store_retargeted=false});
    }
}
catch(Exception error){fatal=error.ToString();}
loadContext.Unload();
string status=fatal==null&&tests.All(t=>t.Status=="PASS")&&successfulCases==5?"PASS_ACTUAL_RECOVERED_ENUMERATOR_CALLER_FRAGMENTS":"RECOVERY_EXECUTION_LIMITATION_CONFIRMED";
var report=new{status,recovery_run=run,structural_checks=tests.Count,runtime_checks=totalRuntimeChecks,successful_cases=successfulCases,cases=5,fatal,tests,evidence,
    assembly_sha256=File.Exists(assemblyPath)?Hash(File.ReadAllBytes(assemblyPath)):null,source_fragments=fragments,member_boundary_count=boundaries.Count,member_boundaries=boundaries,
    probe_source_sha256=Hash(File.ReadAllBytes(Guard("src/re/RecoveredEnumeratorProbe/Program.cs"))),host_runtime=System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
    host_list_assembly=typeof(List<object>).Assembly.FullName,
    runtime_cases=cases,original_game_method_executed=false,production_cil_or_source_modified=false,
    scope="Runs actual GetEnumerator input field load/call/store and actual MoveNext/Current/Dispose receiver/call/result-store byte fragments with original local indices. Exactly five member tokens map explicit Fight.Models/List<Model>/Model boundaries to HostFightInput.Models/List<object>/object; enum locals map to host enum, Current output to object, unused locals are opaque. One or two actual Dispose sites are admitted only with the same enum receiver; the explicit harness executes both sites when present, or repeats the one site. Harness loop/order/recording is explicit; not whole SetStage control flow, game effects, or native MoveNext parity. Original InitLocals retained; no injected initobj/default or retargeted stores can pass. Original native unchanged24-byte SRET witness is independently checked. Exhausted Current null is observed BCL behavior, not an injected substitute."};
File.WriteAllText(Guard($"reports/recovered-enumerator-{run}.json"),JsonSerializer.Serialize(report,options)+Environment.NewLine);
Console.WriteLine($"{status}: {successfulCases}/5 cases; {tests.Count} structural + {totalRuntimeChecks} runtime checks; {fatal}");
return status.StartsWith("PASS",StringComparison.Ordinal)?0:2;

static Span<byte> CollectionsMarshalSpan(List<byte> bytes,int offset,int length)=>System.Runtime.InteropServices.CollectionsMarshal.AsSpan(bytes).Slice(offset,length);
record Row(int Offset,int End,int OperandAt,OpCode Op,int Operand,MemberInfo? Member);
record Consumer(Row Receiver,Row Call,Row? Store);
record CheckRow(string Name,string Status);
public sealed class HostFightInput{public List<object> Models=[];}
public sealed class ObservedTrace
{
    public List<bool> Moves=[];public List<object?> Currents=[];public int Disposals;
    public void RecordMove(bool moved){if(Moves.Count>64)throw new InvalidOperationException("Bounded harness loop exceeded");Moves.Add(moved);}
    public void RecordCurrent(object? current)=>Currents.Add(current);
    public void RecordDispose()=>Disposals++;
    public static void Mutate(HostFightInput input)=>input.Models.Add(new object());
}
