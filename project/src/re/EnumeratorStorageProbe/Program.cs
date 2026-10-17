using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length != 3 || !args.Skip(1).All(s => Regex.IsMatch(s, "^[a-z0-9-]+$")))
    throw new ArgumentException("USB root, baseline run, candidate run required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point");
    return path;
}
string Hash(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
var opcodeMap = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
    .Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!)
    .ToDictionary(o => unchecked((ushort)o.Value));
var reports = new List<object>();
var privateDetails = new List<object>();
int totalChecks = 0;
foreach (string run in args.Skip(1))
{
    string folder = Guard($"analysis/il2cpp/cpp2il-recovery-{run}");
    var context = new AssemblyLoadContext($"enumerator-{run}", isCollectible: true);
    context.Resolving += (c, name) =>
    {
        string candidate = Path.Combine(folder, name.Name + ".dll");
        return File.Exists(candidate) ? c.LoadFromAssemblyPath(candidate) : null;
    };
    string dllPath = Path.Combine(folder, "Assembly-CSharp.dll");
    var assembly = context.LoadFromAssemblyPath(dllPath);
    var type = assembly.GetType("Nekki.SF2.Core.Fights.Fight", true)!;
    var method = type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
        .Single(m => m.Name == "SetStage");
    var body = method.GetMethodBody()!;
    byte[] bytes = body.GetILAsByteArray()!;
    var instructions = new List<Row>();
    for (int at = 0; at < bytes.Length;)
    {
        int start = at; ushort code = bytes[at++];
        if (code == 0xfe) code = (ushort)(0xfe00 | bytes[at++]);
        var op = opcodeMap[code]; int operandAt = at;
        at += op.OperandType switch
        {
            OperandType.InlineNone => 0,
            OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
            OperandType.InlineVar => 2,
            OperandType.InlineI8 or OperandType.InlineR => 8,
            OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(at, 4)),
            _ => 4
        };
        int operand = op.OperandType == OperandType.ShortInlineVar ? bytes[operandAt]
            : op.OperandType == OperandType.InlineVar ? BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(operandAt, 2))
            : at - operandAt == 4 ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(operandAt, 4)) : 0;
        if (op.OperandType == OperandType.InlineNone && (op.Name!.StartsWith("stloc.") || op.Name.StartsWith("ldloc.")))
            operand = int.Parse(op.Name[^1..]);
        MemberInfo? member = null;
        if (op.OperandType is OperandType.InlineMethod or OperandType.InlineType or OperandType.InlineField or OperandType.InlineTok)
            member = method.Module.ResolveMember(operand);
        instructions.Add(new Row(start, at, op, operand, member));
    }
    bool IsEnum(int local) => body.LocalVariables[local].LocalType.IsGenericType &&
        body.LocalVariables[local].LocalType.GetGenericTypeDefinition().FullName == "System.Collections.Generic.List`1+Enumerator";
    var enumSlots = body.LocalVariables.Where(v => IsEnum(v.LocalIndex)).Select(v => v.LocalIndex).ToArray();
    var getCall = instructions.Single(r => r.Member is MethodInfo mi && mi.Name == "GetEnumerator" && mi.DeclaringType!.FullName!.StartsWith("System.Collections.Generic.List`1[["));
    int getIndex = instructions.IndexOf(getCall);
    Row returnStore = instructions.Skip(getIndex + 1).First(r => r.Op != OpCodes.Nop);
    if (!returnStore.Op.Name!.StartsWith("stloc") || !IsEnum(returnStore.Operand)) throw new InvalidDataException("Expected enum return store");
    var consumerCalls = instructions.Where(r => r.Member is MethodInfo mi && mi.DeclaringType!.Name.StartsWith("Enumerator") && mi.Name is "MoveNext" or "get_Current" or "Dispose").ToArray();
    var consumers = consumerCalls.Select(r =>
    {
        int i = instructions.IndexOf(r);
        Row receiver = instructions.Take(i).Last(x => x.Op != OpCodes.Nop);
        if (!receiver.Op.Name!.StartsWith("ldloca") || !IsEnum(receiver.Operand)) throw new InvalidDataException("Expected direct enum address receiver");
        return (call: r, receiver);
    }).ToArray();
    int consumedSlot = consumers.First(p => ((MethodInfo)p.call.Member!).Name == "MoveNext").receiver.Operand;
    var zeroStores = instructions.Select((r, i) => (r, i)).Where(p => p.i > 0 && p.r.Op.Name!.StartsWith("stloc") && IsEnum(p.r.Operand))
        .Select(p => (store: p.r, producer: instructions.Take(p.i).Last(r => r.Op != OpCodes.Nop)))
        .Where(p => p.producer.Op == OpCodes.Ldc_I4_0 || p.producer.Op == OpCodes.Ldc_I4 && p.producer.Operand == 0).ToArray();
    if (consumers.Length != 3 || consumers.Any(p => p.receiver.Operand != consumedSlot)) throw new InvalidDataException("Consumer identity changed");
    bool distinct = returnStore.Operand != consumedSlot;
    if (!distinct || enumSlots.Length < 2) throw new InvalidDataException("Expected baseline storage mismatch");
    totalChecks += 3;
    var move = consumers.Single(p => ((MethodInfo)p.call.Member!).Name == "MoveNext");
    Type hostEnum = typeof(List<object>.Enumerator);
    var hostGet = typeof(List<object>).GetMethod("GetEnumerator")!;
    var hostMove = hostEnum.GetMethod("MoveNext")!;

    // Isolated typed storage only. No SF2 method or helper binding is executed.
    // Preserve every original local index. Untouched locals become opaque objects;
    // touched enumerator slots use the BCL List<object>.Enumerator contract.
    byte[] Signature(DynamicILInfo info)
    {
        var sig = SignatureHelper.GetLocalVarSigHelper();
        foreach (var local in body.LocalVariables) sig.AddArgument(IsEnum(local.LocalIndex) ? hostEnum : typeof(object));
        return sig.GetSignature();
    }
    byte[] RemapCall(Row row, DynamicILInfo info, MethodInfo target)
    {
        byte[] fragment = bytes[row.Offset..row.End];
        int token = info.GetTokenFor(target.MethodHandle, target.DeclaringType!.TypeHandle);
        BinaryPrimitives.WriteInt32LittleEndian(fragment.AsSpan(fragment.Length - 4), token);
        return fragment;
    }
    void Stloc(List<byte> code, int index)
    {
        code.Add(0xfe); code.Add(0x0e); code.Add((byte)index); code.Add((byte)(index >> 8));
    }
    void Ldloca(List<byte> code, int index)
    {
        code.Add(0xfe); code.Add(0x0d); code.Add((byte)index); code.Add((byte)(index >> 8));
    }
    object RuntimeCase(string mode, object[] values)
    {
        var dm = new DynamicMethod($"enumerator_{run}_{mode}", typeof(bool), new[] { typeof(List<object>) }, typeof(Program).Module, true) { InitLocals = true };
        var info = dm.GetDynamicILInfo();
        info.SetLocalSignature(Signature(info));
        var code = new List<byte>();
        if (mode == "original_scalar_store")
        {
            var zero = zeroStores.Single(p => p.store.Operand == consumedSlot);
            code.AddRange(bytes[zero.producer.Offset..zero.producer.End]);
            code.AddRange(bytes[zero.store.Offset..zero.store.End]);
            code.AddRange(bytes[move.receiver.Offset..move.receiver.End]);
            code.AddRange(RemapCall(move.call, info, hostMove));
            code.Add(0x2a);
        }
        else
        {
            Ldloca(code, consumedSlot); code.Add(0xfe); code.Add(0x15);
            code.AddRange(BitConverter.GetBytes(info.GetTokenFor(hostEnum.TypeHandle)));
            code.Add(0x02); // Explicit typed input boundary: List<object> argument.
            code.AddRange(RemapCall(getCall, info, hostGet));
            if (mode == "same_slot_control") Stloc(code, consumedSlot);
            else code.AddRange(bytes[returnStore.Offset..returnStore.End]);
            code.AddRange(bytes[move.receiver.Offset..move.receiver.End]);
            code.AddRange(RemapCall(move.call, info, hostMove));
            code.Add(0x2a);
        }
        info.SetCode(code.ToArray(), 2);
        bool? actual = null; string? exception = null;
        try { actual = dm.CreateDelegate<Func<List<object>, bool>>()(values.ToList()); }
        catch (Exception e) { exception = e.GetType().FullName; }
        bool passed = mode switch
        {
            "original_scalar_store" => exception == typeof(InvalidProgramException).FullName || exception == typeof(NullReferenceException).FullName,
            "initialization_only_control" => exception == typeof(NullReferenceException).FullName,
            "same_slot_control" => exception == null && actual == (values.Length > 0),
            _ => false
        };
        if (!passed) throw new InvalidDataException($"Unexpected {run}/{mode}: {actual}/{exception}");
        totalChecks++;
        return new { mode, element_count = values.Length, result = actual, exception, passed, fragment_sha256 = Hash(code.ToArray()),
            exact_jit_rejection_required = false,
            original_storage_assignment_preserved = mode != "same_slot_control", explicit_storage_retarget_control = mode == "same_slot_control" };
    }
    var cases = new List<object>();
    if (zeroStores.Any(p => p.store.Operand == consumedSlot)) cases.Add(RuntimeCase("original_scalar_store", Array.Empty<object>()));
    foreach (int count in new[] { 0, 1, 3, 8 })
    {
        object[] values = Enumerable.Range(0, count).Select(_ => new object()).ToArray();
        cases.Add(RuntimeCase("initialization_only_control", values));
        cases.Add(RuntimeCase("same_slot_control", values));
    }
    reports.Add(new
    {
        run, assembly_sha256 = Hash(File.ReadAllBytes(dllPath)), method_token = $"0x{method.MetadataToken:X8}",
        method_body_sha256 = Hash(bytes), method_body_bytes = bytes.Length, body.InitLocals,
        enum_local_slots = enumSlots, actual_getenumerator_call_il = getCall.Offset, actual_return_store_il = returnStore.Offset,
        actual_getenumerator_member_token = $"0x{getCall.Operand:X8}", actual_getenumerator_declaring_type = getCall.Member!.DeclaringType!.ToString(),
        actual_return_store_slot = returnStore.Operand, actual_consumer_slot = consumedSlot, distinct_storage = distinct,
        actual_consumed_local_type = body.LocalVariables[consumedSlot].LocalType.ToString(),
        explicit_bcl_local_type_substitution = hostEnum.ToString(),
        consumer_receiver_evidence = consumers.Select(p => new { method = p.call.Member!.Name, member_token = $"0x{p.call.Operand:X8}", call_il = p.call.Offset, receiver_il = p.receiver.Offset, slot = p.receiver.Operand }),
        original_scalar_zero_stores = zeroStores.Select(p => new { producer_il = p.producer.Offset, store_il = p.store.Offset, slot = p.store.Operand }),
        runtime_cases = cases
    });
    privateDetails.Add(new
    {
        run, method = method.ToString(), locals = body.LocalVariables.Select(v => new { index = v.LocalIndex, type = v.LocalType.ToString() }),
        instructions = instructions.Select(r => new { il = r.Offset, op = r.Op.Name, operand = r.Member?.ToString() ?? r.Operand.ToString() })
    });
    context.Unload();
}
var options = new JsonSerializerOptions { WriteIndented = true };
string reportPath = Guard("reports/enumerator-storage-v31.json");
File.WriteAllText(Guard("analysis/il2cpp/enumerator-storage-cil-v31.json"), JsonSerializer.Serialize(privateDetails, options));
File.WriteAllText(reportPath, JsonSerializer.Serialize(new
{
    status = "PASS_OBSERVED_CIL_STORAGE_DEFECT_AND_ISOLATED_BCL_CONTROLS", checks = totalChecks,
    selected_method = "Nekki.SF2.Core.Fights.Fight.SetStage", native_rva = "0xC9F3F0", host_runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
    probe_source_sha256 = Hash(File.ReadAllBytes(Guard("src/re/EnumeratorStorageProbe/Program.cs"))),
    bcl_reference_enumerator_size = System.Runtime.CompilerServices.Unsafe.SizeOf<List<object>.Enumerator>(),
    original_game_method_execution = false, production_recovery_changed = false,
    boundary = "Actual CIL operand/slot observations and isolated fragments. List<Model> is replaced only at explicit input/local/member tokens with BCL List<object>; all unused local storage is opaque object. No game helper bindings. Initialization-only and store-retarget controls are counterfactual diagnostic fixtures, not recovered behavior or a production fix. Whole method, native parity, game initialization and exceptions outside these fragments are untested.",
    runs = reports
}, options));
Console.WriteLine($"Enumerator storage PASS: {totalChecks} checks; {reportPath}");
record Row(int Offset, int End, OpCode Op, int Operand, MemberInfo? Member);
