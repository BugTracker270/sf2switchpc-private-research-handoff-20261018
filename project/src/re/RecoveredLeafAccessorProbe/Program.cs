using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if ((args.Length != 2 && (args.Length != 3 || args[2] != "--survey-protected")) || !Regex.IsMatch(args[1], "^[a-z0-9-]+$"))
    throw new ArgumentException("USB root and run, optionally --survey-protected, required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1];
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(byte[] code) => Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant();
var assemblyPath = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp.dll");
var opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(OpCode))
    .Select(f => (OpCode)f.GetValue(null)!).ToDictionary(op => unchecked((ushort)op.Value));
List<(int Start, int Operand, int End, OpCode Op)> Decode(byte[] code)
{
    var rows = new List<(int, int, int, OpCode)>();
    for (int at = 0; at < code.Length;)
    {
        int start = at;
        ushort value = code[at++]; if (value == 0xfe) value = (ushort)(0xfe00 | code[at++]);
        var op = opcodes[value]; int operand = at;
        at += op.OperandType switch
        {
            OperandType.InlineNone => 0,
            OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
            OperandType.InlineVar => 2, OperandType.InlineI8 or OperandType.InlineR => 8,
            OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)), _ => 4
        };
        rows.Add((start, operand, at, op));
    }
    return rows;
}
int Slot((int Start, int Operand, int End, OpCode Op) row, byte[] code) => row.Op.OperandType == OperandType.InlineNone
    ? int.Parse(row.Op.Name![^1..]) : row.Op.OperandType == OperandType.ShortInlineVar ? code[row.Operand]
    : BinaryPrimitives.ReadUInt16LittleEndian(code.AsSpan(row.Operand, 2));
if (args.Length == 3)
{
    var assembly = Assembly.LoadFrom(assemblyPath);
    var node = assembly.GetType("Nekki.SF2.Core.Fights.Model.Components.Nodes.ModelNode", true)!;
    var field = node.GetField("_Current", BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly)!;
    var getter = node.GetMethod("get_CurrentPosition", BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)!;
    var caller = assembly.GetType("Nekki.SF2.Core.Fights.Model.Components.Edges.ModelEdge", true)!
        .GetMethod("get_StartPosition", BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)!;
    var code = caller.GetMethodBody()!.GetILAsByteArray()!;
    var accesses = Decode(code).Where(row => row.Op.OperandType == OperandType.InlineField).Select(row =>
    {
        var target = caller.Module.ResolveField(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(row.Operand, 4)))!;
        return new { il_offset = row.Start, opcode = row.Op.Name, owner = target.DeclaringType!.FullName, field = target.Name,
            field_type = target.FieldType.FullName, protected_current = target == field };
    }).ToArray();
    var calls = Decode(code).Where(row => row.Op.OperandType == OperandType.InlineMethod).Select(row =>
        caller.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(row.Operand, 4)))!.ToString()).ToArray();
    if (!field.IsFamily || field.IsStatic || getter.IsVirtual || !getter.IsPublic || getter.IsStatic
        || accesses.Count(row => row.protected_current && row.opcode == "ldfld") != 1 || calls.Length != 0)
        throw new Exception("Protected candidate contract differs");
    var survey = new { status = "PROTECTED_FIELD_CANDIDATE_CIL_AND_METADATA_CONFIRMED", recovery_run = run,
        owner = node.FullName, owner_attributes = node.Attributes.ToString(), before_field_init = (node.Attributes & TypeAttributes.BeforeFieldInit) != 0,
        has_type_initializer = node.TypeInitializer != null, field = field.Name, field_visibility = field.Attributes.ToString(),
        getter = getter.Name, getter_public = getter.IsPublic, getter_virtual = getter.IsVirtual,
        caller = caller.DeclaringType!.FullName + "::" + caller.Name, caller_il_sha256 = Hash(code),
        caller_field_accesses = accesses, caller_calls = calls, recovered_cil_executed = false,
        current_emitter_gate_accepts = false, whole_game_source_ready = false,
        scope = "Read-only recovered-metadata/CIL candidate survey. ModelEdge.StartPosition reads its ModelNode receiver field then protected ModelNode._Current. The existing public nonvirtual getter has an independent exact native leaf witness, but the current emitter deliberately accepts private fields only. ModelNode has a type initializer and BeforeFieldInit; absence of explicit native getter initialization does not certify cross-runtime initialization timing. A future protected-field increment needs a declared initialization boundary and actual rewritten-caller execution proof." };
    File.WriteAllText(Guard($"reports/private-access-protected-candidate-{run}.json"), JsonSerializer.Serialize(survey, new JsonSerializerOptions { WriteIndented = true }) + "\n");
    Console.WriteLine(JsonSerializer.Serialize(survey));
    return 0;
}
string? fatal = null, setterHash = null, callerHash = null, sliceHash = null, literalHash = null;
int cases = 0, checks = 0, accessorCalls = 0, fieldStores = 0, callSites = 0, selectedOffset = -1;
try
{
    var assembly = Assembly.LoadFrom(assemblyPath);
    var owner = assembly.GetType("InControl.InputControlMapping", true)!;
    var field = owner.GetField("handle", BindingFlags.NonPublic | BindingFlags.Instance)!;
    var setter = owner.GetMethod("set_Handle", BindingFlags.Public | BindingFlags.Instance)!;
    if (!field.IsPrivate || field.IsStatic || field.FieldType != typeof(string) || !setter.IsPublic || setter.IsVirtual || setter.IsStatic
        || setter.ReturnType != typeof(void) || !setter.GetParameters().Select(p => p.ParameterType).SequenceEqual([typeof(string)]))
        throw new Exception("Original field/accessor contract changed");
    var storageModule = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("LeafAccessorStorage"), AssemblyBuilderAccess.Run).DefineDynamicModule("Storage");
    var builder = storageModule.DefineType("Storage", TypeAttributes.Public | TypeAttributes.Class);
    builder.DefineDefaultConstructor(MethodAttributes.Public);
    builder.DefineField("Value", typeof(string), FieldAttributes.Public);
    builder.DefineField("Sentinel", typeof(object), FieldAttributes.Public);
    var storage = builder.CreateType()!;
    var storageField = storage.GetField("Value")!;
    var sentinelField = storage.GetField("Sentinel")!;
    var setterBody = setter.GetMethodBody()!;
    if (setterBody.ExceptionHandlingClauses.Count != 0) throw new Exception("Accessor EH region unexpected");
    var setterCode = setterBody.GetILAsByteArray()!;
    setterHash = Hash(setterCode);
    var isolatedSetter = new DynamicMethod("ActualRecoveredSetter", typeof(void), [storage, typeof(string)], typeof(Program).Module, true);
    var setterInfo = isolatedSetter.GetDynamicILInfo();
    var setterSignature = SignatureHelper.GetLocalVarSigHelper();
    foreach (var local in setterBody.LocalVariables) setterSignature.AddArgument(local.LocalType == owner ? storage : local.LocalType, local.IsPinned);
    setterInfo.SetLocalSignature(setterSignature.GetSignature());
    foreach (var row in Decode(setterCode))
    {
        if (row.Op == OpCodes.Stfld && setter.Module.ResolveField(BinaryPrimitives.ReadInt32LittleEndian(setterCode.AsSpan(row.Operand, 4))) == field)
        {
            BinaryPrimitives.WriteInt32LittleEndian(setterCode.AsSpan(row.Operand, 4), setterInfo.GetTokenFor(storageField.FieldHandle));
            fieldStores++;
        }
        else if (row.Op.OperandType is OperandType.InlineMethod or OperandType.InlineField or OperandType.InlineType or OperandType.InlineTok
            || row.Op.FlowControl is FlowControl.Call or FlowControl.Throw)
            throw new Exception("Non-leaf recovered accessor token or call");
    }
    if (fieldStores != 1) throw new Exception("Actual recovered setter must have exactly one matching field store");
    setterInfo.SetCode(setterCode, setterBody.MaxStackSize);
    var setAction = isolatedSetter.CreateDelegate(typeof(Action<,>).MakeGenericType(storage, typeof(string)));
    var constructor = assembly.GetType("InControl.GoogleNexusPlayerRemoteProfile", true)!.GetConstructor(Type.EmptyTypes)!;
    var body = constructor.GetMethodBody()!;
    var code = body.GetILAsByteArray()!;
    callerHash = Hash(code);
    var decoded = Decode(code);
    var targets = decoded.Select((row, index) => (row, index)).Where(pair => pair.row.Op == OpCodes.Call
        && constructor.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(pair.row.Operand, 4))) == setter).ToArray();
    if (targets.Length == 0) throw new Exception("Actual rewritten caller does not call the original public setter");
    callSites = targets.Length;
    DynamicMethod? isolatedCaller = null;
    string? expectedLiteral = null;
    foreach (var target in targets)
    {
        for (int first = target.index - 1; first >= Math.Max(0, target.index - 16); first--)
        {
            var rows = decoded.GetRange(first, target.index - first + 1);
            var assigned = new HashSet<int>(); var receiverSlots = new HashSet<int>(); bool accepted = true;
            string? literal = null;
            foreach (var row in rows)
            {
                var name = row.Op.Name!;
                if (name.StartsWith("ldloc", StringComparison.Ordinal) && !name.StartsWith("ldloca", StringComparison.Ordinal))
                {
                    int slot = Slot(row, code);
                    if (body.LocalVariables[slot].LocalType == owner) receiverSlots.Add(slot);
                    else if (!assigned.Contains(slot)) { accepted = false; break; }
                }
                else if (name.StartsWith("stloc", StringComparison.Ordinal)) assigned.Add(Slot(row, code));
                else if (row.Op == OpCodes.Ldstr)
                {
                    if (literal != null) { accepted = false; break; }
                    literal = constructor.Module.ResolveString(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(row.Operand, 4)));
                }
                else if (row.Start == target.row.Start || row.Op == OpCodes.Nop || row.Op == OpCodes.Dup || row.Op == OpCodes.Pop) { }
                else { accepted = false; break; }
            }
            if (!accepted || receiverSlots.Count != 1 || literal == null) continue;
            int start = rows[0].Start;
            var slice = code.AsSpan(start, target.row.End - start).ToArray();
            sliceHash = Hash(slice); selectedOffset = start;
            var candidate = new DynamicMethod("ActualRecoveredCallerSlice", typeof(void), [storage], typeof(Program).Module, true);
            var info = candidate.GetDynamicILInfo();
            var signature = SignatureHelper.GetLocalVarSigHelper();
            foreach (var local in body.LocalVariables) signature.AddArgument(local.LocalType == owner ? storage : local.LocalType, local.IsPinned);
            info.SetLocalSignature(signature.GetSignature());
            foreach (var row in rows)
            {
                int operand = row.Operand - start;
                if (row.Op == OpCodes.Ldstr)
                    BinaryPrimitives.WriteInt32LittleEndian(slice.AsSpan(operand, 4), info.GetTokenFor(literal));
                else if (row.Start == target.row.Start)
                    BinaryPrimitives.WriteInt32LittleEndian(slice.AsSpan(operand, 4), info.GetTokenFor(isolatedSetter));
            }
            int receiver = receiverSlots.Single();
            // Seed only the explicitly supplied receiver local; selected source
            // instructions, string literal and call order remain unchanged.
            var prefix = new byte[] { 0x02, 0xfe, 0x0e, (byte)receiver, (byte)(receiver >> 8) };
            info.SetCode(prefix.Concat(slice).Concat(new byte[] { 0x2a }).ToArray(), Math.Max(1, body.MaxStackSize));
            isolatedCaller = candidate; expectedLiteral = literal; accessorCalls = 1; break;
        }
        if (isolatedCaller != null) break;
    }
    if (isolatedCaller == null || expectedLiteral == null) throw new Exception("No independent literal/receiver call expression found");
    literalHash = Hash(System.Text.Encoding.UTF8.GetBytes(expectedLiteral));
    var callerAction = isolatedCaller.CreateDelegate(typeof(Action<>).MakeGenericType(storage));
    for (int i = 0; i < 64; i++)
    {
        string? value = i == 0 ? null : i == 1 ? string.Empty : new string((char)(0x41 + i), i);
        var receiver = Activator.CreateInstance(storage)!; var sentinel = new object(); sentinelField.SetValue(receiver, sentinel);
        setAction.DynamicInvoke(receiver, value);
        if (!ReferenceEquals(storageField.GetValue(receiver), value) || !ReferenceEquals(sentinelField.GetValue(receiver), sentinel))
            throw new Exception("Recovered setter changed reference identity or unrelated storage");
        checks += 2; cases++;
        storageField.SetValue(receiver, value);
        callerAction.DynamicInvoke(receiver);
        if (!ReferenceEquals(storageField.GetValue(receiver), expectedLiteral) || !ReferenceEquals(sentinelField.GetValue(receiver), sentinel))
            throw new Exception("Recovered caller expression changed literal identity or unrelated storage");
        checks += 2; cases++;
    }
}
catch (Exception exception) { fatal = exception.GetType().FullName + ": " + exception.Message; }
var report = new { status = fatal == null && cases == 128 ? "PASS_RECOVERED_LEAF_ACCESSOR_AT_ISOLATED_STORAGE_BOUNDARY" : "RECOVERED_LEAF_ACCESSOR_LIMITATION",
    assembly_sha256 = Hash(File.ReadAllBytes(assemblyPath)),
    recovery_run = run, cases, checks, call_sites = callSites, accessor_calls = accessorCalls, recovered_setter_field_stores = fieldStores,
    fatal, setter_il_sha256 = setterHash, caller_il_sha256 = callerHash, selected_slice_sha256 = sliceHash,
    selected_expression_il_offset = selectedOffset, selected_literal_sha256 = literalHash,
    original_field_private = true, output_metadata_added = false, original_native_executed = false,
    scope = "Execute actual recovered public setter CIL and one actual rewritten literal/receiver call expression from GoogleNexusPlayerRemoteProfile constructor. Only receiver type/field tokens and call-to-that-exact-recovered-setter token map to isolated CLR storage; source instructions and literal are retained, with one receiver local supplied and a return appended. Arbitrary/null strings and unrelated storage are checked. Native setter execution is recorded separately; original class initialization, profile constructor remainder, GC and whole-game/source parity remain unvalidated.", whole_game_source_ready = false };
File.WriteAllText(Guard($"reports/recovered-leaf-accessor-{run}.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(report));
return fatal == null ? 0 : 1;
