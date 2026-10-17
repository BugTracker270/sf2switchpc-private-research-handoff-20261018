using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length is < 2 or > 3 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$") || args.Length == 3 && args[2] != "--execute") throw new ArgumentException("Verified USB root, immutable run and optional --execute required");
bool execute = args.Length == 3;
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1];
string Guard(string relative) { string p = Path.GetFullPath(Path.Combine(root, relative)); if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB"); for (DirectoryInfo? d = new(Path.GetDirectoryName(p)!); d != null; d = d.Parent) if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point"); return p; }
string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
string FileHash(string path) => Hash(File.ReadAllBytes(path));
string assemblyPath = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp-firstpass.dll"), folder = Path.GetDirectoryName(assemblyPath)!;
string correlationPath = Guard($"reports/recovered-virtual-stream-prefix-{run}.json"), nativePath = Guard("reports/native-virtual-stream-prefix-v36.json"), fixturePath = Guard("analysis/reconstruction/virtual-stream-dispatch-v36/prefix-fixtures.jsonl");
int cases = 0, comparisons = 0, invocationAttempts = 0, overrideCalls = 0, eofReturns = 0, clones = 0, tokenSites = 0, branchesRelocated = 0, prefixCount = 0, localsCount = 0;
bool eligible = false, receiverValueType = false, unchanged = false;
string? fatal = null, bodyHash = null, assemblyHash = null, planHash = null;
MethodInfo? originalMethod = null;
var checks = new List<object>(); var failures = new List<object>(); var controlRows = new List<object>(); var mappingRows = new List<object>();
void Check(string name, bool condition) { checks.Add(new { name, passed = condition }); if (!condition) throw new InvalidDataException(name); }
var context = new AssemblyLoadContext("stream_prefix_fragment_" + run, true);
context.Resolving += (c, n) => File.Exists(Path.Combine(folder, n.Name + ".dll")) ? c.LoadFromAssemblyPath(Path.Combine(folder, n.Name + ".dll")) : null;
try
{
    using var correlationDocument = JsonDocument.Parse(File.ReadAllText(correlationPath)); var correlation = correlationDocument.RootElement;
    using var nativeDocument = JsonDocument.Parse(File.ReadAllText(nativePath)); var native = nativeDocument.RootElement;
    Check("separate unchanged read-only correlation is clean and not a runtime claim", correlation.GetProperty("runtime_eligible").GetBoolean() && !correlation.GetProperty("runtime_performed").GetBoolean()
        && correlation.GetProperty("actual_callvirt_sites").GetInt32() == 2 && correlation.GetProperty("actual_direct_readbyte_sites").GetInt32() == 0
        && correlation.GetProperty("unresolved_prefix_calls").GetArrayLength() == 0 && correlation.GetProperty("helper_zero_placeholders").GetArrayLength() == 0
        && correlation.GetProperty("fatal").ValueKind == JsonValueKind.Null);
    Check("all original native fixtures and unchanged code evidence bound", native.GetProperty("status").GetString() == "PASS_UNCHANGED_NATIVE_STREAM_OVERRIDE_AND_VIRTUAL_READER_PREFIX"
        && native.GetProperty("cases").GetInt32() == 802 && native.GetProperty("checks").GetInt32() == 9624 && native.GetProperty("failures").GetInt32() == 0
        && native.GetProperty("native_guest_functions_replaced").GetInt32() == 0 && native.GetProperty("original_instructions_unmodified").GetBoolean()
        && native.GetProperty("hooks_observe_only").GetBoolean() && native.GetProperty("original_native_virtual_calls").GetInt32() == 1604
        && native.GetProperty("eof_returns").GetInt32() == 276 && native.GetProperty("all_256_values_as_first_and_second_bytes").GetBoolean()
        && native.GetProperty("fixture_sha256").GetString() == FileHash(fixturePath)
        && correlation.GetProperty("fixture_sha256").GetString() == FileHash(fixturePath)
        && correlation.GetProperty("native_report_sha256").GetString() == FileHash(nativePath)
        && native.GetProperty("reader_code_sha256").GetString() == "cfec6671b5b9a8788367f6b7a7b36378b9ea88bdeea69a33ab38bc3ed2a7a9b5"
        && native.GetProperty("override_code_sha256").GetString() == "57b7b4efa4bb42ea002c751dc402dfadb2d17eeb1ca786f29c7a3b4ac8d7acad");
    var fixtures = File.ReadLines(fixturePath).Select(line => JsonDocument.Parse(line).RootElement.Clone()).ToArray();
    var ids = new HashSet<string>(); var firstBytes = new HashSet<int>(); var secondBytes = new HashSet<int>(); int originalEof = 0;
    foreach (var row in fixtures)
    {
        Check("native fixture unique/prefix/two virtual calls " + row.GetProperty("id").GetString(), ids.Add(row.GetProperty("id").GetString()!) && row.GetProperty("outcome").GetString() == "prefix_stop" && row.GetProperty("native_virtual_call_count").GetInt32() == 2);
        int[] values = row.GetProperty("original_returned_ints").EnumerateArray().Select(i => i.GetInt32()).ToArray();
        if (values.Length != 2 || values.Any(v => v is < -1 or > 255)) throw new InvalidDataException("Invalid native observed return list");
        if (values[0] >= 0) firstBytes.Add(values[0]); if (values[1] >= 0) secondBytes.Add(values[1]); originalEof += values.Count(v => v == -1);
    }
    Check("native complete802 cases/both byte domains/276 EOF returns", fixtures.Length == 802 && originalEof == 276 && firstBytes.SetEquals(Enumerable.Range(0, 256)) && secondBytes.SetEquals(Enumerable.Range(0, 256)));
    var assembly = context.LoadFromAssemblyPath(assemblyPath); assemblyHash = FileHash(assemblyPath);
    var type = assembly.GetType("BestHTTP.WebSocket.Frames.WebSocketFrameReader", true)!; receiverValueType = type.IsValueType;
    var method = type.GetMethod("Read", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, [typeof(Stream)])!;
    originalMethod = method;
    var body = method.GetMethodBody()!; byte[] code = body.GetILAsByteArray()!; bodyHash = Hash(code);
    Check("actual immutable v37 method and assembly match inspected evidence", method.ReturnType == typeof(void) && !method.IsStatic && method.MetadataToken == 0x0600067E
        && bodyHash == correlation.GetProperty("actual_body_il_sha256").GetString() && assemblyHash == correlation.GetProperty("assembly_sha256").GetString()
        && bodyHash == "c6c68dce34f0d23792145aee33254a1d7cc01ddfa3f19dfa7bc75c12b98f5048");
    Check("no hidden original type initializer or exception region contract", type.TypeInitializer == null && body.ExceptionHandlingClauses.Count == 0 && body.InitLocals);
    var fields = new[] { "<IsFinal>k__BackingField", "<Type>k__BackingField", "<HasMask>k__BackingField", "<Length>k__BackingField" }.Select(name => type.GetField(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!).ToArray();
    Check("four exact actual game field identities/types retained", fields.All(f => f != null && !f.IsStatic && !f.IsInitOnly) && fields[0].FieldType == typeof(bool) && fields[1].FieldType.IsEnum && Enum.GetUnderlyingType(fields[1].FieldType) == typeof(byte)
        && fields[2].FieldType == typeof(bool) && fields[3].FieldType == typeof(ulong) && fields.Select(f => f.MetadataToken).SequenceEqual(new[] { 0x0400037D, 0x0400037E, 0x0400037F, 0x04000380 }));
    var opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!).ToDictionary(o => unchecked((ushort)o.Value));
    var rows = new Dictionary<int, Row>();
    for (int at = 0; at < code.Length;)
    {
        int start = at; ushort opcode = code[at++]; if (opcode == 0xFE) opcode = (ushort)(0xFE00 | code[at++]); var op = opcodes[opcode]; int operandAt = at;
        int width = op.OperandType switch { OperandType.InlineNone => 0, OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1, OperandType.InlineVar => 2,
            OperandType.InlineI8 or OperandType.InlineR => 8, OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)), _ => 4 };
        at += width; if (width < 0 || at > code.Length) throw new InvalidDataException("Truncated actual instruction");
        int value = width == 4 ? BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(operandAt, 4)) : width == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(code.AsSpan(operandAt, 2)) : width == 1 ? code[operandAt] : 0;
        var member = op.OperandType is OperandType.InlineField or OperandType.InlineMethod or OperandType.InlineType or OperandType.InlineTok ? method.Module.ResolveMember(value) : null;
        rows.Add(start, new(start, at, op, value, member));
    }
    var readByte = typeof(Stream).GetMethod(nameof(Stream.ReadByte), Type.EmptyTypes)!;
    var prefix = new List<Row>(); var visited = new HashSet<int>(); var assigned = new HashSet<int>(); var storeOrder = new List<int>(); var calls = new List<Row>(); int cursor = 0, fenceEnd = -1;
    while (true)
    {
        if (!visited.Add(cursor) || visited.Count > 512 || !rows.TryGetValue(cursor, out var row)) throw new InvalidDataException("Prefix cycle/bounds");
        prefix.Add(row);
        if (row.Op == OpCodes.Br)
        {
            if (row.Offset != 0 || prefix.Count != 1) throw new InvalidDataException("Only original entry branch is in this reviewed fragment");
            cursor = row.End + row.Value; continue;
        }
        if (row.Op == OpCodes.Stloc) { if ((uint)row.Value >= body.LocalVariables.Count) throw new InvalidDataException("Local index"); assigned.Add(row.Value); }
        else if (row.Op == OpCodes.Ldloc) { if (!assigned.Contains(row.Value)) throw new InvalidDataException("Local read lacks original prefix assignment"); }
        else if (row.Op == OpCodes.Ldarg) { if (row.Value != 1) throw new InvalidDataException("Unexpected explicit argument"); }
        else if (row.Op == OpCodes.Ldarg_0) { }
        else if (row.Op == OpCodes.Callvirt)
        {
            if (row.Member is not MethodInfo actual || actual != readByte || actual.DeclaringType != typeof(Stream) || actual.ReturnType != typeof(int) || actual.GetParameters().Length != 0) throw new InvalidDataException("Exact original Stream.ReadByte identity required");
            calls.Add(row);
        }
        else if (row.Op == OpCodes.Stfld)
        {
            int index = Array.IndexOf(fields, row.Member); if (index < 0) throw new InvalidDataException("Unexpected field store"); storeOrder.Add(index);
            if (index == 3) { fenceEnd = row.End; break; }
        }
        else if (row.Op != OpCodes.Ldc_I4 && row.Op != OpCodes.Shr && row.Op != OpCodes.And && row.Op != OpCodes.Ceq) throw new InvalidDataException("Unsupported/unresolved actual prefix opcode " + row.Op.Name);
        cursor = row.End;
    }
    prefixCount = prefix.Count; localsCount = body.LocalVariables.Count;
    Check("exact original47 instructions/two callvirt/four ordered field stores and firstLength fence", prefixCount == 47 && calls.Count == 2 && storeOrder.SequenceEqual(new[] { 0, 1, 2, 3 }) && fenceEnd == 1289
        && correlation.GetProperty("evidence").GetProperty("prefix_instruction_count").GetInt32() == 47 && correlation.GetProperty("prefix_fence_paths").GetInt32() == 1);
    Check("original entry traversal agrees with independent inspection offsets", prefix.Select(r => r.Offset).Order().SequenceEqual(JsonDocument.Parse(File.ReadAllText(Guard(correlation.GetProperty("evidence").GetProperty("private_actual_cil_path").GetString()!))).RootElement.GetProperty("original_instructions").EnumerateArray().Where(r => r.GetProperty("in_prefix").GetBoolean()).Select(r => r.GetProperty("Offset").GetInt32()).Order()));
    var fragment = new DynamicMethod("ActualRecoveredPrefix_" + run, typeof(void), [receiverValueType ? type.MakeByRefType() : type, typeof(Stream)], method.Module, true) { InitLocals = body.InitLocals };
    clones++; var il = fragment.GetILGenerator(); foreach (var local in body.LocalVariables) il.DeclareLocal(local.LocalType, local.IsPinned);
    var labels = prefix.ToDictionary(r => r.Offset, _ => il.DefineLabel());
    foreach (var row in prefix)
    {
        il.MarkLabel(labels[row.Offset]);
        if (row.Op == OpCodes.Br) { il.Emit(row.Op, labels[row.End + row.Value]); branchesRelocated++; }
        else if (row.Member is MethodInfo call) { il.Emit(row.Op, call); tokenSites++; mappingRows.Add(new { offset = row.Offset, kind = "method", source_token = $"0x{row.Value:X8}", exact_original_identity = true, member = call.ToString() }); }
        else if (row.Member is FieldInfo field) { il.Emit(row.Op, field); tokenSites++; mappingRows.Add(new { offset = row.Offset, kind = "field", source_token = $"0x{row.Value:X8}", exact_original_identity = true, member = field.ToString() }); }
        else if (row.Op.OperandType == OperandType.InlineVar) il.Emit(row.Op, (short)row.Value);
        else if (row.Op.OperandType == OperandType.InlineI) il.Emit(row.Op, row.Value);
        else if (row.Op.OperandType == OperandType.InlineNone) il.Emit(row.Op);
        else throw new InvalidDataException("Unsupported emission operand");
    }
    il.Emit(OpCodes.Ret); // The sole added executable instruction is the explicit original Length-store fence.
    Check("clone uses exact members/one branch relocation/no opcode or member substitution", tokenSites == 6 && mappingRows.Count == 6 && branchesRelocated == 1 && clones == 1);
    string planPath = Guard($"analysis/reconstruction/virtual-stream-prefix-runtime/{run}/fragment-plan.json"); Directory.CreateDirectory(Path.GetDirectoryName(planPath)!);
    File.WriteAllText(planPath, JsonSerializer.Serialize(new { source_body_sha256 = bodyHash, original_offsets = prefix.Select(r => r.Offset), original_opcode_values = prefix.Select(r => r.Op.Value), local_types = body.LocalVariables.Select(l => new { l.LocalIndex, type = l.LocalType.FullName, l.IsPinned }), mappingRows, appended_return_fence_after_original_offset = 1284 }, new JsonSerializerOptions { WriteIndented = true }) + "\n"); planHash = FileHash(planPath);
    eligible = true;
    if (execute)
    {
        // Separate authored controls are not edits to the recovered fragment.
        foreach (bool virtualCall in new[] { true, false })
        {
            var control = new DynamicMethod("SyntheticReadByte" + virtualCall, typeof(int), [typeof(Stream)], typeof(ObservedMemoryStream).Module, true);
            var ci = control.GetILGenerator(); ci.Emit(OpCodes.Ldarg_0); ci.Emit(virtualCall ? OpCodes.Callvirt : OpCodes.Call, readByte); ci.Emit(OpCodes.Ret);
            using var input = new ObservedMemoryStream([0xA5]); int result = (int)control.Invoke(null, [input])!;
            bool ok = result == 0xA5 && input.Position == 1 && input.Returns.Count == (virtualCall ? 1 : 0);
            controlRows.Add(new { opcode = virtualCall ? "callvirt" : "call", expected_override_calls = virtualCall ? 1 : 0, actual_override_calls = input.Returns.Count, result, passed = ok }); Check("independent synthetic " + (virtualCall ? "override" : "base-call") + " control", ok);
        }
        var otherFields = type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).Except(fields).ToArray();
        foreach (var row in fixtures)
        {
            byte[] bytes = Convert.FromHexString(row.GetProperty("bytes_hex").GetString()!); byte[] before = (byte[])bytes.Clone();
            using var input = new ObservedMemoryStream(bytes) { Position = row.GetProperty("position_before").GetInt64() };
            object owner = RuntimeHelpers.GetUninitializedObject(type); // No game instance constructor is invoked.
            fields[0].SetValue(owner, true); fields[1].SetValue(owner, Enum.ToObject(fields[1].FieldType, (byte)0xA5)); fields[2].SetValue(owner, true); fields[3].SetValue(owner, 0xA5A5A5A5A5A5A5A5UL);
            object?[] othersBefore = otherFields.Select(f => f.GetValue(owner)).ToArray(); object?[] invocation = [owner, input]; invocationAttempts++; fragment.Invoke(null, invocation); owner = invocation[0]!;
            bool[] results = [Equals(fields[0].GetValue(owner), row.GetProperty("final").GetBoolean()), Convert.ToByte(fields[1].GetValue(owner)) == row.GetProperty("frame_type").GetByte(),
                Equals(fields[2].GetValue(owner), row.GetProperty("has_mask").GetBoolean()), Equals(fields[3].GetValue(owner), row.GetProperty("length").GetUInt64()),
                input.Position == row.GetProperty("position_after").GetInt64(), input.Returns.Count == 2, input.Returns.SequenceEqual(row.GetProperty("original_returned_ints").EnumerateArray().Select(i => i.GetInt32())),
                otherFields.Select(f => f.GetValue(owner)).SequenceEqual(othersBefore), bytes.SequenceEqual(before)];
            comparisons += results.Length; overrideCalls += input.Returns.Count; eofReturns += input.Returns.Count(v => v == -1);
            if (results.Any(ok => !ok)) failures.Add(new { id = row.GetProperty("id").GetString(), failed_checks = results.Select((ok, i) => (ok, i)).Where(p => !p.ok).Select(p => p.i), actual_returns = input.Returns, actual_position = input.Position });
            cases++;
        }
        Check("all802 original fixtures/1604 observed virtual entries/276 EOF returns", cases == 802 && overrideCalls == 1604 && eofReturns == 276 && failures.Count == 0);
    }
    unchanged = Hash(method.GetMethodBody()!.GetILAsByteArray()!) == bodyHash && FileHash(assemblyPath) == assemblyHash;
    Check("actual original game method and DLL remain byte-identical", unchanged);
}
catch (Exception error) { fatal = error.ToString(); }
finally { if (assemblyHash != null && bodyHash != null && originalMethod != null) unchanged = FileHash(assemblyPath) == assemblyHash && Hash(originalMethod.GetMethodBody()!.GetILAsByteArray()!) == bodyHash; }
string status = fatal != null ? "PREFIX_FRAGMENT_RUNTIME_GATE_REJECTED" : execute ? "PASS_ACTUAL_RECOVERED_PREFIX_FRAGMENT_VS_ORIGINAL_NATIVE" : "REVIEW_ONLY_PREFIX_FRAGMENT_READY_NO_RUNTIME_CASES";
var output = new { status, recovery_run = run, review_only = !execute, runtime_eligible = eligible, runtime_performed = invocationAttempts > 0, fragment_invocations_attempted = invocationAttempts, runtime_cases = cases, comparisons, failure_count = failures.Count, first_failures = failures.Take(8), checks, fatal,
    observed_virtual_override_calls = overrideCalls, observed_eof_returns = eofReturns, synthetic_dispatch_controls = controlRows, original_body_il_sha256 = bodyHash, assembly_sha256 = assemblyHash,
    correlation_report_sha256 = FileHash(correlationPath), native_report_sha256 = FileHash(nativePath), fixture_sha256 = FileHash(fixturePath), probe_source_sha256 = FileHash(Guard("src/re/RecoveredVirtualStreamPrefixRuntimeProbe/Program.cs")),
    original_prefix_instructions = prefixCount, original_declared_locals_retained = localsCount, receiver_is_original_value_type = receiverValueType, original_dll_unchanged = unchanged,
    recovered_fragment_dynamic_clones = clones, member_token_remap_sites = tokenSites, member_token_mappings = mappingRows, local_signature_reencoded = clones > 0, branch_offsets_relocated = branchesRelocated,
    inserted_return_fences = clones > 0 ? 1 : 0, source_opcode_changes = 0, original_member_substitutions = 0, helper_substitutions = 0, private_fragment_plan_sha256 = planHash,
    access_bypass = "DynamicMethod uses the original method Module and skipVisibility=true solely to access the original private fields", actual_whole_read_invocations = 0, game_instance_constructors_invoked = 0,
    host_boundary = "Real host ObservedMemoryStream overrides ReadByte, records original virtual-call results and delegates to host MemoryStream.ReadByte. Actual game receiver type, enum and four field identities are retained; original Stream.ReadByte MethodInfo is unchanged. All locals/branch/store order are retained in one isolated cloned prefix ending at an inserted return after the original first Length store.",
    scope = "Fragment comparison only, not direct invocation of the entire recovered Read. Member metadata tokens and branch offsets are remapped to their exact original identities in an isolated host method; no diagnostic, call opcode, field type, helper, getter or member is replaced. Original ARM64 native fixtures provide the separate reference. Game/runtime initialization, native object layout/GC/padding, extended lengths, payload, masks, null/closed/error paths, concurrency, helpers, EH and full source portability remain outside this boundary." };
string reportPath = Guard($"reports/recovered-virtual-stream-prefix-runtime-{run}" + (execute ? "" : "-review") + ".json");
File.WriteAllText(reportPath, JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { status, cases, comparisons, overrideCalls, eofReturns, fatal })); context.Unload(); return fatal == null ? 0 : 2;

record Row(int Offset, int End, OpCode Op, int Value, MemberInfo? Member);
sealed class ObservedMemoryStream(byte[] bytes) : MemoryStream(bytes, false)
{
    public List<int> Returns { get; } = [];
    public override int ReadByte() { int value = base.ReadByte(); Returns.Add(value); return value; }
}
