using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length != 2 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$")) throw new ArgumentException("Verified USB root and recovery run required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1];
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
string FileHash(string path) => Hash(File.ReadAllBytes(path));
string folder = Guard($"analysis/il2cpp/cpp2il-recovery-{run}"), assemblyPath = Path.Combine(folder, "Assembly-CSharp-firstpass.dll");
string nativeReport = Guard("reports/native-virtual-stream-prefix-v36.json"), fixturePath = Guard("analysis/reconstruction/virtual-stream-dispatch-v36/prefix-fixtures.jsonl");
var checks = new List<Check>(); var limitations = new List<string>(); var evidence = new Dictionary<string, object?>();
var callRows = new List<object>(); var diagnosticRows = new List<object>(); var placeholderRows = new List<object>();
var prefixOffsets = new SortedSet<int>();
int fixtureCases = 0, nativeEof = 0, nativeCalls = 0, actualVirtualCalls = 0, directReadByteCalls = 0, fencePaths = 0;
bool nativeBound = false, prefixShape = false, correlation = false, runtimeEligible = false;
string? fatal = null, bodyHash = null, privateHash = null;
void Check(string name, bool passed) => checks.Add(new(name, passed ? "PASS" : "FAIL"));
var context = new AssemblyLoadContext("actual_stream_prefix_" + run, true);
context.Resolving += (c, n) => File.Exists(Path.Combine(folder, n.Name + ".dll")) ? c.LoadFromAssemblyPath(Path.Combine(folder, n.Name + ".dll")) : null;
try
{
    using var native = JsonDocument.Parse(File.ReadAllText(nativeReport)); var report = native.RootElement;
    if (report.GetProperty("status").GetString() != "PASS_UNCHANGED_NATIVE_STREAM_OVERRIDE_AND_VIRTUAL_READER_PREFIX"
        || report.GetProperty("cases").GetInt32() != 802 || report.GetProperty("checks").GetInt32() != 9624
        || report.GetProperty("failures").GetInt32() != 0 || report.GetProperty("native_guest_functions_replaced").GetInt32() != 0
        || !report.GetProperty("hooks_observe_only").GetBoolean() || !report.GetProperty("original_instructions_unmodified").GetBoolean()
        || report.GetProperty("virtual_slot").GetInt32() != 19 || report.GetProperty("original_native_virtual_calls").GetInt32() != 1604
        || report.GetProperty("function_offset").GetString() != "0x258" || report.GetProperty("method_info_offset").GetString() != "0x260"
        || report.GetProperty("reader_code_sha256").GetString() != "cfec6671b5b9a8788367f6b7a7b36378b9ea88bdeea69a33ab38bc3ed2a7a9b5"
        || report.GetProperty("override_code_sha256").GetString() != "57b7b4efa4bb42ea002c751dc402dfadb2d17eeb1ca786f29c7a3b4ac8d7acad"
        || report.GetProperty("native_source_sha256").GetString() != FileHash(Guard("analysis/nso/main-uncompressed.nso"))
        || report.GetProperty("fixture_sha256").GetString() != FileHash(fixturePath))
        throw new InvalidDataException("Original native dispatch/fixture/code evidence differs");
    var ids = new HashSet<string>(); var firstValues = new HashSet<int>(); var secondValues = new HashSet<int>();
    foreach (string line in File.ReadLines(fixturePath))
    {
        using var doc = JsonDocument.Parse(line); var row = doc.RootElement;
        if (!ids.Add(row.GetProperty("id").GetString()!) || row.GetProperty("outcome").GetString() != "prefix_stop"
            || row.GetProperty("native_virtual_call_count").GetInt32() != 2) throw new InvalidDataException("Duplicate/non-prefix native case");
        int[] values = row.GetProperty("original_returned_ints").EnumerateArray().Select(i => i.GetInt32()).ToArray();
        if (values.Length != 2 || values.Any(v => v is < -1 or > 255)) throw new InvalidDataException("Invalid original return observations");
        if (values[0] >= 0) firstValues.Add(values[0]); if (values[1] >= 0) secondValues.Add(values[1]);
        fixtureCases++; nativeCalls += 2; nativeEof += values.Count(v => v == -1);
    }
    nativeBound = fixtureCases == 802 && nativeCalls == 1604 && nativeEof == 276
        && firstValues.SetEquals(Enumerable.Range(0, 256)) && secondValues.SetEquals(Enumerable.Range(0, 256));
    Check("all802 original native cases and both byte domains bound without guest replacements", nativeBound);
    if (!nativeBound) throw new InvalidDataException("Complete native case binding differs");

    var assembly = context.LoadFromAssemblyPath(assemblyPath);
    var type = assembly.GetType("BestHTTP.WebSocket.Frames.WebSocketFrameReader", true)!;
    var method = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly)
        .Single(m => m.Name == "Read" && m.GetParameters() is [{ ParameterType: var parameter }] && parameter == typeof(Stream));
    Check("actual original instance Read(Stream) metadata", !method.IsStatic && method.ReturnType == typeof(void));
    var body = method.GetMethodBody()!; byte[] bytes = body.GetILAsByteArray()!; bodyHash = Hash(bytes);
    var opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(OpCode))
        .Select(f => (OpCode)f.GetValue(null)!).ToDictionary(o => unchecked((ushort)o.Value));
    var rows = new List<Row>();
    for (int at = 0; at < bytes.Length;)
    {
        int start = at; ushort code = bytes[at++];
        if (code == 0xFE) { if (at == bytes.Length) throw new InvalidDataException("Truncated two-byte opcode"); code = (ushort)(0xFE00 | bytes[at++]); }
        var op = opcodes[code]; int operandAt = at;
        int width = op.OperandType switch
        {
            OperandType.InlineNone => 0, OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
            OperandType.InlineVar => 2, OperandType.InlineI8 or OperandType.InlineR => 8,
            OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(at, 4)), _ => 4
        };
        if (width < 0 || at > bytes.Length - width) throw new InvalidDataException("Truncated CIL operand");
        at += width;
        int value = width == 1 ? bytes[operandAt] : width == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(operandAt, 2))
            : width == 4 ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(operandAt, 4)) : 0;
        if (op.OperandType == OperandType.InlineNone && (op.Name!.StartsWith("stloc.") || op.Name.StartsWith("ldloc."))) value = int.Parse(op.Name[^1..]);
        MemberInfo? member = op.OperandType is OperandType.InlineMethod or OperandType.InlineType or OperandType.InlineField or OperandType.InlineTok
            ? method.Module.ResolveMember(value) : null;
        int[] targets = op.OperandType == OperandType.ShortInlineBrTarget ? [at + unchecked((sbyte)value)]
            : op.OperandType == OperandType.InlineBrTarget ? [at + value]
            : op.OperandType == OperandType.InlineSwitch ? Enumerable.Range(0, BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(operandAt, 4)))
                .Select(i => at + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(operandAt + 4 + 4 * i, 4))).ToArray() : [];
        rows.Add(new(start, at, operandAt, op, value, member, targets));
    }
    var byOffset = rows.ToDictionary(r => r.Offset);
    foreach (var row in rows)
        if (row.Targets.Any(t => !byOffset.ContainsKey(t))) throw new InvalidDataException("Branch does not target an actual instruction");
    var fields = new[] { "<IsFinal>k__BackingField", "<Type>k__BackingField", "<HasMask>k__BackingField", "<Length>k__BackingField" }
        .Select(name => type.GetField(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!).ToArray();
    if (fields.Any(f => f == null) || fields[0].FieldType != typeof(bool) || !fields[1].FieldType.IsEnum
        || Enum.GetUnderlyingType(fields[1].FieldType) != typeof(byte) || fields[2].FieldType != typeof(bool) || fields[3].FieldType != typeof(ulong))
        throw new InvalidDataException("Original four header-field contracts differ");
    var pathRows = new List<PathRow>();
    var active = new HashSet<int>(); int visits = 0;
    void Visit(int offset, int stores, List<int> callOffsets, List<int> storeOffsets)
    {
        if (++visits > 4096 || active.Count > 512) throw new InvalidDataException("Prefix CFG budget exceeded");
        if (!active.Add(offset)) throw new InvalidDataException("Cycle before first header Length store");
        var row = byOffset[offset]; prefixOffsets.Add(offset);
        var nextCalls = callOffsets.ToList(); var nextStores = storeOffsets.ToList(); int nextMask = stores;
        if (row.Member is MethodInfo call && call.Name == "ReadByte" && call.DeclaringType == typeof(Stream)) nextCalls.Add(offset);
        if (row.Op == OpCodes.Stfld && row.Member is FieldInfo field)
        {
            int index = Array.IndexOf(fields, field);
            if (index < 0) limitations.Add("Unexpected field write before header Length store");
            else { nextMask |= 1 << index; nextStores.Add(index); }
            if (index == 3)
            {
                pathRows.Add(new(row.End, nextMask, nextCalls.ToArray(), nextStores.ToArray())); fencePaths++;
                active.Remove(offset); return;
            }
        }
        if (row.Op.FlowControl is FlowControl.Return or FlowControl.Throw) throw new InvalidDataException("Prefix exits before header Length store");
        if (row.Op.FlowControl == FlowControl.Branch)
        {
            if (row.Targets.Length != 1 || row.Op == OpCodes.Leave || row.Op == OpCodes.Leave_S) throw new InvalidDataException("Unsupported prefix transfer");
            Visit(row.Targets[0], nextMask, nextCalls, nextStores);
        }
        else
        {
            if (row.Op.FlowControl == FlowControl.Cond_Branch) foreach (int target in row.Targets) Visit(target, nextMask, nextCalls, nextStores);
            if (!byOffset.ContainsKey(row.End)) throw new InvalidDataException("Prefix falls off original body");
            Visit(row.End, nextMask, nextCalls, nextStores);
        }
        active.Remove(offset);
    }
    Visit(rows[0].Offset, 0, [], []);
    prefixShape = pathRows.Count > 0 && pathRows.All(p => p.Stores == 15 && p.CallOffsets.Length == 2 && p.StoreOrder.SequenceEqual([0, 1, 2, 3]));
    Check("all bounded actual entry paths preserve2 calls and4 original header stores in order", prefixShape);
    var prefix = rows.Where(r => prefixOffsets.Contains(r.Offset)).ToArray();
    var meaningful = rows.Where(r => r.Op != OpCodes.Nop).ToArray();
    foreach (var row in prefix)
    {
        if (row.Member is MethodInfo target && row.Op.FlowControl == FlowControl.Call)
        {
            bool readByte = target.DeclaringType == typeof(Stream) && target.Name == "ReadByte" && !target.IsStatic && target.IsVirtual
                && target.ReturnType == typeof(int) && target.GetParameters().Length == 0;
            if (readByte)
            {
                if (row.Op == OpCodes.Callvirt) actualVirtualCalls++; else directReadByteCalls++;
                callRows.Add(new { offset = row.Offset, opcode = row.Op.Name, metadata_token = $"0x{row.Value:X8}",
                    declaring_type = target.DeclaringType!.FullName, target.Name, return_type = target.ReturnType.FullName, target.IsVirtual });
            }
            else
            {
                diagnosticRows.Add(new { offset = row.Offset, opcode = row.Op.Name, declaring_type = target.DeclaringType?.FullName, target.Name });
                limitations.Add("Actual prefix contains an unresolved diagnostic/helper or unexpected call");
            }
        }
        if (row.Op == OpCodes.Conv_I || row.Op == OpCodes.Conv_U) limitations.Add("Actual prefix still converts an object/pointer through native-int storage");
        if (row.Op == OpCodes.Calli || row.Op == OpCodes.Jmp || row.Op == OpCodes.Ldflda || row.Op == OpCodes.Ldsflda)
            limitations.Add("Actual prefix contains unsupported indirect/address-sensitive semantics");
        int i = Array.IndexOf(meaningful, row);
        if (i + 4 < meaningful.Length && row.Op == OpCodes.Ldstr && meaningful[i + 1].Member is MethodInfo helper
            && helper.DeclaringType?.FullName == "Cpp2ILInjected.Cpp2ILHelpers" && helper.Name == "NoteDecompilerIssue"
            && meaningful[i + 2].Op == OpCodes.Ldc_I4_0 && meaningful[i + 3].Op == OpCodes.Conv_I
            && meaningful[i + 4].Op.Name!.StartsWith("stloc"))
        {
            int slot = meaningful[i + 4].Value; string diagnostic = method.Module.ResolveString(row.Value);
            placeholderRows.Add(new { diagnostic_offset = row.Offset, helper_offset = meaningful[i + 1].Offset,
                zero_offset = meaningful[i + 2].Offset, conversion_offset = meaningful[i + 3].Offset, store_offset = meaningful[i + 4].Offset,
                local = slot, local_type = body.LocalVariables[slot].LocalType.FullName, diagnostic_sha256 = Hash(System.Text.Encoding.UTF8.GetBytes(diagnostic)),
                paired_method_info_offset_0x260 = diagnostic.Contains("+260]", StringComparison.Ordinal) });
            limitations.Add("Actual prefix contains a diagnostic-to-native-int-zero placeholder; it is not recovered native null");
        }
    }
    Check("both actual slot19 member references have exact Stream.ReadByte identity", actualVirtualCalls + directReadByteCalls == 2);
    Check("both actual native-virtual sites retain CIL callvirt", actualVirtualCalls == 2 && directReadByteCalls == 0);
    Check("actual prefix has no unresolved diagnostic/helper-zero substitutions", diagnosticRows.Count == 0 && placeholderRows.Count == 0);
    Check("actual prefix has no object-to-native-int residue", !prefix.Any(r => r.Op == OpCodes.Conv_I || r.Op == OpCodes.Conv_U));
    Check("read-only inspection preserves actual original method body", Hash(method.GetMethodBody()!.GetILAsByteArray()!) == bodyHash);
    correlation = prefixShape && actualVirtualCalls == 2 && directReadByteCalls == 0;
    runtimeEligible = nativeBound && correlation && limitations.Count == 0;
    evidence["actual_method_token"] = $"0x{method.MetadataToken:X8}";
    evidence["actual_body_bytes"] = bytes.Length; evidence["actual_init_locals"] = body.InitLocals;
    evidence["actual_eh_clauses"] = body.ExceptionHandlingClauses.Count;
    evidence["prefix_instruction_count"] = prefix.Length; evidence["prefix_cfg_visits"] = visits;
    evidence["prefix_fence_paths"] = pathRows; evidence["prefix_fence_original_field"] = fields[3].Name;
    evidence["original_header_field_tokens"] = fields.Select(f => new { f.Name, metadata_token = $"0x{f.MetadataToken:X8}", type = f.FieldType.FullName }).ToArray();
    evidence["native_prefix_end"] = "0x4A0E00";
    string privateFolder = Guard($"analysis/reconstruction/virtual-stream-dispatch-v36/actual-{run}"); Directory.CreateDirectory(privateFolder);
    string privatePath = Path.Combine(privateFolder, "actual-cil.json");
    File.WriteAllText(privatePath, JsonSerializer.Serialize(new { method = method.ToString(), body_sha256 = bodyHash,
        original_instructions = rows.Select(r => new { r.Offset, r.End, opcode = r.Op.Name, operand = r.Member?.ToString() ?? r.Value.ToString(),
            owner = r.Member?.DeclaringType?.FullName, r.Targets, in_prefix = prefixOffsets.Contains(r.Offset) }),
        locals = body.LocalVariables.Select(v => new { v.LocalIndex, type = v.LocalType.FullName }), paths = pathRows }, new JsonSerializerOptions { WriteIndented = true }) + "\n");
    privateHash = FileHash(privatePath); evidence["private_actual_cil_path"] = Path.GetRelativePath(root, privatePath);
}
catch (Exception error) { fatal = error.ToString(); }
context.Unload();
if (directReadByteCalls > 0) limitations.Add("Ordinary CIL call does not preserve observed native override dispatch");
if (runtimeEligible) limitations.Add("Clean prefix correlation found; isolated execution still requires a separately reviewed boundary executor");
string status = correlation ? "ACTUAL_VIRTUAL_PREFIX_CORRELATED_EXECUTION_LIMITATIONS" : "RECOVERY_EXECUTION_LIMITATION_CONFIRMED";
var output = new { status, recovery_run = run, native_evidence_bound = nativeBound, native_fixture_cases = fixtureCases,
    native_virtual_calls = nativeCalls, native_eof_returns = nativeEof, structural_checks = checks,
    actual_native_virtual_identity_preserved = correlation, actual_callvirt_sites = actualVirtualCalls, actual_direct_readbyte_sites = directReadByteCalls,
    actual_prefix_cfg_shape_proven = prefixShape, prefix_fence_paths = fencePaths, calls = callRows,
    unresolved_prefix_calls = diagnosticRows, helper_zero_placeholders = placeholderRows, evidence,
    runtime_eligible = runtimeEligible, runtime_performed = false, runtime_cases = 0, actual_game_methods_invoked = 0,
    execution_limitations = limitations.Distinct().ToArray(), fatal,
    assembly_sha256 = File.Exists(assemblyPath) ? FileHash(assemblyPath) : null, actual_body_il_sha256 = bodyHash,
    native_report_sha256 = FileHash(nativeReport), fixture_sha256 = FileHash(fixturePath), private_cil_evidence_sha256 = privateHash,
    probe_source_sha256 = FileHash(Guard("src/re/RecoveredVirtualStreamPrefixProbe/Program.cs")),
    cil_or_source_modified = false, call_opcodes_rewritten = 0, member_substitutions = 0, tokens_remapped = 0, dynamic_clones = 0,
    scope = "Read-only inspection of the unchanged actual recovered Read(Stream) CIL. Bounded CFG entry paths stop at the first original header Length field store, preserving actual call opcodes and member/field identities. Slot19 native dispatch and all802 original native cases are independently hash-bound. Diagnostics, native-int placeholder zeros and missing callvirt are explicit execution blockers; none are rewritten, removed, retargeted or executed. No runtime cases, cloned fragments, game/static constructors or helper substitutions are counted as recovery. Native constructor/vtable input boundaries, complete frame parsing, exception paths and full clean source remain separate." };
File.WriteAllText(Guard($"reports/recovered-virtual-stream-prefix-{run}.json"), JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { status, actualVirtualCalls, directReadByteCalls, diagnostic_calls = diagnosticRows.Count,
    placeholders = placeholderRows.Count, fencePaths, runtime_performed = false, fatal }));
return correlation && fatal == null ? 0 : 2;

record Check(string Name, string Status);
record Row(int Offset, int End, int OperandAt, OpCode Op, int Value, MemberInfo? Member, int[] Targets);
record PathRow(int End, int Stores, int[] CallOffsets, int[] StoreOrder);
