using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;

if (args.Length != 2 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$")) throw new ArgumentException("USB root and candidate run required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1], baseline = "nso-runtime-helper-abi-v37";
string Guard(string relative) { string p = Path.GetFullPath(Path.Combine(root, relative)); if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB"); for (DirectoryInfo? d = new(Path.GetDirectoryName(p)!); d != null; d = d.Parent) if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point"); return p; }
string Hash(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
string FileHash(string relative) => Hash(File.ReadAllBytes(Guard(relative)));
var checks = new List<object>(); string? fatal = null; Observation? old = null, current = null;
var snapshots = new Dictionary<string, Snapshot>(); var tokenComparisons = new List<object>();
void Check(string name, bool ok) { checks.Add(new { name, passed = ok }); if (!ok) throw new InvalidDataException(name); }
var opcodes = typeof(OpCodes).GetFields(BindingFlags.Static | BindingFlags.Public).Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!).ToDictionary(o => unchecked((ushort)o.Value));
List<Row> Decode(MethodInfo method)
{
    byte[] code = method.GetMethodBody()!.GetILAsByteArray()!; var rows = new List<Row>();
    for (int at = 0; at < code.Length;)
    {
        int start = at; ushort value = code[at++]; if (value == 0xFE) value = (ushort)(0xFE00 | code[at++]); var op = opcodes[value]; int operandAt = at;
        int width = op.OperandType switch { OperandType.InlineNone => 0, OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1, OperandType.InlineVar => 2,
            OperandType.InlineI8 or OperandType.InlineR => 8, OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)), _ => 4 };
        at += width; if (width < 0 || at > code.Length) throw new InvalidDataException("Truncated actual CIL");
        int operand = width == 4 ? BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(operandAt, 4)) : width == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(code.AsSpan(operandAt, 2)) : width == 1 ? code[operandAt] : 0;
        MemberInfo? member = op.OperandType is OperandType.InlineMethod or OperandType.InlineField or OperandType.InlineType or OperandType.InlineTok ? method.Module.ResolveMember(operand) : null;
        string? text = op.OperandType == OperandType.InlineString ? method.Module.ResolveString(operand) : null;
        int[] targets = op.OperandType == OperandType.InlineBrTarget ? [at + operand] : op.OperandType == OperandType.ShortInlineBrTarget ? [at + unchecked((sbyte)operand)] : [];
        if (op.OperandType == OperandType.InlineSwitch) throw new InvalidDataException("Unexpected switch in reviewed methods");
        rows.Add(new(start, at, op, operand, member, text, targets));
    }
    return rows;
}
string Key(MethodInfo m) => m.DeclaringType!.FullName + "::" + m.Name + "(" + string.Join(",", m.GetParameters().Select(p => p.ParameterType.FullName)) + ")->" + m.ReturnType.FullName;
string TypeKey(Type type) => type.Assembly.GetName().FullName + "::" + type.FullName;
string MemberKey(MemberInfo member) => member switch { MethodInfo m => TypeKey(m.DeclaringType!) + "::" + m.Name + "(" + string.Join(",", m.GetParameters().Select(p => TypeKey(p.ParameterType))) + ")->" + TypeKey(m.ReturnType) + ":generic=" + string.Join(",", m.GetGenericArguments().Select(TypeKey)), ConstructorInfo c => TypeKey(c.DeclaringType!) + "::.ctor(" + string.Join(",", c.GetParameters().Select(p => TypeKey(p.ParameterType))) + ")", FieldInfo f => TypeKey(f.DeclaringType!) + "::" + f.Name + ":" + TypeKey(f.FieldType), Type t => TypeKey(t), _ => throw new InvalidDataException("Unrecognized member identity") };
object[] SemanticRows(List<Row> rows) => rows.Select(r => (object)new { r.Offset, r.End, opcode = r.Op.Name, operand = r.Member != null ? MemberKey(r.Member) : r.Text != null ? "string:" + r.Text : r.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), r.Targets }).ToArray();
string SemanticHash(MethodInfo method, List<Row> rows) => Hash(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { instructions = SemanticRows(rows), init_locals = method.GetMethodBody()!.InitLocals, max_stack = method.GetMethodBody()!.MaxStackSize, locals = method.GetMethodBody()!.LocalVariables.Select(l => new { l.LocalIndex, type = l.LocalType.FullName, l.IsPinned }), exceptions = method.GetMethodBody()!.ExceptionHandlingClauses.Select(e => new { e.Flags, e.TryOffset, e.TryLength, e.HandlerOffset, e.HandlerLength, filter = e.Flags == ExceptionHandlingClauseOptions.Filter ? e.FilterOffset : -1, catch_type = e.Flags == ExceptionHandlingClauseOptions.Clause ? e.CatchType?.FullName : null }) })));
Snapshot TakeSnapshot(MethodInfo method, List<Row> rows) => new(method.GetMethodBody()!.GetILAsByteArray()!, rows, JsonSerializer.Serialize(new { method_key = MemberKey(method), init_locals = method.GetMethodBody()!.InitLocals, max_stack = method.GetMethodBody()!.MaxStackSize, locals = method.GetMethodBody()!.LocalVariables.Select(l => new { l.LocalIndex, type = TypeKey(l.LocalType), l.IsPinned }), exceptions = method.GetMethodBody()!.ExceptionHandlingClauses.Select(e => new { e.Flags, e.TryOffset, e.TryLength, e.HandlerOffset, e.HandlerLength, filter = e.Flags == ExceptionHandlingClauseOptions.Filter ? e.FilterOffset : -1, catch_type = e.Flags == ExceptionHandlingClauseOptions.Clause ? TypeKey(e.CatchType!) : null }) }));
void CompareUnchanged(string label)
{
    var before = snapshots[baseline + label]; var after = snapshots[run + label];
    Check(label + " exact method/local/pinning/InitLocals/maxstack/EH identities", before.Shape == after.Shape);
    Check(label + " same byte length and instruction boundaries", before.Code.Length == after.Code.Length && before.Rows.Count == after.Rows.Count && before.Rows.Zip(after.Rows).All(pair => pair.First.Offset == pair.Second.Offset && pair.First.End == pair.Second.End && pair.First.Op == pair.Second.Op));
    byte[] left = (byte[])before.Code.Clone(), right = (byte[])after.Code.Clone(); int metadataOperands = 0, changedTokens = 0;
    foreach (var (a, b) in before.Rows.Zip(after.Rows))
    {
        bool token = a.Op.OperandType is OperandType.InlineMethod or OperandType.InlineField or OperandType.InlineType or OperandType.InlineTok or OperandType.InlineString;
        if (!token) continue;
        if (a.End - a.Offset != a.Op.Size + 4) throw new InvalidDataException("Non4byte metadata operand");
        string identityA = a.Op.OperandType == OperandType.InlineString ? "string:" + a.Text : MemberKey(a.Member!);
        string identityB = b.Op.OperandType == OperandType.InlineString ? "string:" + b.Text : MemberKey(b.Member!);
        if (identityA != identityB) throw new InvalidDataException(label + " resolved metadata identity differs at " + a.Offset);
        metadataOperands++; if (a.Value != b.Value) changedTokens++;
        left.AsSpan(a.Offset + a.Op.Size, 4).Clear(); right.AsSpan(b.Offset + b.Op.Size, 4).Clear();
    }
    Check(label + " exact all non-token opcode/operand bytes and matched metadata identities", left.SequenceEqual(right));
    tokenComparisons.Add(new { method = label, instructions = before.Rows.Count, raw_before_sha256 = Hash(before.Code), raw_after_sha256 = Hash(after.Code), normalized_sha256 = Hash(left), matched_metadata_operands = metadataOperands, changed_metadata_tokens = changedTokens, all_non_token_bytes_equal = true, original_cil_rewritten = false });
}
Observation Observe(string recovery)
{
    string folder = Guard($"analysis/il2cpp/cpp2il-recovery-{recovery}"); var context = new AssemblyLoadContext("xml_companion_" + recovery, true);
    context.Resolving += (c, n) => File.Exists(Path.Combine(folder, n.Name + ".dll")) ? c.LoadFromAssemblyPath(Path.Combine(folder, n.Name + ".dll")) : null;
    try
    {
        var main = context.LoadFromAssemblyPath(Path.Combine(folder, "Assembly-CSharp.dll")); var first = context.LoadFromAssemblyPath(Path.Combine(folder, "Assembly-CSharp-firstpass.dll"));
        var xml = main.GetType("XmlExtensions", true)!;
        var method = xml.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static).Single(m => m.Name == "TryGetAttribute" && m.GetParameters().Select(p => p.ParameterType).SequenceEqual(new[] { typeof(XmlNode), typeof(string) }));
        Check(recovery + " actual TryGetAttribute metadata signature", method.ReturnType == typeof(XmlAttribute) && method.GetMethodBody()!.ExceptionHandlingClauses.Count == 0);
        var getter = typeof(XmlNode).GetProperty(nameof(XmlNode.Attributes))!.GetMethod!;
        var tail = typeof(XmlAttributeCollection).GetMethods().Single(m => m.Name == "get_ItemOf" && m.GetParameters().Select(p => p.ParameterType).SequenceEqual(new[] { typeof(string) }));
        var rows = Decode(method); var calls = rows.Where(r => r.Member is MethodInfo).ToArray();
        bool Getter(Row row) => row.Member is MethodInfo m && m == getter && m.IsVirtual && m.ReturnType == typeof(XmlAttributeCollection) && m.GetParameters().Length == 0;
        bool Tail(Row row) => row.Member is MethodInfo m && m == tail && m.ReturnType == typeof(XmlAttribute);
        var getterCalls = calls.Where(Getter).ToArray(); var tailCalls = calls.Where(Tail).ToArray();
        var issues = calls.Where(r => r.Member!.DeclaringType?.FullName?.StartsWith("Cpp2ILInjected.", StringComparison.Ordinal) == true).ToArray();
        var diagnostics = rows.Where(r => r.Text != null).Select(r => r.Text!).ToArray();
        var firstAttribute = xml.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static).Single(m => m.Name == "FirstAttribute"); var firstRows = Decode(firstAttribute);
        var reader = first.GetType("BestHTTP.WebSocket.Frames.WebSocketFrameReader", true)!.GetMethod("Read", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance, [typeof(Stream)]) ?? throw new InvalidDataException("Exact original internal Read(Stream) method missing"); var readerRows = Decode(reader);
        var yaml = first.GetType("YamlDotNet.Core.Emitter", true)!.GetMethod("Write", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance, [typeof(char)])!; var yamlRows = Decode(yaml);
        snapshots.Add(recovery + "Stream.Read", TakeSnapshot(reader, readerRows)); snapshots.Add(recovery + "Emitter.Write", TakeSnapshot(yaml, yamlRows));
        var extra = new { first_attribute_getter_callvirt_sites = firstRows.Count(r => r.Op == OpCodes.Callvirt && Getter(r)), first_attribute_unresolved_178 = firstRows.Count(r => r.Text?.Contains("+178]", StringComparison.Ordinal) == true),
            stream_readbyte_callvirt_sites = readerRows.Count(r => r.Op == OpCodes.Callvirt && r.Member is MethodInfo m && m.DeclaringType == typeof(Stream) && m.Name == "ReadByte"),
            stream_body_sha256 = Hash(reader.GetMethodBody()!.GetILAsByteArray()!), stream_semantic_sha256 = SemanticHash(reader, readerRows), yaml_semantic_sha256 = SemanticHash(yaml, yamlRows), yaml_body_sha256 = Hash(yaml.GetMethodBody()!.GetILAsByteArray()!), yaml_unresolved_void_argument = yamlRows.Count(r => r.Text?.Contains("+1E8]", StringComparison.Ordinal) == true) };
        string privatePath = Guard($"analysis/reconstruction/virtual-companion-cil/{recovery}.json"); Directory.CreateDirectory(Path.GetDirectoryName(privatePath)!);
        File.WriteAllText(privatePath, JsonSerializer.Serialize(new { method_token = method.MetadataToken, instructions = rows.Select(r => new { r.Offset, r.End, opcode = r.Op.Name, r.Value, member = r.Member?.ToString(), owner = r.Member?.DeclaringType?.FullName, r.Text, r.Targets }), stream_semantic_instructions = SemanticRows(readerRows), yaml_semantic_instructions = SemanticRows(yamlRows), extra }, new JsonSerializerOptions { WriteIndented = true }) + "\n");
        var result = new Observation(recovery, Hash(File.ReadAllBytes(Path.Combine(folder, "Assembly-CSharp.dll"))), Hash(method.GetMethodBody()!.GetILAsByteArray()!), rows.Count,
            getterCalls.Count(r => r.Op == OpCodes.Callvirt), getterCalls.Count(r => r.Op != OpCodes.Callvirt), tailCalls.Length, tailCalls.All(r => r.Op == OpCodes.Call), issues.Length,
            diagnostics.Any(d => d.Contains("Indirect call", StringComparison.Ordinal) && d.Contains("+188]", StringComparison.Ordinal)),
            rows.Count(r => r.Op == OpCodes.Conv_I || r.Op == OpCodes.Conv_U), extra.first_attribute_getter_callvirt_sites, extra.first_attribute_unresolved_178,
            extra.stream_readbyte_callvirt_sites, extra.stream_body_sha256, extra.stream_semantic_sha256, extra.yaml_body_sha256, extra.yaml_semantic_sha256, extra.yaml_unresolved_void_argument,
            Path.GetRelativePath(root, privatePath), Hash(File.ReadAllBytes(privatePath)), calls.Where(r => r.Member is MethodInfo).Select(r => new { offset = r.Offset, opcode = r.Op.Name, exact_member_key = Key((MethodInfo)r.Member!), original_metadata_token = $"0x{r.Value:X8}" }).ToArray());
        if (recovery != baseline)
        {
            Check("current original call set is only exact virtual getter and exact direct indexer", calls.Length == 2 && result.GetterVirtual == 1 && result.GetterDirect == 0 && result.TailCount == 1 && result.TailDirect && result.Issues == 0);
            Check("no pointer casts, helper placeholders, field writes or address operations in actual helper", result.PointerConversions == 0 && rows.All(r => r.Op != OpCodes.Stfld && r.Op != OpCodes.Stsfld && r.Op != OpCodes.Calli && r.Op != OpCodes.Jmp && r.Op != OpCodes.Ldind_I && r.Op != OpCodes.Stind_I));
            var allowed = new HashSet<OpCode> { OpCodes.Nop, OpCodes.Ldarg_0, OpCodes.Ldarg_1, OpCodes.Ldarg, OpCodes.Ldloc, OpCodes.Stloc, OpCodes.Ldnull, OpCodes.Ldc_I4, OpCodes.Ldc_I4_0, OpCodes.Ceq, OpCodes.Br, OpCodes.Brtrue, OpCodes.Brfalse, OpCodes.Call, OpCodes.Callvirt, OpCodes.Ret };
            Check("actual helper uses only bounded control/local/member instructions", rows.All(r => allowed.Contains(r.Op)));
            // Analyze original CIL values without running any game/BCL call.
            foreach (bool nullNode in new[] { true, false })
            {
                var values = new Dictionary<int, object?>(); var stack = new Stack<object?>(); var byOffset = rows.ToDictionary(r => r.Offset); var seen = new HashSet<int>(); int pc = 0; var events = new List<string>(); object? returned = null;
                while (true)
                {
                    if (!seen.Add(pc) || seen.Count > 128) throw new InvalidDataException("Unexpected helper loop"); var r = byOffset[pc]; int next = r.End;
                    if (r.Op == OpCodes.Ldarg_0 || r.Op == OpCodes.Ldarg && r.Value == 0) stack.Push(nullNode ? null : "NODE");
                    else if (r.Op == OpCodes.Ldarg_1 || r.Op == OpCodes.Ldarg && r.Value == 1) stack.Push("NAME");
                    else if (r.Op == OpCodes.Ldloc) stack.Push(values[r.Value]); else if (r.Op == OpCodes.Stloc) values[r.Value] = stack.Pop();
                    else if (r.Op == OpCodes.Ldnull) stack.Push(null); else if (r.Op == OpCodes.Ldc_I4 || r.Op == OpCodes.Ldc_I4_0) stack.Push(r.Op == OpCodes.Ldc_I4_0 ? 0 : r.Value);
                    else if (r.Op == OpCodes.Ceq) { var b = stack.Pop(); var a = stack.Pop(); bool Zero(object? x) => x == null || x is int i && i == 0; stack.Push(Zero(a) && Zero(b) || Equals(a, b) ? 1 : 0); }
                    else if (r.Op == OpCodes.Br) next = r.Targets.Single();
                    else if (r.Op == OpCodes.Brtrue || r.Op == OpCodes.Brfalse) { var v = stack.Pop(); bool truth = v != null && !(v is int i && i == 0); if (truth == (r.Op == OpCodes.Brtrue)) next = r.Targets.Single(); }
                    else if (Getter(r)) { if (!Equals(stack.Pop(), "NODE")) throw new InvalidDataException("Getter does not consume original node"); events.Add("getter"); stack.Push("ATTRIBUTES_RESULT"); }
                    else if (Tail(r)) { if (!Equals(stack.Pop(), "NAME") || !Equals(stack.Pop(), "ATTRIBUTES_RESULT")) throw new InvalidDataException("Tail does not consume original name/getter result"); events.Add("indexer"); stack.Push("ATTRIBUTE_RESULT"); }
                    else if (r.Op == OpCodes.Ret) { returned = stack.Pop(); if (stack.Count != 0) throw new InvalidDataException("Return stack differs"); break; }
                    else if (r.Op != OpCodes.Nop) throw new InvalidDataException("Unsupported abstract instruction"); pc = next;
                }
                Check(nullNode ? "null receiver path returns null without getter/indexer" : "non-null path retains original getter-result/name tail dataflow", nullNode ? returned == null && events.Count == 0 : Equals(returned, "ATTRIBUTE_RESULT") && events.SequenceEqual(new[] { "getter", "indexer" }));
            }
        }
        return result;
    }
    finally { context.Unload(); }
}
try
{
    using var native = JsonDocument.Parse(File.ReadAllText(Guard("analysis/reconstruction/virtual-copy-root-v38/native-inventory.json")));
    Check("original native witness current/hash-bound", native.RootElement.GetProperty("native_sha256").GetString() == FileHash("analysis/nso/main-uncompressed.nso") && native.RootElement.GetProperty("methods")[0].GetProperty("sha256").GetString() == "31624d0e92a6f3d234085049e27d6d43d93a464f4c6d4f51856901ec77d48c00");
    old = Observe(baseline); current = Observe(run);
    Check("frozen baseline retains copied-companion diagnostic and no virtual getter", old.GetterVirtual == 0 && old.Has188Diagnostic && old.Issues > 0);
    Check("tail target and direct opcode retained in both recovered versions", old.TailCount == 1 && old.TailDirect && current.TailCount == 1 && current.TailDirect);
    Check("other original getter sites and deferred producer-root stay unchanged", old.FirstGetterVirtual == 2 && current.FirstGetterVirtual == 2 && old.First178 == 1 && current.First178 == 1);
    Check("both original Stream virtual sites retained", old.StreamVirtual == 2 && current.StreamVirtual == 2); CompareUnchanged("Stream.Read");
    Check("deferred Yaml void-argument site retained", old.YamlIssue == 1 && current.YamlIssue == 1); CompareUnchanged("Emitter.Write");
}
catch (Exception error) { fatal = error.ToString(); }
string status = fatal == null ? "PASS_ACTUAL_COPIED_COMPANION_CALLVIRT_AND_UNCHANGED_SCOPE_CORRELATION" : "ACTUAL_COMPANION_CIL_CORRELATION_FAILED";
var output = new { status, recovery_run = run, baseline_run = baseline, checks = checks.Count, tests = checks, baseline = old, actual = current, token_only_comparisons = tokenComparisons, fatal,
    probe_source_sha256 = FileHash("src/re/RecoveredVirtualCompanionProbe/Program.cs"), native_inventory_sha256 = FileHash("analysis/reconstruction/virtual-copy-root-v38/native-inventory.json"),
    game_methods_invoked = 0, runtime_cases = 0, cil_modified = false, call_opcodes_rewritten = 0, member_substitutions = 0, dynamic_clones = 0, tokens_remapped = 0, full_clean_decompile_ready = false,
    raw_cil_hashes_retained = true, unaffected_methods_comparison = "Exact opcodes, offsets, all immediate/string operands, resolved member identities, branch destinations, local types/pinning, InitLocals, MaxStack and EH clauses. Original raw hashes are retained separately because emitted metadata token numbering can change across full outputs.",
    scope = "Read-only actual recovered CIL comparison in isolated collectible assembly contexts. Exact original virtual XmlNode.Attributes getter and direct XmlAttributeCollection indexer identities/opcodes, null branch and saved name/getter-result dataflow are analyzed without invoking either method. Null-getter results, real XML parsing, exceptions, constructor/runtime effects and whole-game behavior remain unexecuted; the original76-byte native witness provides separate register/copy/control evidence." };
File.WriteAllText(Guard($"reports/recovered-virtual-companion-{run}.json"), JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }) + "\n"); Console.WriteLine(JsonSerializer.Serialize(new { status, checks = checks.Count, fatal })); return fatal == null ? 0 : 2;

record Row(int Offset, int End, OpCode Op, int Value, MemberInfo? Member, string? Text, int[] Targets);
record Snapshot(byte[] Code, List<Row> Rows, string Shape);
record Observation(string Recovery, string AssemblyHash, string BodyHash, int Instructions, int GetterVirtual, int GetterDirect, int TailCount, bool TailDirect, int Issues, bool Has188Diagnostic, int PointerConversions,
    int FirstGetterVirtual, int First178, int StreamVirtual, string StreamHash, string StreamSemanticHash, string YamlHash, string YamlSemanticHash, int YamlIssue, string PrivatePath, string PrivateHash, object[] Calls);
