using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;

if (args.Length is < 2 or > 3 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$") || args.Length == 3 && args[2] != "--execute") throw new ArgumentException("USB root, pinned run and optional --execute required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1]; bool execute = args.Length == 3;
string Guard(string relative) { string path = Path.GetFullPath(Path.Combine(root, relative)); if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB"); for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent) if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point"); return path; }
string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
string FileHash(string relative) => Hash(File.ReadAllBytes(Guard(relative)));
var tests = new List<object>(); var results = new List<object>(); int cases = 0, attempts = 0, comparisons = 0, failures = 0, observedOverrides = 0;
void Check(string name, bool passed) { tests.Add(new { name, passed }); if (!passed) throw new InvalidDataException(name); }
string? fatal = null; string? assemblyHash = null, bodyHash = null; int methodToken = 0, instructionCount = 0; string inspectionHash = FileHash($"reports/recovered-virtual-companion-{run}.json");
var loadContext = new AssemblyLoadContext("unchanged_xml_helper_" + run, true);
try
{
    Check("only reviewed v38 run accepted", run == "nso-virtual-companion-copy-v38");
    using var inspection = JsonDocument.Parse(File.ReadAllText(Guard($"reports/recovered-virtual-companion-{run}.json")));
    Check("completed read-only original CIL correlation required", inspection.RootElement.GetProperty("status").GetString() == "PASS_ACTUAL_COPIED_COMPANION_CALLVIRT_AND_UNCHANGED_SCOPE_CORRELATION");
    Check("inspection performed no original method execution or rewriting", inspection.RootElement.GetProperty("game_methods_invoked").GetInt32() == 0 && !inspection.RootElement.GetProperty("cil_modified").GetBoolean() && inspection.RootElement.GetProperty("member_substitutions").GetInt32() == 0);
    string folder = Guard($"analysis/il2cpp/cpp2il-recovery-{run}");
    loadContext.Resolving += (context, name) => File.Exists(Path.Combine(folder, name.Name + ".dll")) ? context.LoadFromAssemblyPath(Path.Combine(folder, name.Name + ".dll")) : null;
    var assembly = loadContext.LoadFromAssemblyPath(Path.Combine(folder, "Assembly-CSharp.dll"));
    assemblyHash = Hash(File.ReadAllBytes(Path.Combine(folder, "Assembly-CSharp.dll")));
    Check("actual unchanged assembly matches completed inspection", assemblyHash == inspection.RootElement.GetProperty("actual").GetProperty("AssemblyHash").GetString());
    var owner = assembly.GetType("XmlExtensions", true)!;
    Check("original declaring type has no type initializer", owner.TypeInitializer == null);
    var method = owner.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static).Single(m => m.Name == "TryGetAttribute" && m.GetParameters().Select(p => p.ParameterType).SequenceEqual(new[] { typeof(XmlNode), typeof(string) }));
    methodToken = method.MetadataToken; byte[] code = method.GetMethodBody()!.GetILAsByteArray()!; bodyHash = Hash(code);
    Check("exact reviewed complete body hash and static closed signature", bodyHash == "8f4bd15d3a389843ed61de4163d0f30d12ccf2256c3ed1a696221af9f7dcda90" && bodyHash == inspection.RootElement.GetProperty("actual").GetProperty("BodyHash").GetString() && method.IsStatic && !method.IsGenericMethod && method.ReturnType == typeof(XmlAttribute));
    Check("no original EH clauses", method.GetMethodBody()!.ExceptionHandlingClauses.Count == 0);
    var getter = typeof(XmlNode).GetProperty(nameof(XmlNode.Attributes))!.GetMethod!;
    var indexer = typeof(XmlAttributeCollection).GetMethods().Single(m => m.Name == "get_ItemOf" && m.GetParameters().Select(p => p.ParameterType).SequenceEqual(new[] { typeof(string) }));
    var opcodes = typeof(OpCodes).GetFields(BindingFlags.Static | BindingFlags.Public).Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!).ToDictionary(o => unchecked((ushort)o.Value));
    var calls = new List<(OpCode Op, MethodInfo Method)>();
    var allowed = new HashSet<OpCode> { OpCodes.Ldarg, OpCodes.Ldc_I4, OpCodes.Ceq, OpCodes.Stloc, OpCodes.Ldloc, OpCodes.Brtrue, OpCodes.Br, OpCodes.Nop, OpCodes.Callvirt, OpCodes.Call, OpCodes.Ret, OpCodes.Ldnull };
    for (int cursor = 0; cursor < code.Length;)
    {
        ushort value = code[cursor++]; if (value == 0xFE) value = (ushort)(0xFE00 | code[cursor++]); var opcode = opcodes[value];
        if (!allowed.Contains(opcode)) throw new InvalidDataException("Unreviewed original opcode");
        int width = opcode.OperandType switch { OperandType.InlineNone => 0, OperandType.InlineVar => 2, OperandType.InlineI or OperandType.InlineBrTarget or OperandType.InlineMethod => 4, _ => throw new InvalidDataException("Unreviewed original operand") };
        if (cursor + width > code.Length) throw new InvalidDataException("Truncated original CIL");
        if (opcode.OperandType == OperandType.InlineMethod) calls.Add((opcode, method.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(cursor, 4))) as MethodInfo ?? throw new InvalidDataException("Nonmethod original call")));
        cursor += width; instructionCount++;
    }
    Check("entire original helper has exactly19 reviewed instructions", instructionCount == 19);
    Check("complete original call allowlist is exact host XmlNode virtual getter and direct collection indexer", calls.Count == 2 && calls[0].Op == OpCodes.Callvirt && calls[0].Method == getter && calls[1].Op == OpCodes.Call && calls[1].Method == indexer && getter.IsVirtual && getter.ReturnType == typeof(XmlAttributeCollection) && getter.GetParameters().Length == 0 && indexer.ReturnType == typeof(XmlAttribute));
    if (execute)
    {
        // Authored host XML inputs. No recovered XML/game constructor is invoked.
        var document = new XmlDocument(); document.LoadXml("<root present='value' empty='' xmlns:p='urn:p' p:flag='namespaced'><child child='x'/>hello<!--comment--></root>");
        XmlElement element = document.DocumentElement!; XmlNode child = element.FirstChild!; XmlNode text = element.ChildNodes[1]!; XmlNode comment = element.LastChild!;
        var observing = new ObservingDocument(element.Attributes, null); var nullGetter = new ObservingDocument(null, null); var throwingGetter = new ObservingDocument(null, new InvalidOperationException("authored host getter failure"));
        var fixtures = new List<(string Name, XmlNode? Node, string? Attribute)>();
        foreach (var name in new string?[] { "present", "empty", "missing", "p:flag", "flag", "", null }) fixtures.Add(("element/" + (name ?? "<null>"), element, name));
        foreach (var node in new (string Name, XmlNode? Node)[] { ("null", null), ("document", document), ("text", text), ("comment", comment), ("attribute", element.Attributes["present"]!), ("fragment", document.CreateDocumentFragment()) })
            foreach (var name in new string?[] { "present", null }) fixtures.Add((node.Name + "/" + (name ?? "<null>"), node.Node, name));
        fixtures.Add(("child/present", child, "child")); fixtures.Add(("child/missing", child, "missing"));
        fixtures.Add(("observing/present", observing, "present")); fixtures.Add(("observing/missing", observing, "missing")); fixtures.Add(("observing/null-name", observing, null));
        fixtures.Add(("observing/null-collection", nullGetter, "present")); fixtures.Add(("observing/throw", throwingGetter, "present"));
        Check("authored host fixture matrix exactly26", fixtures.Count == 26);
        foreach (var fixture in fixtures)
        {
            var observer = fixture.Node as ObservingDocument; if (observer != null) observer.GetterCalls = 0;
            var expected = Capture(() => fixture.Node == null ? null : fixture.Node.Attributes![fixture.Attribute!]); int expectedCalls = observer?.GetterCalls ?? 0;
            if (observer != null) observer.GetterCalls = 0;
            attempts++; var actual = Capture(() => (XmlAttribute?)method.Invoke(null, new object?[] { fixture.Node, fixture.Attribute })); int actualCalls = observer?.GetterCalls ?? 0;
            bool returnIdentity = ReferenceEquals(expected.Value, actual.Value), exceptionType = expected.Error?.GetType() == actual.Error?.GetType(), exceptionMessage = expected.Error?.Message == actual.Error?.Message, getterCalls = expectedCalls == actualCalls && (observer == null || actualCalls == 1);
            comparisons += 4; bool pass = returnIdentity && exceptionType && exceptionMessage && getterCalls;
            results.Add(new { name = fixture.Name, passed = pass, return_identity = returnIdentity, exception_type = actual.Error?.GetType().FullName, expected_exception_type = expected.Error?.GetType().FullName, exception_type_matches = exceptionType, exception_message_matches = exceptionMessage, expected_getter_calls = expectedCalls, actual_getter_calls = actualCalls, getter_calls_match = getterCalls });
            if (pass) cases++; else failures++; observedOverrides += actualCalls;
        }
        Check("all original unchanged whole-helper host cases pass", cases == 26 && attempts == 26 && failures == 0 && comparisons == 104 && observedOverrides == 5);
        Check("original assembly remains byte-exact after execution", assemblyHash == Hash(File.ReadAllBytes(Path.Combine(folder, "Assembly-CSharp.dll"))) && bodyHash == Hash(method.GetMethodBody()!.GetILAsByteArray()!));
    }
}
catch (Exception error) { fatal = error.ToString(); }
finally { loadContext.Unload(); }
string status = fatal != null ? "RECOVERED_XML_ATTRIBUTE_WHOLE_HELPER_HOST_BOUNDARY_FAILED" : execute ? "PASS_UNCHANGED_RECOVERED_XML_ATTRIBUTE_WHOLE_HELPER_AT_HOST_XML_BOUNDARY" : "REVIEW_ONLY_UNCHANGED_RECOVERED_XML_ATTRIBUTE_WHOLE_HELPER_READY";
var report = new { status, recovery_run = run, execute_requested = execute, checks = tests.Count, tests, attempts, cases, comparisons, failures, actual_virtual_override_calls = observedOverrides, original_method_invocations = attempts, method_metadata_token = $"0x{methodToken:X8}", assembly_sha256 = assemblyHash, complete_original_cil_sha256 = bodyHash, original_instructions = instructionCount, source_sha256 = FileHash("src/re/RecoveredXmlAttributeRuntimeProbe/Program.cs"), inspection_report_sha256 = inspectionHash, results, fatal,
    cil_modified = false, dynamic_clones = 0, tokens_remapped = 0, call_opcode_rewrites = 0, member_substitutions = 0, access_bypasses = 0, recovered_constructors_invoked = 0, recovered_type_initializer_absent_required = true, native_parity_proved = false, full_clean_decompile_ready = false,
    scope = "Unchanged complete original static XmlExtensions.TryGetAttribute invoked only when --execute is explicitly supplied, in an isolated collectible ALC. Original recovered type has no .cctor. Host System.Xml types and original exact virtual Attributes getter/direct collection indexer MethodInfos are framework-unified without replacements. Authored .NET XML inputs, nullable names, null Attributes and observing/throwing host getter overrides are compared with host node.Attributes[name] under the original null-node rule. Return object identity, exception type/message and observed getter counts are checked; no recovered constructor, whole game or native XML implementation is executed or claimed." };
string reportPath = Guard($"reports/recovered-xml-attribute-runtime-{run}" + (execute ? "" : "-review") + ".json"); File.WriteAllText(reportPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { status, checks = tests.Count, attempts, cases, comparisons, failures, fatal })); return fatal == null ? 0 : 2;

static Outcome Capture(Func<XmlAttribute?> action) { try { return new(action(), null); } catch (TargetInvocationException error) when (error.InnerException != null) { return new(null, error.InnerException); } catch (Exception error) { return new(null, error); } }
record Outcome(XmlAttribute? Value, Exception? Error);
sealed class ObservingDocument(XmlAttributeCollection? collection, Exception? error) : XmlDocument
{
    public int GetterCalls;
    public override XmlAttributeCollection? Attributes { get { GetterCalls++; if (error != null) throw error; return collection; } }
}
