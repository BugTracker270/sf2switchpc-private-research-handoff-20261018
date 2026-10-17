using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
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
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var checks = new List<object>(); var failures = new List<object>(); var calls = new List<object>();
int cases = 0, assertions = 0, constructorCalls = 0, bitConverterCalls = 0;
string? fatal = null, cilHash = null, fixtureHash = null;
int? nativeCases = null, nativeFailures = null, nativeGuestFunctionReplacements = null;
int fixtureCases = 0, singleByteValueCount = 0, validPositionCount = 0;
bool nativeEvidenceBound = false, fixtureCaseBinding = false;
var fixtureRows = new List<(string Id, byte[] Bytes, int Position, bool Expected, int After)>();
string assemblyPath = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp.dll");
string fixture = Guard("analysis/reconstruction/boolean-reader-reference/fixtures.jsonl");
string nativeReport = Guard("reports/native-boolean-reader-v33.json");
try
{
    using (var native = JsonDocument.Parse(File.ReadAllText(nativeReport)))
    {
        var evidence = native.RootElement;
        nativeCases = evidence.GetProperty("cases").GetInt32();
        nativeFailures = evidence.GetProperty("failures").GetInt32();
        nativeGuestFunctionReplacements = evidence.GetProperty("native_guest_function_replacements").GetInt32();
        if (evidence.GetProperty("status").GetString() != "PASS_ORIGINAL_BOOLEAN_READER_RETURN_AND_POSITION_AT_INITIALIZED_RUNTIME_BOUNDARY"
            || nativeCases != 811 || nativeFailures != 0 || nativeGuestFunctionReplacements != 0
            || !evidence.GetProperty("native_hooks_observe_only").GetBoolean()
            || !evidence.GetProperty("original_converter_call_executed_per_case").GetBoolean()
            || !evidence.GetProperty("all_256_single_byte_values").GetBoolean()
            || evidence.GetProperty("valid_positions_min").GetInt32() != 0
            || evidence.GetProperty("valid_positions_max").GetInt32() != 256
            || evidence.GetProperty("fixture_sha256").GetString() != Hash(fixture)
            || evidence.GetProperty("native_source_sha256").GetString() != Hash(Guard("analysis/nso/main-uncompressed.nso"))
            || !evidence.GetProperty("code_unmodified").GetBoolean()
            || evidence.GetProperty("readboolean_code_sha256").GetString() != "a2c22a6bcf2d17e31452dd9f67a08c42b7b246e10cf3db95f8e6cac2a1fef722"
            || evidence.GetProperty("toboolean_code_sha256").GetString() != "5380a7ce418e5ad7e7423ae1f3114e9cd752d23949c0effd91e0f46ba8d3423d")
            throw new InvalidDataException("Native complete-case, code, initialization-boundary or no-replacement evidence differs");
    }
    fixtureHash = Hash(fixture);
    var uniqueIds = new HashSet<string>(StringComparer.Ordinal);
    var singleByteValues = new HashSet<byte>();
    var validPositions = new HashSet<int>();
    foreach (string line in File.ReadLines(fixture))
    {
        using var doc = JsonDocument.Parse(line); var row = doc.RootElement;
        if (row.GetProperty("outcome").GetString() != "return")
            throw new InvalidDataException("The native valid-input witness must contain return cases only");
        string id = row.GetProperty("id").GetString()!;
        byte[] bytes = Convert.FromHexString(row.GetProperty("bytes_hex").GetString()!);
        int position = row.GetProperty("position_before").GetInt32();
        if (!uniqueIds.Add(id) || position < 0 || position >= bytes.Length)
            throw new InvalidDataException("Duplicate fixture identity or invalid native witness position");
        if (bytes.Length == 1 && position == 0) singleByteValues.Add(bytes[0]);
        validPositions.Add(position);
        fixtureRows.Add((id, bytes, position, row.GetProperty("returned_boolean").GetBoolean(), row.GetProperty("position_after").GetInt32()));
    }
    fixtureCases = fixtureRows.Count;
    singleByteValueCount = singleByteValues.Count;
    validPositionCount = validPositions.Count;
    if (fixtureCases != nativeCases || !singleByteValues.SetEquals(Enumerable.Range(0, 256).Select(i => (byte)i))
        || !validPositions.SetEquals(Enumerable.Range(0, 257)))
        throw new InvalidDataException("Fixture cases or complete byte/valid-position coverage differ from the native witness");
    nativeEvidenceBound = fixtureCaseBinding = true;
    checks.Add(new { name = "all 811 unchanged-native return cases, no guest replacements, all byte values and valid positions bound by hashes", passed = true });
    var assembly = Assembly.LoadFrom(assemblyPath);
    var type = assembly.GetType("BinaryReaderNekki", true)!;
    var method = type.GetMethod("ReadBoolean", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly, [])!;
    var bytesField = type.GetField("_bytes", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!;
    var positionField = type.GetField("<Position>k__BackingField", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!;
    if (method.IsStatic || method.ReturnType != typeof(bool) || bytesField.FieldType != typeof(byte[]) || positionField.FieldType != typeof(int))
        throw new InvalidDataException("Original reader metadata contract differs");
    var body = method.GetMethodBody()!; var code = body.GetILAsByteArray()!;
    if (body.ExceptionHandlingClauses.Count != 0) throw new InvalidDataException("Unexpected recovered exception region");
    cilHash = Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant();
    var opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(OpCode))
        .Select(f => (OpCode)f.GetValue(null)!).ToDictionary(o => unchecked((ushort)o.Value));
    OpCode previous = default;
    for (int at = 0; at < code.Length;)
    {
        int offset = at; ushort value = code[at++]; if (value == 0xFE) value = (ushort)(0xFE00 | code[at++]);
        var op = opcodes[value];
        bool ordinary = op.Name!.StartsWith("ldarg", StringComparison.Ordinal) || op.Name.StartsWith("ldloc", StringComparison.Ordinal)
            || op.Name.StartsWith("stloc", StringComparison.Ordinal) || op.Name.StartsWith("ldc.i4", StringComparison.Ordinal)
            || op == OpCodes.Nop || op == OpCodes.Ret || op == OpCodes.Add || op == OpCodes.And || op == OpCodes.Ceq
            || op == OpCodes.Conv_I4 || op == OpCodes.Conv_U4 || op == OpCodes.Br || op == OpCodes.Br_S
            || op == OpCodes.Brtrue || op == OpCodes.Brtrue_S || op == OpCodes.Brfalse || op == OpCodes.Brfalse_S;
        if (op == OpCodes.Ldfld || op == OpCodes.Stfld)
        {
            var field = method.Module.ResolveField(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)))!;
            if (field != bytesField && field != positionField || op == OpCodes.Stfld && field != positionField)
                throw new InvalidDataException("Unexpected reader field effect");
        }
        else if (op == OpCodes.Ldtoken)
        {
            var target = method.Module.ResolveType(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)));
            if (target != typeof(BitConverter) || at + 4 >= code.Length || code[at + 4] != unchecked((byte)OpCodes.Call.Value))
                throw new InvalidDataException("Only the exact BitConverter class token/constructor request is permitted");
        }
        else if (op == OpCodes.Call)
        {
            var target = method.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4))) as MethodInfo;
            bool constructor = previous == OpCodes.Ldtoken && target?.DeclaringType == typeof(RuntimeHelpers)
                && target.Name == nameof(RuntimeHelpers.RunClassConstructor) && target.IsStatic && target.ReturnType == typeof(void)
                && target.GetParameters().Select(p => p.ParameterType).SequenceEqual([typeof(RuntimeTypeHandle)]);
            bool conversion = target?.DeclaringType == typeof(BitConverter) && target.Name == nameof(BitConverter.ToBoolean)
                && target.IsStatic && target.ReturnType == typeof(bool)
                && target.GetParameters().Select(p => p.ParameterType).SequenceEqual([typeof(byte[]), typeof(int)]);
            if (!constructor && !conversion) throw new InvalidDataException("Unexpected reader call or diagnostic helper: " + target);
            if (constructor) constructorCalls++; else bitConverterCalls++;
            calls.Add(new { il_offset = offset, declaring_type = target!.DeclaringType!.FullName, target.Name });
        }
        else if (!ordinary) throw new InvalidDataException("Unexpected reader instruction: " + op);
        at += op.OperandType switch
        {
            OperandType.InlineNone => 0,
            OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
            OperandType.InlineVar => 2,
            OperandType.InlineI or OperandType.InlineField or OperandType.InlineMethod or OperandType.InlineTok or OperandType.InlineBrTarget => 4,
            _ => throw new InvalidDataException("Unsupported reader operand encoding")
        };
        if (at > code.Length) throw new InvalidDataException("Truncated reader CIL");
        previous = op;
    }
    if (constructorCalls != 1 || bitConverterCalls != 1) throw new InvalidDataException("Exact reader constructor/conversion call counts differ");
    checks.Add(new { name = "unchanged recovered method with exact two managed calls and original field effects", passed = true });
    foreach (var row in fixtureRows)
    {
        byte[] bytes = row.Bytes.ToArray(); byte[] before = bytes.ToArray();
        int position = row.Position;
        object instance = RuntimeHelpers.GetUninitializedObject(type);
        bytesField.SetValue(instance, bytes); positionField.SetValue(instance, position);
        bool actual = (bool)method.Invoke(instance, null)!;
        int after = (int)positionField.GetValue(instance)!;
        bool passed = actual == row.Expected && after == row.After
            && bytes.AsSpan().SequenceEqual(before) && ReferenceEquals(bytesField.GetValue(instance), bytes);
        assertions += 4; cases++;
        if (!passed) failures.Add(new { id = row.Id, actual, position_after = after });
    }
    if (cases != nativeCases || cases != 811) throw new InvalidDataException("Actual invocation count does not equal all native witness cases");
}
catch (Exception error) { fatal = error.ToString(); }
string status = fatal == null && nativeEvidenceBound && fixtureCaseBinding && cases == nativeCases && cases == 811 && failures.Count == 0 ? "PASS_ACTUAL_RECOVERED_BOOLEAN_READER_VS_ORIGINAL_NATIVE" : "RECOVERY_EXECUTION_LIMITATION_CONFIRMED";
var report = new { status, recovery_run = run, cases, checks = assertions, structural_checks = checks, failure_count = failures.Count,
    first_failures = failures.Take(8), fatal, calls, original_constructor_calls = constructorCalls, original_conversion_calls = bitConverterCalls,
    assembly_sha256 = File.Exists(assemblyPath) ? Hash(assemblyPath) : null, body_il_sha256 = cilHash, fixture_sha256 = fixtureHash,
    native_report_sha256 = File.Exists(nativeReport) ? Hash(nativeReport) : null,
    native_case_binding = new { native_cases = nativeCases, native_failures = nativeFailures, native_guest_function_replacements = nativeGuestFunctionReplacements,
        fixture_cases = fixtureCases, native_evidence_bound = nativeEvidenceBound, fixture_case_binding = fixtureCaseBinding,
        actual_executed_cases = cases, all_native_cases_executed = nativeEvidenceBound && fixtureCaseBinding && cases == nativeCases && cases == 811,
        single_byte_value_count = singleByteValueCount, valid_position_count = validPositionCount, valid_positions_min = 0, valid_positions_max = 256 },
    probe_source_sha256 = Hash(Guard("src/re/RecoveredBooleanReaderProbe/Program.cs")),
    cil_or_source_edited = false, tokens_remapped = 0, dynamic_clones = 0,
    scope = "Direct execution of the unchanged recovered BinaryReaderNekki.ReadBoolean method on its actual recovered type. Explicit caller boundary allocates the type without invoking its instance constructor and supplies its two original input fields. Real CLR BitConverter.ToBoolean and exact RunClassConstructor(BitConverter) calls remain; no original static constructor is stubbed or suppressed. All 811 native return cases, position changes, unchanged array bytes and array identity must agree. Native/runtime initialization boundaries and exceptional cases retain the native report's separate limits. No whole-reader constructor, serialization system, startup, complete source or portable game claim." };
File.WriteAllText(Guard($"reports/recovered-boolean-reader-{run}.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine($"{status}: {cases} cases / {assertions} checks; {fatal}");
return status.StartsWith("PASS", StringComparison.Ordinal) ? 0 : 2;
