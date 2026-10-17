using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length != 2 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$")) throw new ArgumentException("USB root and immutable run required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1];
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB");
    for (DirectoryInfo? dir = new(Path.GetDirectoryName(path)!); dir != null; dir = dir.Parent)
        if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point");
    return path;
}
string Hash(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
string folder = Guard($"analysis/il2cpp/cpp2il-recovery-{run}"), path = Path.Combine(folder, "Assembly-CSharp-firstpass.dll");
var context = new AssemblyLoadContext("value_this_diagnosis_" + run, true);
context.Resolving += (c, n) => File.Exists(Path.Combine(folder, n.Name + ".dll")) ? c.LoadFromAssemblyPath(Path.Combine(folder, n.Name + ".dll")) : null;
string? fatal = null, returnedException = null; bool returned = false, parity = false, getterProof = false;
int attempted = 0; var privateRows = new List<object>(); var publicCalls = new List<object>();
string? ilHash = null, getterHash = null; string assemblyHash = Hash(File.ReadAllBytes(path));
try
{
    var assembly = context.LoadFromAssemblyPath(path);
    var type = assembly.GetType("CodeStage.AntiCheat.ObscuredTypes.ObscuredInt", true)!;
    var detector = assembly.GetType("CodeStage.AntiCheat.Detectors.ObscuredCheatingDetector", true)!;
    var field = detector.GetField("<Instance>k__BackingField", BindingFlags.Static | BindingFlags.NonPublic)!;
    var getter = detector.GetProperty("Instance", BindingFlags.Static | BindingFlags.Public)!.GetMethod!;
    var method = type.GetMethod("InternalDecrypt", BindingFlags.Instance | BindingFlags.NonPublic)!;
    byte[] bytes = method.GetMethodBody()!.GetILAsByteArray()!, getterBytes = getter.GetMethodBody()!.GetILAsByteArray()!;
    ilHash = Hash(bytes); getterHash = Hash(getterBytes);
    // This is the independently validated exact br/ldsfld/ret getter, with no
    // owner .cctor. Do not generalize to arbitrary getters or strip diagnostics.
    if (detector.TypeInitializer != null || getterHash != "e2fc24869b8d39bb20cf308dda7ffe9c838bfb5cca2ea6af9a92b3d391c8c0fb"
        || getterBytes.Length != 11 || getterBytes[0] != 0x38 || BinaryPrimitives.ReadInt32LittleEndian(getterBytes.AsSpan(1, 4)) != 0
        || getterBytes[5] != 0x7E || getterBytes[10] != 0x2A
        || getter.Module.ResolveField(BinaryPrimitives.ReadInt32LittleEndian(getterBytes.AsSpan(6, 4))) != field)
        throw new InvalidDataException("Exact original pure getter/no-cctor boundary differs");
    getterProof = true;
    var opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(OpCode))
        .Select(f => (OpCode)f.GetValue(null)!).ToDictionary(o => unchecked((ushort)o.Value));
    for (int at = 0; at < bytes.Length;)
    {
        int offset = at; ushort value = bytes[at++]; if (value == 0xFE) value = (ushort)(0xFE00 | bytes[at++]);
        var op = opcodes[value]; int operandAt = at;
        int width = op.OperandType switch { OperandType.InlineNone => 0, OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
            OperandType.InlineVar => 2, OperandType.InlineI8 or OperandType.InlineR => 8,
            OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(at, 4)), _ => 4 };
        at += width; if (at > bytes.Length) throw new InvalidDataException("Truncated CIL");
        int operand = width == 4 ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(operandAt, 4)) : width == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(operandAt, 2)) : width == 1 ? bytes[operandAt] : 0;
        var member = op.OperandType is OperandType.InlineMethod or OperandType.InlineField or OperandType.InlineType or OperandType.InlineTok ? method.Module.ResolveMember(operand) : null;
        string? text = op.OperandType == OperandType.InlineString ? method.Module.ResolveString(operand) : member?.ToString();
        privateRows.Add(new { offset, end = at, opcode = op.Name, operand, text, member_owner = member?.DeclaringType?.FullName });
        if (member is MethodInfo call) publicCalls.Add(new { offset, opcode = op.Name, name = call.Name, owner = call.DeclaringType?.FullName, return_type = call.ReturnType.FullName });
    }
    string fixturePath = Guard("analysis/reconstruction/currency-reference/currency-fixtures-v2.jsonl");
    using var native = JsonDocument.Parse(File.ReadAllText(Guard("reports/native-currency-codec.json")));
    if (native.RootElement.GetProperty("fixture_sha256").GetString() != Hash(File.ReadAllBytes(fixturePath))) throw new InvalidDataException("Native fixture changed");
    JsonElement fixture = default;
    foreach (string line in File.ReadLines(fixturePath)) { using var doc = JsonDocument.Parse(line); if (doc.RootElement.GetProperty("mode").GetInt32() == 0) { fixture = doc.RootElement.Clone(); break; } }
    if (fixture.ValueKind == JsonValueKind.Undefined) throw new InvalidDataException("No original absent-detector fixture");
    uint[] Parts(JsonElement words) { ulong[] data = words.EnumerateArray().Select(i => i.GetUInt64()).ToArray(); return [(uint)data[0], (uint)(data[0] >> 32), (uint)data[1], (uint)((data[1] >> 32) & 255)]; }
    var input = Parts(fixture.GetProperty("instanceWords")); var expected = Parts(fixture.GetProperty("internalAfter"));
    var fields = new[] { "currentCryptoKey", "hiddenValue", "fakeValue", "inited" }.Select(n => type.GetField(n, BindingFlags.NonPublic | BindingFlags.Instance)!).ToArray();
    var key = type.GetField("cryptoKey", BindingFlags.NonPublic | BindingFlags.Static)!; var savedDetector = field.GetValue(null); var savedKey = key.GetValue(null);
    try
    {
        field.SetValue(null, null); if (getter.Invoke(null, null) != null || field.GetValue(null) != null) throw new InvalidDataException("Explicit null boundary not retained");
        int global = fixture.GetProperty("globalKey").GetInt32(); key.SetValue(null, global);
        object value = Activator.CreateInstance(type)!;
        for (int i = 0; i < 3; i++) fields[i].SetValue(value, unchecked((int)input[i])); fields[3].SetValue(value, input[3] != 0);
        attempted++;
        try
        {
            uint actual = unchecked((uint)(int)method.Invoke(value, null)!); returned = true;
            uint[] state = [unchecked((uint)(int)fields[0].GetValue(value)!), unchecked((uint)(int)fields[1].GetValue(value)!), unchecked((uint)(int)fields[2].GetValue(value)!), (bool)fields[3].GetValue(value)! ? 1u : 0u];
            parity = actual == fixture.GetProperty("internalResult").GetUInt32() && state.SequenceEqual(expected) && (int)key.GetValue(null)! == global;
        }
        catch (Exception error)
        {
            var chain = new List<string>(); for (Exception? item = error; item != null; item = item.InnerException) chain.Add(item.GetType().FullName + ": " + item.Message);
            returnedException = string.Join(" -> ", chain);
        }
    }
    finally { field.SetValue(null, savedDetector); key.SetValue(null, savedKey); }
    if (Hash(method.GetMethodBody()!.GetILAsByteArray()!) != ilHash || Hash(File.ReadAllBytes(path)) != assemblyHash) throw new InvalidDataException("Original CIL/DLL changed during diagnosis");
}
catch (Exception error) { fatal = error.ToString(); }
string privatePath = Guard($"analysis/reconstruction/value-this-regression-v36/{run}-cil.json"); Directory.CreateDirectory(Path.GetDirectoryName(privatePath)!);
File.WriteAllText(privatePath, JsonSerializer.Serialize(privateRows, new JsonSerializerOptions { WriteIndented = true }) + "\n");
var output = new { status = "DIAGNOSIS_ONLY_ACTUAL_VALUE_THIS_CLR_IMPORT_RESULT", recovery_run = run, exact_pure_getter_no_cctor_verified = getterProof,
    diagnostic_invocations_attempted = attempted, diagnostic_invocations_returned = returned ? 1 : 0, diagnostic_return_matches_one_native_fixture = parity,
    invocation_exception = returnedException, fatal, accepted_regression_cases = 0, calls = publicCalls,
    assembly_sha256 = assemblyHash, cil_sha256 = ilHash, getter_cil_sha256 = getterHash, private_cil_path = Path.GetRelativePath(root, privatePath),
    private_cil_sha256 = Hash(File.ReadAllBytes(privatePath)), probe_source_sha256 = Hash(File.ReadAllBytes(Guard("src/re/ValueThisRegressionDiagnosisProbe/Program.cs"))),
    existing_regression_modified = false, cil_or_source_edited = false, tokens_remapped = 0, dynamic_clones = 0,
    scope = "Diagnosis only. Exact independently verified no-cctor static getter is supplied null, crypto key and original struct fields are supplied from one absent-detector native fixture. The unchanged private method is invoked to distinguish CLR import rejection from an overbroad syntactic reachability gate. Existing regression gates remain unchanged, and zero cases count as acceptance. Actual diagnostics and other branches are never rewritten or bypassed in recovered code." };
File.WriteAllText(Guard($"reports/value-this-clr-diagnosis-{run}.json"), JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { output.status, attempted, returned, parity, returnedException, fatal }));
context.Unload(); return fatal == null ? 0 : 2;
