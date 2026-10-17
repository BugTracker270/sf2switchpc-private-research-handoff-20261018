using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length != 2 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$")) throw new ArgumentException("Verified USB root and recovery run required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1];
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var path = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp-firstpass.dll");
var fixture = Guard("analysis/reconstruction/currency-reference/currency-fixtures-v2.jsonl");
int cases = 0, checks = 0, zeroKeys = 0, nonzeroKeys = 0;
string? fatal = null;
var failures = new List<object>(); var methods = new List<object>();
try
{
    using var nativeReport = JsonDocument.Parse(File.ReadAllText(Guard("reports/native-currency-codec.json")));
    if (nativeReport.RootElement.GetProperty("status").GetString() != "PASS_COMPILED_CURRENCY_INT_CODEC_VS_ORIGINAL_ARM64"
        || nativeReport.RootElement.GetProperty("fixture_sha256").GetString() != Hash(fixture)) throw new IOException("Original native fixture evidence differs");
    var assembly = Assembly.LoadFrom(path);
    var type = assembly.GetType("CodeStage.AntiCheat.ObscuredTypes.ObscuredInt", true)!;
    var key = type.GetField("cryptoKey", BindingFlags.NonPublic | BindingFlags.Static)!;
    if (!type.IsValueType || key.FieldType != typeof(int)) throw new InvalidDataException("Original metadata contracts differ");
    var operations = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(field => field.FieldType == typeof(OpCode))
        .Select(field => (OpCode)field.GetValue(null)!).ToDictionary(operation => unchecked((ushort)operation.Value));
    MethodInfo Select(string name)
    {
        var method = type.GetMethod(name, BindingFlags.Public | BindingFlags.Static, [typeof(int), typeof(int)])!;
        if (method.ReturnType != typeof(int)) throw new InvalidDataException("Unexpected codec return type");
        var body = method.GetMethodBody()!; var code = body.GetILAsByteArray()!;
        if (body.ExceptionHandlingClauses.Count != 0) throw new InvalidDataException("Unexpected exception region");
        OpCode previous = default;
        int initializerCalls = 0;
        for (int at = 0; at < code.Length;)
        {
            ushort value = code[at++]; if (value == 0xFE) value = (ushort)(0xFE00 | code[at++]);
            var operation = operations[value]; string op = operation.Name!;
            if (!(op.StartsWith("ldarg", StringComparison.Ordinal) || op.StartsWith("ldloc", StringComparison.Ordinal)
                || op.StartsWith("stloc", StringComparison.Ordinal) || op.StartsWith("ldc.i4", StringComparison.Ordinal)
                || operation == OpCodes.Ceq || operation == OpCodes.Xor || operation == OpCodes.Ret || operation == OpCodes.Nop
                || operation == OpCodes.Br || operation == OpCodes.Br_S || operation == OpCodes.Brtrue || operation == OpCodes.Brtrue_S
                || operation == OpCodes.Brfalse || operation == OpCodes.Brfalse_S || operation == OpCodes.Ldsfld
                || operation == OpCodes.Ldtoken || operation == OpCodes.Call))
                throw new InvalidDataException("Unexpected scalar codec instruction/helper: " + operation);
            if (operation == OpCodes.Ldtoken)
            {
                var owner = method.Module.ResolveType(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)));
                if (owner != type || at + 4 >= code.Length || code[at + 4] != unchecked((byte)OpCodes.Call.Value))
                    throw new InvalidDataException("Only the original codec class token immediately before RunClassConstructor is permitted");
            }
            if (operation == OpCodes.Call)
            {
                var target = method.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4))) as MethodInfo;
                if (previous != OpCodes.Ldtoken || target?.DeclaringType != typeof(System.Runtime.CompilerServices.RuntimeHelpers)
                    || target.Name != "RunClassConstructor" || !target.IsStatic || target.ReturnType != typeof(void)
                    || target.GetParameters().Length != 1 || target.GetParameters()[0].ParameterType != typeof(RuntimeTypeHandle))
                    throw new InvalidDataException("Only exact existing RunClassConstructor(RuntimeTypeHandle) may consume the codec class token");
                initializerCalls++;
            }
            if (operation == OpCodes.Ldsfld)
            {
                var field = method.Module.ResolveField(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)))!;
                if (field.Module != key.Module || field.MetadataToken != key.MetadataToken) throw new InvalidDataException("Unexpected static dependency");
            }
            at += operation.OperandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI or OperandType.InlineField or OperandType.InlineBrTarget or OperandType.InlineTok or OperandType.InlineMethod => 4,
                _ => throw new InvalidDataException("Unexpected scalar operand encoding")
            };
            previous = operation;
        }
        methods.Add(new { method = name, native_rva = name == "Encrypt" ? "0x7A8C20" : "0x7A8D70", bytes = code.Length,
            cil_sha256 = Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant(), body.MaxStackSize, locals = body.LocalVariables.Count,
            original_owner_class_constructor_calls = initializerCalls });
        return method;
    }
    var encrypt = Select("Encrypt"); var decrypt = Select("Decrypt");
    foreach (var line in File.ReadLines(fixture))
    {
        using var document = JsonDocument.Parse(line); var row = document.RootElement;
        int global = row.GetProperty("globalKey").GetInt32(), value = row.GetProperty("value").GetInt32(), explicitKey = row.GetProperty("explicitKey").GetInt32();
        uint expected = row.GetProperty("explicitResult").GetUInt32();
        key.SetValue(null, global); // Explicit initialized static-key boundary; original CLR cctor may execute first.
        uint encoded = unchecked((uint)(int)encrypt.Invoke(null, [value, explicitKey])!);
        uint decoded = unchecked((uint)(int)decrypt.Invoke(null, [value, explicitKey])!);
        bool unchanged = (int)key.GetValue(null)! == global;
        checks += 3;
        if (encoded != expected || decoded != expected || !unchanged) failures.Add(new { index = cases, encoded, decoded, expected, static_key_unchanged = unchanged });
        if (explicitKey == 0) zeroKeys++; else nonzeroKeys++;
        cases++;
    }
}
catch (Exception error) { fatal = error.GetType().FullName + ": " + error.Message; }
string status = fatal == null && cases > 0 && failures.Count == 0 && zeroKeys > 0 && nonzeroKeys > 0
    ? "PASS_ACTUAL_RECOVERED_SCALAR_CURRENCY_CODEC_VS_ORIGINAL_NATIVE" : "RECOVERY_EXECUTION_LIMITATION_CONFIRMED";
var report = new { status, recovery_run = run, cases, checks, zero_key_cases = zeroKeys, nonzero_key_cases = nonzeroKeys, failure_count = failures.Count,
    first_failures = failures.Take(8), fatal, methods, assembly_sha256 = Hash(path), fixture_sha256 = Hash(fixture),
    cil_or_source_edited = false, tokens_remapped = 0, dynamic_clones = 0,
    scope = "Calls the actual recovered static Encrypt(int,int)/Decrypt(int,int) CIL directly in .NET, with no source/IL edits, clones or helper substitutions. Exact original-owner ldtoken/RunClassConstructor(RuntimeTypeHandle) pairs execute normally; no arbitrary token or call is admitted. Uses exact original ARM64 fixture values and an explicit initialized cryptoKey input set through the original field; CLR type initialization may run before that input is set. Native initialization order is outside the arithmetic comparison. Checks zero-key fallback, explicit-key XOR and unchanged static key. No default-key overload, aggregate conversion, detector callback, whole currency/economy, original runtime or full source claim." };
File.WriteAllText(Guard($"reports/recovered-currency-scalars-{run}.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine($"{status}: {cases} cases / {checks} checks; {fatal}");
return status.StartsWith("PASS", StringComparison.Ordinal) ? 0 : 2;
