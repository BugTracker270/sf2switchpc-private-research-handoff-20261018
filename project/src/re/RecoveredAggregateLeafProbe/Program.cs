using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
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
var firstpass = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp-firstpass.dll");
var main = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp.dll");
var fixture = Guard("analysis/il2cpp/integer-aggregate-leaf-native-fixtures-v1.jsonl");
int cases = 0, checks = 0, fieldsRemapped = 0;
string? fatal = null;
var failures = new List<object>();
var bodies = new List<object>();
try
{
    _ = Assembly.LoadFrom(firstpass);
    var assembly = Assembly.LoadFrom(main);
    var owner = assembly.GetType("Nekki.SF2.Core.Utils.CurrencyStruct", true)!;
    var getter = owner.GetMethod("get_Count", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)!;
    var setter = owner.GetMethod("set_Count", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)!;
    var sourceField = owner.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance).Single(field => field.Name == "<Count>k__BackingField");
    var valueType = sourceField.FieldType;
    var sourceFields = valueType.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
    if (!valueType.IsValueType || sourceFields.Length != 4
        || !sourceFields.Select(field => field.Name).Order().SequenceEqual(new[] { "currentCryptoKey", "fakeValue", "hiddenValue", "inited" })
        || sourceFields.Single(field => field.Name == "inited").FieldType != typeof(bool)
        || sourceFields.Where(field => field.Name != "inited").Any(field => field.FieldType != typeof(int))) throw new InvalidDataException("Original recovered value field contracts differ");
    var opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(field => field.FieldType == typeof(OpCode))
        .Select(field => (OpCode)field.GetValue(null)!).ToDictionary(opcode => unchecked((ushort)opcode.Value));
    DynamicMethod Clone(MethodInfo source, bool isSetter)
    {
        var body = source.GetMethodBody() ?? throw new InvalidDataException("Missing recovered body");
        byte[] code = body.GetILAsByteArray()!;
        bodies.Add(new { method = source.Name, cil_sha256 = Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant(), bytes = code.Length,
            max_stack = body.MaxStackSize, locals = body.LocalVariables.Count, exception_regions = body.ExceptionHandlingClauses.Count });
        if (body.ExceptionHandlingClauses.Count != 0 || body.LocalVariables.Count != 0) throw new InvalidDataException("Whole-leaf body must have no exception regions or locals");
        var clone = new DynamicMethod("RecoveredAggregate_" + source.Name, isSetter ? typeof(void) : typeof(Value16),
            isSetter ? [typeof(Storage), typeof(Value16)] : [typeof(Storage)], typeof(Program).Module, true);
        var info = clone.GetDynamicILInfo();
        info.SetLocalSignature(SignatureHelper.GetLocalVarSigHelper().GetSignature());
        int at = 0, fieldOps = 0;
        var sequence = new List<OpCode>();
        while (at < code.Length)
        {
            ushort value = code[at++]; if (value == 0xFE) value = (ushort)(0xFE00 | code[at++]);
            var opcode = opcodes[value]; sequence.Add(opcode);
            if (opcode == OpCodes.Ldfld || opcode == OpCodes.Stfld)
            {
                int token = BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4));
                var resolved = source.Module.ResolveField(token)!;
                if (resolved.Module != sourceField.Module || resolved.MetadataToken != sourceField.MetadataToken
                    || opcode != (isSetter ? OpCodes.Stfld : OpCodes.Ldfld)) throw new InvalidDataException("Unexpected field operation");
                var target = typeof(Storage).GetField(nameof(Storage.Count))!;
                BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(at, 4), info.GetTokenFor(target.FieldHandle));
                at += 4; fieldOps++; fieldsRemapped++;
            }
            else if (opcode != OpCodes.Ldarg_0 && opcode != OpCodes.Ldarg_1 && opcode != OpCodes.Ret)
                throw new InvalidDataException("Unexpected whole-leaf opcode or helper: " + opcode);
        }
        OpCode[] expected = isSetter ? [OpCodes.Ldarg_0, OpCodes.Ldarg_1, OpCodes.Stfld, OpCodes.Ret] : [OpCodes.Ldarg_0, OpCodes.Ldfld, OpCodes.Ret];
        if (fieldOps != 1 || !sequence.SequenceEqual(expected)) throw new InvalidDataException("Exact original-derived whole-field copy sequence required");
        info.SetCode(code, body.MaxStackSize);
        return clone;
    }
    var read = Clone(getter, false).CreateDelegate<Func<Storage, Value16>>();
    var write = Clone(setter, true).CreateDelegate<Action<Storage, Value16>>();
    foreach (var line in File.ReadLines(fixture))
    {
        using var document = JsonDocument.Parse(line);
        var expected = document.RootElement.GetProperty("fields").EnumerateArray().Select(element => element.GetUInt32()).ToArray();
        var value = new Value16 { Key = unchecked((int)expected[0]), Hidden = unchecked((int)expected[1]), Fake = unchecked((int)expected[2]), Inited = expected[3] != 0 };
        var storage = new Storage();
        write(storage, value);
        uint[] stored = storage.Count.Fields(); checks += 4;
        var returned = read(storage).Fields(); checks += 4;
        bool sentinels = storage.Before == 0x123456789ABCDEF0UL && storage.After == 0xFEDCBA9876543210UL;
        checks += 2;
        if (!stored.SequenceEqual(expected) || !returned.SequenceEqual(expected) || !sentinels) failures.Add(new { index = cases, stored, returned, expected, sentinels });
        cases++;
    }
}
catch (Exception error) { fatal = error.GetType().FullName + ": " + error.Message; }
string status = fatal == null && cases > 0 && failures.Count == 0 ? "PASS_RECOVERED_16BYTE_FIELD_COPIES_VS_ORIGINAL_NATIVE" : "RECOVERY_EXECUTION_LIMITATION_CONFIRMED";
var report = new { status, recovery_run = run, cases, checks, fields_remapped = fieldsRemapped, failure_count = failures.Count, first_failures = failures.Take(8), fatal, bodies,
    assembly_sha256 = Hash(main), firstpass_sha256 = Hash(firstpass), fixture_sha256 = Hash(fixture),
    source_changes = false, cil_opcode_and_branch_bytes_changed = false,
    scope = "Retains actual complete recovered getter/setter CIL instruction bytes, changing only the sole field metadata token in each body to isolated storage with the same four declared value fields. Matches original ARM64 field values; native tail padding identity is expressly excluded. Helpers, calls, branches, locals and other instructions are rejected. No original runtime, class initialization, GC, null receiver, generic aggregate entry/call/return, codec, or complete source claim." };
File.WriteAllText(Guard($"reports/recovered-aggregate-leaves-{run}.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine($"{status}: {cases} cases / {checks} field checks; {fatal}");
return status.StartsWith("PASS", StringComparison.Ordinal) ? 0 : 2;

[StructLayout(LayoutKind.Explicit, Size = 16)]
struct Value16
{
    [FieldOffset(0)] public int Key;
    [FieldOffset(4)] public int Hidden;
    [FieldOffset(8)] public int Fake;
    [FieldOffset(12)] public bool Inited;
    public uint[] Fields() => [unchecked((uint)Key), unchecked((uint)Hidden), unchecked((uint)Fake), Inited ? 1u : 0u];
}
[StructLayout(LayoutKind.Sequential)]
sealed class Storage
{
    public ulong Before = 0x123456789ABCDEF0UL;
    public Value16 Count;
    public ulong After = 0xFEDCBA9876543210UL;
}
