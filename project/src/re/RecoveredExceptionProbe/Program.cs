using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length != 2 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$")) throw new ArgumentException("Verified USB root and recovery run required");
var root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
var run = args[1];
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
var path = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp-firstpass.dll");
string? fatal = null;
var slices = new List<object>();
int cases = 0, checks = 0, selected = 0;
string? bodyHash = null;
try
{
    var assembly = Assembly.LoadFrom(path);
    var type = assembly.GetType("AuthenticationSample", true)!;
    var method = type.GetMethod("Start", BindingFlags.Instance | BindingFlags.NonPublic)!;
    var body = method.GetMethodBody()!;
    if (body.ExceptionHandlingClauses.Count != 0) throw new Exception("Unexpected exception region");
    var code = body.GetILAsByteArray()!;
    bodyHash = Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant();
    var ops = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(OpCode))
        .Select(f => (OpCode)f.GetValue(null)!).ToDictionary(op => unchecked((ushort)op.Value));
    for (int at = 0; at < code.Length;)
    {
        int start = at;
        ushort value = code[at++]; if (value == 0xfe) value = (ushort)(0xfe00 | code[at++]);
        var op = ops[value]; int operand = at;
        at += op.OperandType switch
        {
            OperandType.InlineNone => 0,
            OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
            OperandType.InlineVar => 2,
            OperandType.InlineI8 or OperandType.InlineR => 8,
            OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)),
            _ => 4
        };
        if (op != OpCodes.Newobj || method.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(operand, 4))) is not ConstructorInfo ctor
            || ctor.DeclaringType != typeof(ArrayTypeMismatchException)) continue;
        if (ctor.GetParameters().Length != 0 || at - start != 5) throw new Exception("Factory constructor contract differs");
        selected++;
        // The actual recovered instruction is isolated without rewriting its
        // operation. Only its module token is rebound; ret delimits this slice.
        var slice = code.AsSpan(start, at - start).ToArray();
        var originalHash = Convert.ToHexString(SHA256.HashData(slice)).ToLowerInvariant();
        var dm = new DynamicMethod("RecoveredExceptionFactorySlice", typeof(Exception), Type.EmptyTypes, typeof(Program).Module, true);
        var info = dm.GetDynamicILInfo();
        info.SetLocalSignature(SignatureHelper.GetLocalVarSigHelper().GetSignature());
        BinaryPrimitives.WriteInt32LittleEndian(slice.AsSpan(1, 4), info.GetTokenFor(ctor.MethodHandle));
        info.SetCode(slice.Concat(new byte[] { 0x2a }).ToArray(), 1);
        var invoke = dm.CreateDelegate<Func<Exception>>();
        Exception? previous = null;
        var expected = new ArrayTypeMismatchException();
        for (int i = 0; i < 32; i++)
        {
            var actual = invoke();
            checks += 6;
            if (actual.GetType() != typeof(ArrayTypeMismatchException) || actual.HResult != expected.HResult
                || actual.Message != expected.Message || actual.InnerException != null || actual.StackTrace != null
                || ReferenceEquals(previous, actual)) throw new Exception("Recovered CLR exception constructor initialization differs");
            previous = actual; cases++;
        }
        slices.Add(new { original_il_offset = start, original_il_sha256 = originalHash, exact_type = ctor.DeclaringType.FullName,
            constructor = ".ctor()", cases = 32, checks = 192 });
    }
    if (selected != 7) throw new Exception($"Expected seven recovered factory constructors; observed {selected}");
}
catch (Exception ex) { fatal = ex.GetType().FullName + ": " + ex.Message; }
var report = new
{
    status = fatal == null ? "PASS_ACTUAL_RECOVERED_FACTORY_CONSTRUCTORS_AT_CLR_BOUNDARY" : "RECOVERED_FACTORY_CONSTRUCTOR_LIMITATION",
    recovery_run = run, cases, checks, selected_constructors = selected, fatal, original_caller_il_sha256 = bodyHash, slices,
    assembly_sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant(),
    scope = "Seven actual recovered parameterless ArrayTypeMismatchException newobj instructions in AuthenticationSample.Start, each isolated with ret appended and exact constructor token rebound to the host CLR contract. Checks exact type, constructor HResult/Message, null InnerException/StackTrace and fresh identity. No source edits, gameplay/Unity code or original ARM64 constructor bodies execute; no assertion of original exception-message localization, GC or full caller parity. A source error disappearing alone does not pass this probe."
};
var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
File.WriteAllText(Guard($"reports/recovered-exception-factory-{run}.json"), json + "\n");
Console.WriteLine(json);
return fatal == null ? 0 : 2;
