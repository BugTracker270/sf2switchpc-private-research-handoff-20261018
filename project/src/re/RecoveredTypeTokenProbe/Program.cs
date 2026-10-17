using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length != 2 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$")) throw new ArgumentException("USB root and recovery run required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1];
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? directory = new(Path.GetDirectoryName(path)!); directory != null; directory = directory.Parent)
        if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string assemblyPath = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp.dll");
string? fatal = null, fullBodyHash = null, prefixHash = null, actualType = null;
int typeFromHandleCalls = 0, checks = 0, expressionStart = 0;
try
{
    var assembly = Assembly.LoadFrom(assemblyPath);
    var getter = assembly.GetType("CocosAnimationUiSpriteRenderer", true)!.GetMethod("get_drawMode", BindingFlags.Public | BindingFlags.Instance)!;
    var body = getter.GetMethodBody()!;
    if (body.ExceptionHandlingClauses.Count != 0) throw new Exception("Unexpected exception region in selected prefix source");
    var code = body.GetILAsByteArray()!;
    fullBodyHash = Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant();
    var operations = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(OpCode))
        .Select(f => (OpCode)f.GetValue(null)!).ToDictionary(op => unchecked((ushort)op.Value));
    var decoded = new List<(int Start, int Operand, int End, OpCode Op)>();
    int end = 0;
    for (int at = 0; at < code.Length;)
    {
        int start = at;
        ushort value = code[at++];
        if (value == 0xfe) value = (ushort)(0xfe00 | code[at++]);
        var op = operations[value];
        int operand = at;
        at += op.OperandType switch
        {
            OperandType.InlineNone => 0,
            OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
            OperandType.InlineVar => 2,
            OperandType.InlineI8 or OperandType.InlineR => 8,
            OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)),
            _ => 4
        };
        decoded.Add((start, operand, at, op));
        if (op == OpCodes.Call && getter.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(operand, 4)))
            is MethodInfo { Name: "GetTypeFromHandle", DeclaringType: { } declaring } && declaring == typeof(Type))
        {
            typeFromHandleCalls++;
            end = at;
        }
    }
    if (typeFromHandleCalls is < 1 or > 2) throw new Exception("Expected one native contract and at most one erroneous synthesized conversion");
    var tokenLoads = decoded.Where(row => row.Start < end && row.Op == OpCodes.Ldtoken).ToArray();
    if (tokenLoads.Length != 1) throw new Exception("Expected one independent literal-type expression");
    expressionStart = tokenLoads[0].Start;
    var prefix = code.AsSpan(expressionStart, end - expressionStart).ToArray();
    prefixHash = Convert.ToHexString(SHA256.HashData(prefix)).ToLowerInvariant();
    var dynamic = new DynamicMethod("RecoveredTypeTokenPrefix", typeof(Type), Type.EmptyTypes, typeof(Program).Module, true);
    var info = dynamic.GetDynamicILInfo();
    var signature = SignatureHelper.GetLocalVarSigHelper();
    foreach (var local in body.LocalVariables) signature.AddArgument(local.LocalType, local.IsPinned);
    info.SetLocalSignature(signature.GetSignature());
    Type? expected = null;
    var assigned = new HashSet<int>();
    foreach (var original in decoded.Where(row => row.Start >= expressionStart && row.End <= end))
    {
        var row = (Start: original.Start - expressionStart, Operand: original.Operand - expressionStart,
            End: original.End - expressionStart, original.Op);
        var op = row.Op;
        if (op.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch
            || op.Name!.StartsWith("ldarg", StringComparison.Ordinal) || op.Name.StartsWith("starg", StringComparison.Ordinal)
            || op == OpCodes.Ldloca || op == OpCodes.Ldloca_S)
            throw new Exception("The selected literal expression is not independent straight-line CIL");
        if (op.Name.StartsWith("ldloc", StringComparison.Ordinal) || op.Name.StartsWith("stloc", StringComparison.Ordinal))
        {
            int slot = op.OperandType == OperandType.InlineNone ? int.Parse(op.Name[^1..])
                : op.OperandType == OperandType.ShortInlineVar ? prefix[row.Operand]
                : BinaryPrimitives.ReadUInt16LittleEndian(prefix.AsSpan(row.Operand, 2));
            if (op.Name.StartsWith("stloc", StringComparison.Ordinal)) assigned.Add(slot);
            else if (!assigned.Contains(slot)) throw new Exception("Literal expression reads a local assigned outside the slice");
        }
        if (op.OperandType is OperandType.InlineNone or OperandType.ShortInlineI or OperandType.ShortInlineVar
            or OperandType.InlineVar or OperandType.InlineI or OperandType.InlineI8 or OperandType.ShortInlineR or OperandType.InlineR) continue;
        int token = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(row.Operand, 4)), replacement;
        if (op == OpCodes.Ldtoken && op.OperandType == OperandType.InlineTok)
        {
            var type = getter.Module.ResolveType(token);
            if (type.FullName != "UnityEngine.SpriteDrawMode" || !type.IsEnum || (expected != null && type != expected))
                throw new Exception("Unexpected token type in selected prefix");
            expected = type;
            replacement = info.GetTokenFor(type.TypeHandle);
        }
        else if (op == OpCodes.Call && op.OperandType == OperandType.InlineMethod
            && getter.Module.ResolveMethod(token) is MethodInfo { Name: "GetTypeFromHandle", DeclaringType: { } declaring } method
            && declaring == typeof(Type) && method.GetParameters().Select(p => p.ParameterType).SequenceEqual(new[] { typeof(RuntimeTypeHandle) }))
            replacement = info.GetTokenFor(typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle))!.MethodHandle);
        else throw new Exception("Unexpected token/call; the rest of the game method must not execute: " + op);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(row.Operand, 4), replacement);
    }
    if (expected == null) throw new Exception("No original enum token recovered");
    info.SetCode(prefix.Concat(new byte[] { 0x2a }).ToArray(), body.MaxStackSize);
    var result = dynamic.CreateDelegate<Func<Type>>()();
    actualType = result.FullName;
    checks++;
    if (result != expected) throw new Exception("Recovered type token produced a different CLR type");
    checks++;
    if (typeFromHandleCalls != 1) throw new Exception("Double conversion survived the runtime gate");
}
catch (Exception ex) { fatal = ex.GetType().FullName + ": " + ex.Message; }
var report = new
{
    status = fatal == null && checks == 2 ? "PASS_RECOVERED_TYPE_HANDLE_TOKEN_CONTRACT" : "RECOVERED_TYPE_HANDLE_TOKEN_LIMITATION",
    recovery_run = run, type_from_handle_calls = typeFromHandleCalls, checks, fatal, actual_type = actualType,
    expression_start = expressionStart,
    full_body_il_sha256 = fullBodyHash, bounded_prefix_il_sha256 = prefixHash,
    assembly_sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assemblyPath))).ToLowerInvariant(),
    scope = "Execute only the actual recovered independent literal-type expression from its sole ldtoken through its final Type.GetTypeFromHandle call, with a ret appended. Original expression instructions and locals retained. Every local read must follow an assignment inside this straight-line slice; arguments, branches, field operations and other calls/tokens are rejected. Original enum token maps to that exact recovered enum; only the verified System.Type API token maps to the host BCL implementation of the same handle contract. Earlier control flow and the remaining unresolved getter are never executed. This is a CLR token/stack contract check, not original ARM64 execution, full getter validation or full source compilation."
};
var output = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
File.WriteAllText(Guard($"reports/recovered-type-handle-token-{run}.json"), output + "\n");
Console.WriteLine(output);
return report.status == "PASS_RECOVERED_TYPE_HANDLE_TOKEN_CONTRACT" ? 0 : 2;
