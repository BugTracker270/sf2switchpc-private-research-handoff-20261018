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
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string assemblyPath = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp.dll");
string? fatal = null, bodyHash = null, sliceHash = null;
int cases = 0, checks = 0, rawAllocations = 0, directConstructors = 0, newobjConstructors = 0;
try
{
    var assembly = Assembly.LoadFrom(assemblyPath);
    var type = assembly.GetType("BackKeyManager", true)!;
    var field = type.GetField("_backKeyListeners", BindingFlags.NonPublic | BindingFlags.Instance)!;
    var listType = field.FieldType;
    if (!listType.IsConstructedGenericType || listType.GetGenericTypeDefinition() != typeof(List<>))
        throw new Exception("Expected exact recovered field instantiation of the host CLR List<T> contract");
    var constructor = type.GetConstructor(Type.EmptyTypes)!;
    var body = constructor.GetMethodBody()!;
    if (body.ExceptionHandlingClauses.Count != 0) throw new Exception("Unexpected exception region");
    var code = body.GetILAsByteArray()!;
    bodyHash = Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant();
    var ops = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(OpCode))
        .Select(f => (OpCode)f.GetValue(null)!).ToDictionary(op => unchecked((ushort)op.Value));
    var decoded = new List<(int Start, int Operand, int End, OpCode Op)>();
    int end = 0;
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
        decoded.Add((start, operand, at, op));
        if (op == OpCodes.Stfld && constructor.Module.ResolveField(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(operand, 4))) == field)
        {
            if (end != 0) throw new Exception("Multiple selected field stores");
            end = at;
        }
    }
    if (end == 0) throw new Exception("No recovered list-field store");
    var starts = decoded.Where(row => row.End <= end &&
        ((row.Op == OpCodes.Ldtoken && constructor.Module.ResolveType(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(row.Operand, 4))) == listType)
         || (row.Op == OpCodes.Newobj && constructor.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(row.Operand, 4))) is ConstructorInfo c && c.DeclaringType == listType))).ToArray();
    if (starts.Length != 1) throw new Exception("Expected one isolated allocation/construction expression");
    int begin = starts[0].Start;
    var slice = code.AsSpan(begin, end - begin).ToArray();
    sliceHash = Convert.ToHexString(SHA256.HashData(slice)).ToLowerInvariant();
    var module = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("IsolatedConstructorStorage"), AssemblyBuilderAccess.Run).DefineDynamicModule("Storage");
    var builder = module.DefineType("Storage", TypeAttributes.Public | TypeAttributes.Class);
    builder.DefineDefaultConstructor(MethodAttributes.Public);
    builder.DefineField("Listeners", listType, FieldAttributes.Public);
    var storageType = builder.CreateType()!;
    var storageField = storageType.GetField("Listeners")!;
    var dynamic = new DynamicMethod("RecoveredConstructorSlice", typeof(void), [storageType], typeof(Program).Module, true);
    var info = dynamic.GetDynamicILInfo();
    var signature = SignatureHelper.GetLocalVarSigHelper();
    foreach (var local in body.LocalVariables) signature.AddArgument(local.LocalType == type ? storageType : local.LocalType, local.IsPinned);
    info.SetLocalSignature(signature.GetSignature());
    var assigned = new HashSet<int>();
    foreach (var original in decoded.Where(row => row.Start >= begin && row.End <= end))
    {
        var row = (Start: original.Start - begin, Operand: original.Operand - begin, End: original.End - begin, original.Op);
        var op = row.Op;
        if (op.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch || op.Name!.StartsWith("starg", StringComparison.Ordinal)
            || op == OpCodes.Ldloca || op == OpCodes.Ldloca_S)
            throw new Exception("Constructor slice is not independent straight-line CIL");
        if (op.Name.StartsWith("ldarg", StringComparison.Ordinal))
        {
            int argument = op.OperandType == OperandType.InlineNone ? int.Parse(op.Name[^1..])
                : op.OperandType == OperandType.ShortInlineVar ? slice[row.Operand]
                : BinaryPrimitives.ReadUInt16LittleEndian(slice.AsSpan(row.Operand, 2));
            if (argument != 0) throw new Exception("Unexpected constructor argument");
        }
        if (op.Name.StartsWith("ldloc", StringComparison.Ordinal) || op.Name.StartsWith("stloc", StringComparison.Ordinal))
        {
            int slot = op.OperandType == OperandType.InlineNone ? int.Parse(op.Name[^1..])
                : op.OperandType == OperandType.ShortInlineVar ? slice[row.Operand]
                : BinaryPrimitives.ReadUInt16LittleEndian(slice.AsSpan(row.Operand, 2));
            if (op.Name.StartsWith("stloc", StringComparison.Ordinal)) assigned.Add(slot);
            else if (!assigned.Contains(slot)) throw new Exception("Slice depends on a local assigned before its boundary");
        }
        if (op.OperandType is OperandType.InlineNone or OperandType.ShortInlineI or OperandType.ShortInlineVar
            or OperandType.InlineVar or OperandType.InlineI or OperandType.InlineI8 or OperandType.ShortInlineR or OperandType.InlineR) continue;
        int token = BinaryPrimitives.ReadInt32LittleEndian(slice.AsSpan(row.Operand, 4)), replacement;
        if ((op == OpCodes.Ldtoken || op == OpCodes.Castclass) && constructor.Module.ResolveType(token) == listType)
            replacement = info.GetTokenFor(listType.TypeHandle);
        else if (op == OpCodes.Stfld && constructor.Module.ResolveField(token) == field)
            replacement = info.GetTokenFor(storageField.FieldHandle);
        else if (op.OperandType == OperandType.InlineMethod && constructor.Module.ResolveMethod(token) is ConstructorInfo ctor
            && ctor.DeclaringType == listType && ctor.GetParameters().Length == 0 && op is var ctorOp && (ctorOp == OpCodes.Call || ctorOp == OpCodes.Newobj))
        {
            replacement = info.GetTokenFor(ctor.MethodHandle, listType.TypeHandle);
            if (op == OpCodes.Newobj) newobjConstructors++; else directConstructors++;
        }
        else if (op == OpCodes.Call && constructor.Module.ResolveMethod(token) is MethodInfo method
            && method.DeclaringType == typeof(Type) && method.Name == "GetTypeFromHandle")
            replacement = info.GetTokenFor(typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle))!.MethodHandle);
        else if (op == OpCodes.Call && constructor.Module.ResolveMethod(token) is MethodInfo allocator
            && allocator.DeclaringType?.FullName == "System.Runtime.Serialization.FormatterServices" && allocator.Name == "GetUninitializedObject")
        {
#pragma warning disable SYSLIB0050
            if (allocator.DeclaringType != typeof(System.Runtime.Serialization.FormatterServices)
                || !allocator.GetParameters().Select(p => p.ParameterType).SequenceEqual(new[] { typeof(Type) }))
#pragma warning restore SYSLIB0050
                throw new Exception("Unexpected allocator contract");
            replacement = info.GetTokenFor(allocator.MethodHandle); rawAllocations++;
        }
        else throw new Exception("Unapproved token/call in constructor slice: " + op);
        BinaryPrimitives.WriteInt32LittleEndian(slice.AsSpan(row.Operand, 4), replacement);
    }
    if (directConstructors + newobjConstructors != 1 || rawAllocations != directConstructors)
        throw new Exception("Unexpected allocation/constructor count");
    info.SetCode(slice.Concat(new byte[] { 0x2a }).ToArray(), body.MaxStackSize);
    var action = dynamic.CreateDelegate(typeof(Action<>).MakeGenericType(storageType));
    for (int i = 0; i < 32; i++)
    {
        var storage = Activator.CreateInstance(storageType)!;
        action.DynamicInvoke(storage);
        var value = storageField.GetValue(storage);
        checks += 4;
        if (value == null || value.GetType() != listType || (int)listType.GetProperty("Count")!.GetValue(value)! != 0
            || (int)listType.GetProperty("Capacity")!.GetValue(value)! != 0) throw new Exception("Recovered list construction/storage differs");
        cases++;
    }
}
catch (Exception ex) { fatal = ex.GetType().FullName + ": " + ex.Message; }
var report = new
{
    status = fatal == null && cases == 32 ? "PASS_RECOVERED_CONSTRUCTION_AT_CLR_LIST_BOUNDARY" : "RECOVERED_CONSTRUCTION_LIMITATION",
    recovery_run = run, cases, checks, raw_allocation_calls = rawAllocations, direct_constructor_calls = directConstructors,
    newobj_constructors = newobjConstructors, fatal, original_body_il_sha256 = bodyHash, slice_il_sha256 = sliceHash,
    assembly_sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assemblyPath))).ToLowerInvariant(),
    scope = "Actual recovered allocation/constructor/field-store expression only, retaining its operations and local assignments; ret appended before the Unity base-constructor boundary. The receiver/one field map to isolated dynamic storage with the exact original closed List<BackKeyController> CLR type retained. No Game/Unity function is executed. List constructor and reflection allocation use the host CLR standard contracts, with exactly one constructor instruction required. Checks field non-null/exact type/empty Count/empty Capacity across 32 fresh storage objects. Original ARM64, Nintendo allocation/GC, Unity base initialization, exceptions and complete constructor/source correctness remain unverified."
};
var output = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
File.WriteAllText(Guard($"reports/recovered-constructor-{run}.json"), output + "\n"); Console.WriteLine(output);
return report.status == "PASS_RECOVERED_CONSTRUCTION_AT_CLR_LIST_BOUNDARY" ? 0 : 2;
