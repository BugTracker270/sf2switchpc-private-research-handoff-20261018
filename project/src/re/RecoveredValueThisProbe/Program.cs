using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;

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
var assemblyPath = Guard($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp-firstpass.dll");
var fixturePath = Guard("analysis/reconstruction/currency-reference/currency-fixtures-v2.jsonl");
int cases = 0, checks = 0, lazy = 0, initialized = 0, unreachableHelpers = 0;
int boundaryChecks = 0;
bool exactNullBoundaryProof = false;
bool diagnosticTokenRelocationVerified = false;
int diagnosticTokensRelocated = 0;
string? getterBodyHash = null;
var scopeControls = new List<object>();
var scopeExcludedHelpers = new List<object>();
string? fatal = null, bodyHash = null;
var failures = new List<object>(); var blockedCalls = new List<object>();
try
{
    using var nativeReport = JsonDocument.Parse(File.ReadAllText(Guard("reports/native-currency-codec.json")));
    if (nativeReport.RootElement.GetProperty("fixture_sha256").GetString() != Hash(fixturePath)
        || nativeReport.RootElement.GetProperty("status").GetString() != "PASS_COMPILED_CURRENCY_INT_CODEC_VS_ORIGINAL_ARM64") throw new IOException("Native fixture evidence differs");
    var assembly = Assembly.LoadFrom(assemblyPath);
    var type = assembly.GetType("CodeStage.AntiCheat.ObscuredTypes.ObscuredInt", true)!;
    var method = type.GetMethod("InternalDecrypt", BindingFlags.NonPublic | BindingFlags.Instance)!;
    var body = method.GetMethodBody()!; var code = body.GetILAsByteArray()!;
    bodyHash = Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant();
    if (!type.IsValueType || method.ReturnType != typeof(int) || method.GetParameters().Length != 0 || body.ExceptionHandlingClauses.Count != 0) throw new InvalidDataException("Unexpected original method contract/EH");
    var opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(field => field.FieldType == typeof(OpCode))
        .Select(field => (OpCode)field.GetValue(null)!).ToDictionary(opcode => unchecked((ushort)opcode.Value));
    var decoded = new Dictionary<int, (OpCode Op, int End, int Operand, int[] Targets)>();
    for (int at = 0; at < code.Length;)
    {
        int start = at; ushort value = code[at++]; if (value == 0xFE) value = (ushort)(0xFE00 | code[at++]);
        var opcode = opcodes[value]; int operand = at;
        int width = opcode.OperandType switch
        {
            OperandType.InlineNone => 0,
            OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
            OperandType.InlineVar => 2,
            OperandType.InlineI8 or OperandType.InlineR => 8,
            OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)),
            _ => 4
        };
        at += width;
        if (at > code.Length) throw new InvalidDataException("Truncated recovered CIL");
        var targets = opcode.OperandType switch
        {
            OperandType.ShortInlineBrTarget => new[] { at + unchecked((sbyte)code[operand]) },
            OperandType.InlineBrTarget => new[] { at + BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(operand, 4)) },
            OperandType.InlineSwitch => Enumerable.Range(0, (width-4)/4).Select(index => at + BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(operand+4+index*4, 4))).ToArray(),
            _ => Array.Empty<int>()
        };
        decoded.Add(start, (opcode, at, operand, targets));
    }
    HashSet<int> Reachable(int? knownNullBranch = null, int initializedSuccessor = -1)
    {
        var result = new HashSet<int>(); var pending = new Queue<int>(); pending.Enqueue(0);
        while (pending.TryDequeue(out int at))
        {
            if (!result.Add(at)) continue;
            if (!decoded.TryGetValue(at, out var row)) throw new InvalidDataException("CIL branch or fallthrough outside decoded body");
            if (knownNullBranch == at) { pending.Enqueue(initializedSuccessor); continue; }
            foreach (int target in row.Targets) pending.Enqueue(target);
            if (row.Op.FlowControl is not (FlowControl.Return or FlowControl.Throw or FlowControl.Branch)) pending.Enqueue(row.End);
        }
        return result;
    }
    var reachable = Reachable();
    var detectorType = assembly.GetType("CodeStage.AntiCheat.Detectors.ObscuredCheatingDetector", true)!;
    var detectorField = detectorType.GetField("<Instance>k__BackingField", BindingFlags.NonPublic | BindingFlags.Static)!;
    var getter = detectorType.GetProperty("Instance", BindingFlags.Public | BindingFlags.Static)!.GetMethod!;
    byte[] getterCode = getter.GetMethodBody()!.GetILAsByteArray()!;
    getterBodyHash = Convert.ToHexString(SHA256.HashData(getterCode)).ToLowerInvariant();
    // This additional scope proof is deliberately pinned to the immutable v36
    // method and independently validated no-cctor getter. It changes only this
    // probe's reachability analysis, never the recovered body or call opcode.
    const string PinnedBodyHash = "a5205a5ff8db842dd1364036451ba57e703964274a9b2a2c0ee9ae92217d0b0b";
    const string PinnedAssemblyHash = "224877d85a8b3dcde0a6f3f1d766ee3eafd7b02f00281b142d95b37ba0a64031";
    string LocalSignature(MethodBody candidateBody) => string.Join("|", candidateBody.LocalVariables.Select(v => v.LocalIndex + ":" + v.LocalType.AssemblyQualifiedName + ":" + v.IsPinned));
    var pinnedReference = new Lazy<(byte[] Code, string Diagnostic, string Locals, bool Init, int MaxStack)>(() =>
    {
        string referenceFolder = Guard("analysis/il2cpp/cpp2il-recovery-nso-virtual-dispatch-v36");
        string referencePath = Path.Combine(referenceFolder, "Assembly-CSharp-firstpass.dll");
        if (Hash(referencePath) != PinnedAssemblyHash) throw new InvalidDataException("Immutable v36 codec reference DLL differs");
        var referenceContext = new AssemblyLoadContext("codec_token_reference", true);
        referenceContext.Resolving += (c, n) => File.Exists(Path.Combine(referenceFolder, n.Name + ".dll")) ? c.LoadFromAssemblyPath(Path.Combine(referenceFolder, n.Name + ".dll")) : null;
        try
        {
            var referenceAssembly = referenceContext.LoadFromAssemblyPath(referencePath);
            var referenceMethod = referenceAssembly.GetType(type.FullName!, true)!.GetMethod(method.Name, BindingFlags.NonPublic | BindingFlags.Instance)!;
            var referenceBody = referenceMethod.GetMethodBody()!; byte[] referenceCode = referenceBody.GetILAsByteArray()!;
            if (Convert.ToHexString(SHA256.HashData(referenceCode)).ToLowerInvariant() != PinnedBodyHash || referenceCode[195] != 0x72 || referenceBody.ExceptionHandlingClauses.Count != 0)
                throw new InvalidDataException("Pinned reference body/header differs");
            return (referenceCode, referenceMethod.Module.ResolveString(BinaryPrimitives.ReadInt32LittleEndian(referenceCode.AsSpan(196, 4))), LocalSignature(referenceBody), referenceBody.InitLocals, referenceBody.MaxStackSize);
        }
        finally { referenceContext.Unload(); }
    });
    bool MatchesPinnedBody(byte[] candidate)
    {
        var reference = pinnedReference.Value;
        if (candidate.Length != reference.Code.Length || candidate[195] != 0x72 || body.InitLocals != reference.Init || body.MaxStackSize != reference.MaxStack || LocalSignature(body) != reference.Locals) return false;
        try
        {
            if (method.Module.ResolveString(BinaryPrimitives.ReadInt32LittleEndian(candidate.AsSpan(196, 4))) != reference.Diagnostic) return false;
            byte[] normalized = (byte[])candidate.Clone();
            reference.Code.AsSpan(196, 4).CopyTo(normalized.AsSpan(196, 4));
            return Convert.ToHexString(SHA256.HashData(normalized)).ToLowerInvariant() == PinnedBodyHash;
        }
        catch (Exception error) when (error is ArgumentException or BadImageFormatException) { return false; }
    }
    bool ProveNullBoundary(byte[] candidate, byte[] candidateGetter, bool detectorIsNull)
    {
        if (!detectorIsNull || detectorType.TypeInitializer != null
            || !MatchesPinnedBody(candidate)
            || Convert.ToHexString(SHA256.HashData(candidateGetter)).ToLowerInvariant() != "e2fc24869b8d39bb20cf308dda7ffe9c838bfb5cca2ea6af9a92b3d391c8c0fb"
            || candidateGetter.Length != 11 || candidateGetter[0] != 0x38 || BinaryPrimitives.ReadInt32LittleEndian(candidateGetter.AsSpan(1, 4)) != 0
            || candidateGetter[5] != 0x7E || candidateGetter[10] != 0x2A
            || getter.Module.ResolveField(BinaryPrimitives.ReadInt32LittleEndian(candidateGetter.AsSpan(6, 4))) != detectorField
            || !getter.IsStatic || getter.ReturnType != detectorType || getter.GetParameters().Length != 0) return false;
        bool Is(int at, OpCode opcode, int end, int? operand = null) => decoded.TryGetValue(at, out var row) && row.Op == opcode && row.End == end
            && (operand == null || BinaryPrimitives.ReadInt32LittleEndian(candidate.AsSpan(row.Operand, 4)) == operand);
        if (!Is(350, OpCodes.Call, 355) || !Is(355, OpCodes.Stloc, 359) || BinaryPrimitives.ReadUInt16LittleEndian(candidate.AsSpan(decoded[355].Operand, 2)) != 4
            || !Is(359, OpCodes.Call, 364) || !Is(364, OpCodes.Ldc_I4, 369, 0) || !Is(369, OpCodes.Ceq, 371)
            || !Is(371, OpCodes.Stloc, 375) || BinaryPrimitives.ReadUInt16LittleEndian(candidate.AsSpan(decoded[371].Operand, 2)) != 5
            || !Is(375, OpCodes.Ldloc, 379) || BinaryPrimitives.ReadUInt16LittleEndian(candidate.AsSpan(decoded[375].Operand, 2)) != 5
            || !Is(379, OpCodes.Brtrue, 384, 5) || !Is(384, OpCodes.Br, 389, -293)
            || method.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(candidate.AsSpan(decoded[350].Operand, 4))) != getter
            || method.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(candidate.AsSpan(decoded[359].Operand, 4))) != getter) return false;
        // Before this branch, all managed calls are the exact getter or an
        // already initialized own-type constructor contract. No detector setter
        // or arbitrary helper can change the explicit null static boundary.
        foreach (var (at, row) in decoded.Where(item => reachable.Contains(item.Key)))
        {
            if (row.Op == OpCodes.Stsfld && method.Module.ResolveField(BinaryPrimitives.ReadInt32LittleEndian(candidate.AsSpan(row.Operand, 4))) == detectorField) return false;
            if (row.Op.OperandType != OperandType.InlineMethod) continue;
            var target = method.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(candidate.AsSpan(row.Operand, 4)))!;
            if (target == getter || target.DeclaringType?.FullName?.StartsWith("Cpp2ILInjected.", StringComparison.Ordinal) == true) continue;
            var previous = decoded.SingleOrDefault(item => item.Value.End == at);
            if (target.DeclaringType != typeof(RuntimeHelpers) || target.Name != nameof(RuntimeHelpers.RunClassConstructor)
                || target is not MethodInfo info || info.ReturnType != typeof(void) || !info.GetParameters().Select(p => p.ParameterType).SequenceEqual(new[] { typeof(RuntimeTypeHandle) })
                || previous.Value.Op != OpCodes.Ldtoken || method.Module.ResolveType(BinaryPrimitives.ReadInt32LittleEndian(candidate.AsSpan(previous.Value.Operand, 4))) != type) return false;
        }
        return true;
    }
    bool hasSyntacticHelpers = decoded.Any(item => reachable.Contains(item.Key) && item.Value.Op.OperandType == OperandType.InlineMethod
        && method.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(item.Value.Operand, 4)))!.DeclaringType?.FullName?.StartsWith("Cpp2ILInjected.", StringComparison.Ordinal) == true);
    if (hasSyntacticHelpers)
    {
        RuntimeHelpers.RunClassConstructor(type.TypeHandle); // Retain the real .cctor before supplying test state.
        detectorField.SetValue(null, null);
        diagnosticTokenRelocationVerified = MatchesPinnedBody(code);
        diagnosticTokensRelocated = code.AsSpan(196, 4).SequenceEqual(pinnedReference.Value.Code.AsSpan(196, 4)) ? 0 : 1;
        exactNullBoundaryProof = ProveNullBoundary(code, getterCode, detectorField.GetValue(null) == null && getter.Invoke(null, null) == null);
        scopeControls.Add(new { control = "exact_original_null_getter_branch", passed = exactNullBoundaryProof });
        object nonNullDetector = RuntimeHelpers.GetUninitializedObject(detectorType);
        bool rejectsNonNull = !ProveNullBoundary(code, getterCode, nonNullDetector == null);
        scopeControls.Add(new { control = "non_null_detector_rejected_without_invocation", passed = rejectsNonNull });
        byte[] changedGetter = (byte[])getterCode.Clone(); changedGetter[0] ^= 1;
        bool rejectsGetter = !ProveNullBoundary(code, changedGetter, true);
        scopeControls.Add(new { control = "altered_getter_copy_rejected_without_execution", passed = rejectsGetter });
        byte[] changedBranch = (byte[])code.Clone(); changedBranch[379] = unchecked((byte)OpCodes.Brfalse.Value);
        bool rejectsBranch = !ProveNullBoundary(changedBranch, getterCode, true);
        scopeControls.Add(new { control = "altered_branch_copy_rejected_without_execution", passed = rejectsBranch });
        if (!exactNullBoundaryProof || !rejectsNonNull || !rejectsGetter || !rejectsBranch) throw new InvalidDataException("Unresolved helper has no exact verified absent-detector exclusion or negative control failed");
        reachable = Reachable(379, 389);
    }
    foreach (var (offset, row) in decoded)
    {
        if (row.Op.OperandType != OperandType.InlineMethod) continue;
        var target = method.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(row.Operand, 4)))!;
        bool unresolved = target.DeclaringType?.FullName?.StartsWith("Cpp2ILInjected.", StringComparison.Ordinal) == true
            || target.DeclaringType?.FullName == "System.Runtime.CompilerServices.Unsafe";
        if (unresolved && reachable.Contains(offset))
        {
            var previous = decoded.FirstOrDefault(candidate => candidate.Value.End == offset);
            string? diagnostic = previous.Value.Op == OpCodes.Ldstr
                ? method.Module.ResolveString(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(previous.Value.Operand, 4))) : null;
            blockedCalls.Add(new { offset, target = target.ToString(), declaring_type = target.DeclaringType?.FullName, diagnostic });
        }
        else if (unresolved)
        {
            unreachableHelpers++;
            scopeExcludedHelpers.Add(new { offset, target = target.ToString(), declaring_type = target.DeclaringType?.FullName });
        }
    }
    if (blockedCalls.Count != 0) throw new InvalidDataException("Reachable unresolved helper/unsafe address operation; actual body was not executed");
    var key = type.GetField("cryptoKey", BindingFlags.NonPublic | BindingFlags.Static)!;
    var fields = new[] { "currentCryptoKey", "hiddenValue", "fakeValue", "inited" }.Select(name => type.GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!).ToArray();
    detectorField.SetValue(null, null); // Supplied absent detector; original CLR type initializers may execute first.
    static uint[] Parts(ulong[] words) => [(uint)words[0], (uint)(words[0] >> 32), (uint)words[1], (uint)((words[1] >> 32) & 0xFF)];
    foreach (var line in File.ReadLines(fixturePath))
    {
        using var document = JsonDocument.Parse(line); var row = document.RootElement;
        if (row.GetProperty("mode").GetInt32() != 0) continue; // Exact native absent-detector fixture subset.
        var input = Parts(row.GetProperty("instanceWords").EnumerateArray().Select(element => element.GetUInt64()).ToArray());
        var expected = Parts(row.GetProperty("internalAfter").EnumerateArray().Select(element => element.GetUInt64()).ToArray());
        if (input[3] > 1 || expected[3] > 1) throw new InvalidDataException("Noncanonical native bool fixture");
        int global = row.GetProperty("globalKey").GetInt32(); key.SetValue(null, global);
        object value = Activator.CreateInstance(type)!; // CLR boxes a default value; game constructor is bypassed.
        for (int index = 0; index < 3; index++) fields[index].SetValue(value, unchecked((int)input[index]));
        fields[3].SetValue(value, input[3] != 0);
        uint result = unchecked((uint)(int)method.Invoke(value, null)!);
        uint[] actual = [unchecked((uint)(int)fields[0].GetValue(value)!), unchecked((uint)(int)fields[1].GetValue(value)!), unchecked((uint)(int)fields[2].GetValue(value)!), (bool)fields[3].GetValue(value)! ? 1u : 0u];
        bool keyUnchanged = (int)key.GetValue(null)! == global;
        if (detectorField.GetValue(null) != null || getter.Invoke(null, null) != null) throw new InvalidDataException("Explicit absent-detector boundary changed");
        boundaryChecks++;
        checks += 6;
        uint wanted = row.GetProperty("internalResult").GetUInt32();
        if (result != wanted || !actual.SequenceEqual(expected) || !keyUnchanged) failures.Add(new { index = cases, result, wanted, actual, expected, static_key_unchanged = keyUnchanged });
        if (input[3] == 0) lazy++; else initialized++;
        cases++;
    }
}
catch (Exception error)
{
    var chain = new List<string>();
    for (Exception? item = error; item != null; item = item.InnerException) chain.Add(item.GetType().FullName + ": " + item.Message);
    fatal = string.Join(" -> ", chain);
}
string status = fatal == null && cases > 0 && failures.Count == 0 && lazy > 0 && initialized > 0
    ? "PASS_ACTUAL_RECOVERED_VALUE_THIS_CODEC_VS_ORIGINAL_NATIVE" : "RECOVERY_EXECUTION_LIMITATION_CONFIRMED";
var report = new { status, recovery_run = run, cases, checks, lazy_initialization_cases = lazy, already_initialized_cases = initialized,
    failure_count = failures.Count, first_failures = failures.Take(8), fatal, blocked_calls = blockedCalls, unreachable_helper_calls = unreachableHelpers,
    cil_sha256 = bodyHash, assembly_sha256 = Hash(assemblyPath), fixture_sha256 = Hash(fixturePath), cil_or_source_edited = false, tokens_remapped = 0,
    probe_source_sha256 = Hash(Guard("src/re/RecoveredValueThisProbe/Program.cs")), getter_cil_sha256 = getterBodyHash,
    exact_null_getter_boundary_proved = exactNullBoundaryProof, null_boundary_checks = boundaryChecks, scope_guard_controls = scopeControls,
    scope_excluded_helpers = scopeExcludedHelpers, analysis_only_forced_null_branch = exactNullBoundaryProof ? new { offset = 379, taken_successor = 389, excluded_successor = 384 } : null,
    diagnostic_token_relocation_equivalent = diagnosticTokenRelocationVerified, relocated_diagnostic_string_tokens = diagnosticTokensRelocated,
    pinned_reference_assembly_sha256 = "224877d85a8b3dcde0a6f3f1d766ee3eafd7b02f00281b142d95b37ba0a64031",
    token_relocation_scope = "Only the four-byte LDSTR user-string token at original offset195 may differ; resolved string, every other original CIL byte, locals/pinning/InitLocals/maxstack and the original null-getter/branch remain identical to the pinned v36 reference. No candidate or original CIL is rewritten or executed from the analysis-only comparison copy.",
    active_detector_callback_recovered = false, active_detector_callback_executed = false,
    scope = "Calls actual recovered private InternalDecrypt CIL directly on a CLR-boxed value with original fields, no clones or CIL/source/token edits. Native absent-detector fixtures only, explicit initialized cryptoKey and detector statics; original CLR type initializers may execute. Checks return bits, all declared post-state fields, lazy initialization and unchanged key. Native padding, native object header/GC, constructors, active detector/callback, general integer aggregate ABI, conversions and complete source remain outside this comparison." };
File.WriteAllText(Guard($"reports/recovered-value-this-{run}.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine($"{status}: {cases} cases / {checks} checks; {fatal}");
return status.StartsWith("PASS", StringComparison.Ordinal) ? 0 : 2;
