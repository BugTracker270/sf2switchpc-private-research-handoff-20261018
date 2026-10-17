using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length is < 2 or > 3 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$")
    || (args.Length == 3 && args[2] is not ("--diagnostic-tail-experiment" or "--with-wrapper-identities"))) throw new ArgumentException("USB root and recovery run required");
bool tailExperiment = args.Length == 3 && args[2] == "--diagnostic-tail-experiment";
bool testIdentities = args.Length == 3 && args[2] == "--with-wrapper-identities";
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1];
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string folder = $"analysis/il2cpp/cpp2il-recovery-{run}";
string vectorPath = Guard(folder + "/UnityEngine.CoreModule.dll"), tweenPath = Guard(folder + "/DOTween.dll");
string fixturePath = Guard("analysis/il2cpp/vector3-native-fixtures-v1.json");
string Hash(string file) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))).ToLowerInvariant();
var failures = new List<object>();
var bodyHashes = new Dictionary<string, string>();
var initializerTokens = new List<object>();
var initializerPairs = new Dictionary<string, int>();
int initializerChecks = 0, throwingInitializerRequests = 0;
object? initializerNativeWitness = null;
string? fatal = null;
int cases = 0, checks = 0, nestedAddresses = 0, callerNestedAddresses = 0, unreachableWarningCalls = 0, identityCases = 0, identityChecks = 0;
string? identityFixtureHash = null;
try
{
    void InitCheck(bool condition, string message)
    {
        initializerChecks++;
        if (!condition) throw new Exception("Initializer boundary check: " + message);
    }
    var nativeBytes = File.ReadAllBytes(Guard("analysis/nso/main-uncompressed.nso"));
    if (Convert.ToHexString(SHA256.HashData(nativeBytes)).ToLowerInvariant() != "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968")
        throw new Exception("Original native input hash differs");
    using var nativeCaller = JsonDocument.Parse(File.ReadAllText(Guard("reports/native-fp-class-guard-caller.json")));
    string nativeCallerHash = Convert.ToHexString(SHA256.HashData(nativeBytes.AsSpan(0xA6A1F0 + 0x100, 172))).ToLowerInvariant();
    if (nativeCaller.RootElement.GetProperty("status").GetString() != "PASS_ORIGINAL_FP_SCHEDULED_CLASS_GUARD_HFA_CALLER"
        || nativeCaller.RootElement.GetProperty("caller_sha256").GetString() != nativeCallerHash
        || nativeCaller.RootElement.GetProperty("fixture_sha256").GetString() != Hash(fixturePath))
        throw new Exception("Original native caller evidence differs");
    int dataRaw = BinaryPrimitives.ReadInt32LittleEndian(nativeBytes.AsSpan(0x30, 4));
    int dataRva = BinaryPrimitives.ReadInt32LittleEndian(nativeBytes.AsSpan(0x34, 4));
    ulong typeSlot = BinaryPrimitives.ReadUInt64LittleEndian(nativeBytes.AsSpan(dataRaw + 0x3981A50 - dataRva, 8));
    using var typeUsageMap = JsonDocument.Parse(File.ReadAllText(Guard("analysis/il2cpp/effective-main/script.json")));
    var usage = typeUsageMap.RootElement.GetProperty("ScriptMetadata").EnumerateArray().Single(e => e.GetProperty("Address").GetUInt64() == typeSlot);
    if (usage.GetProperty("Name").GetString() != "UnityEngine.Vector3_TypeInfo") throw new Exception("Native initializer class-slot identity differs");
    initializerNativeWitness = new { caller_rva = "0xA6A1F0", native_bytes = 172, native_sha256 = nativeCallerHash,
        class_guard_rva = "0xA6A244", initializer_call_rva = "0xA6A254", initializer_target = "0xB2E720",
        class_got = "0x3981A50", type_usage_slot = $"0x{typeSlot:X}", type_usage = usage.GetProperty("Name").GetString(),
        original_initializer_contents_executed = false, native_evidence = "reports/native-fp-class-guard-caller.json" };
    var vectorAssembly = Assembly.LoadFrom(vectorPath);
    var tweenAssembly = Assembly.LoadFrom(tweenPath);
    var vectorType = vectorAssembly.GetType("UnityEngine.Vector3", true)!;
    var wrapperType = tweenAssembly.GetType("DG.Tweening.Core.Surrogates.Vector3Wrapper", true)!;
    var pluginType = tweenAssembly.GetType("DG.Tweening.Plugins.Vector3WrapperPlugin", true)!;
    var caller = pluginType.GetMethod("SetRelativeEndValue", BindingFlags.Public | BindingFlags.Instance)!;
    var ownerType = caller.GetParameters().Single().ParameterType;
    var addition = vectorType.GetMethod("op_Addition", BindingFlags.Public | BindingFlags.Static)!;
    if (!vectorType.IsValueType || !wrapperType.IsValueType || !ownerType.IsConstructedGenericType)
        throw new Exception("Expected recovered vector/wrapper/closed generic declarations");
    var fields = vectorType.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
    if (fields.Length != 3 || fields.Any(f => f.FieldType != typeof(float))
        || !fields.Select(f => f.Name).Order().SequenceEqual(new[] { "x", "y", "z" })) throw new Exception("Vector field shape differs");
    var wrapperFields = wrapperType.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
    if (wrapperFields.Length != 1 || wrapperFields[0].Name != "value" || wrapperFields[0].FieldType != vectorType)
        throw new Exception("Nested wrapper shape differs");
    Type MapType(Type type) => type == vectorType ? typeof(Vec3) : type == wrapperType ? typeof(VecWrapper)
        : type == ownerType ? typeof(TweenData) : type.IsPrimitive ? type : throw new Exception("Unapproved local/type substitution: " + type);
    var operations = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(OpCode))
        .Select(f => (OpCode)f.GetValue(null)!).ToDictionary(op => unchecked((ushort)op.Value));

    var runClassConstructor = typeof(System.Runtime.CompilerServices.RuntimeHelpers).GetMethod("RunClassConstructor", [typeof(RuntimeTypeHandle)])!;
    bool IsRcc(MethodBase? method) => method is MethodInfo m && m.IsStatic && m.ReturnType == typeof(void)
        && m.DeclaringType?.FullName == "System.Runtime.CompilerServices.RuntimeHelpers" && m.Name == "RunClassConstructor"
        && m.GetParameters().Length == 1 && m.GetParameters()[0].ParameterType == typeof(RuntimeTypeHandle);
    DynamicMethod Clone(MethodInfo source, string name, Type returns, Type[] parameters, DynamicMethod? recoveredAddition, Type? initializerBoundary = null)
    {
        var body = source.GetMethodBody()!;
        if (body.ExceptionHandlingClauses.Count != 0) throw new Exception("Unexpected exception region");
        var code = body.GetILAsByteArray()!;
        bodyHashes[name] = Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant();
        var dynamic = new DynamicMethod(name, returns, parameters, typeof(Program).Module, true);
        var info = dynamic.GetDynamicILInfo();
        var signature = SignatureHelper.GetLocalVarSigHelper();
        foreach (var local in body.LocalVariables) signature.AddArgument(MapType(local.LocalType), local.IsPinned);
        info.SetLocalSignature(signature.GetSignature());
        // The upstream emitter appends analysis warnings after the executable body.
        // Prove reachability before mapping those calls to a throwing trap. Retain
        // all bytes: a reachable helper is still rejected rather than ignored.
        var decoded = new Dictionary<int, (OpCode Op, int End, int[] Targets)>();
        for (int at = 0; at < code.Length;)
        {
            int start = at;
            ushort value = code[at++];
            if (value == 0xfe) value = (ushort)(0xfe00 | code[at++]);
            var op = operations[value];
            int operand = at;
            int width = op.OperandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(at, 4)),
                _ => 4
            };
            at += width;
            var targets = op.OperandType switch
            {
                OperandType.ShortInlineBrTarget => new[] { at + unchecked((sbyte)code[operand]) },
                OperandType.InlineBrTarget => new[] { at + BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(operand, 4)) },
                OperandType.InlineSwitch => Enumerable.Range(0, (width - 4) / 4).Select(i => at + BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(operand + 4 + 4 * i, 4))).ToArray(),
                _ => Array.Empty<int>()
            };
            decoded.Add(start, (op, at, targets));
        }
        var reachable = new HashSet<int>();
        var pending = new Queue<int>();
        pending.Enqueue(0);
        while (pending.TryDequeue(out int at))
        {
            if (!reachable.Add(at)) continue;
            if (!decoded.TryGetValue(at, out var row)) throw new Exception("CIL branch/fallthrough is outside an instruction boundary");
            foreach (var target in row.Targets) pending.Enqueue(target);
            if (row.Op.FlowControl is not (FlowControl.Branch or FlowControl.Return or FlowControl.Throw)) pending.Enqueue(row.End);
        }
        int offset = 0;
        initializerPairs[name] = 0;
        while (offset < code.Length)
        {
            int instructionOffset = offset;
            ushort value = code[offset++];
            if (value == 0xfe) value = (ushort)(0xfe00 | code[offset++]);
            var op = operations[value];
            switch (op.OperandType)
            {
                case OperandType.InlineNone: continue;
                case OperandType.ShortInlineI: case OperandType.ShortInlineVar: case OperandType.ShortInlineBrTarget: offset++; continue;
                case OperandType.InlineVar: offset += 2; continue;
                case OperandType.InlineI8: case OperandType.InlineR: offset += 8; continue;
                case OperandType.InlineI: case OperandType.ShortInlineR: case OperandType.InlineBrTarget: offset += 4; continue;
                case OperandType.InlineSwitch: offset += 4 + 4 * BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(offset, 4)); continue;
            }
            int token = BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(offset, 4)), replacement;
            if (op.OperandType == OperandType.InlineField)
            {
                var field = source.Module.ResolveField(token)!;
                FieldInfo mapped;
                if (field.DeclaringType == vectorType && field.FieldType == typeof(float) && new[] { "x", "y", "z" }.Contains(field.Name))
                    mapped = typeof(Vec3).GetField(field.Name)!;
                else if (field.DeclaringType == wrapperType && field.Name == "value" && field.FieldType == vectorType)
                    mapped = typeof(VecWrapper).GetField("value")!;
                else if (field.DeclaringType == ownerType && field.FieldType == wrapperType && new[] { "startValue", "endValue", "changeValue" }.Contains(field.Name))
                    mapped = typeof(TweenData).GetField(field.Name)!;
                else throw new Exception("Unapproved field substitution: " + field);
                if (op == OpCodes.Ldflda) nestedAddresses++;
                replacement = info.GetTokenFor(mapped.FieldHandle);
            }
            else if (op.OperandType == OperandType.InlineType)
                replacement = info.GetTokenFor(MapType(source.Module.ResolveType(token)).TypeHandle);
            else if (op.OperandType == OperandType.InlineMethod && op == OpCodes.Call && source.Module.ResolveMethod(token) == addition && recoveredAddition != null)
                replacement = info.GetTokenFor(recoveredAddition);
            else if (op == OpCodes.Ldtoken && op.OperandType == OperandType.InlineTok && source == caller && initializerBoundary != null
                && source.Module.ResolveMember(token) == vectorType
                && decoded.TryGetValue(decoded[instructionOffset].End, out var afterHandle) && afterHandle.Op == OpCodes.Call
                && IsRcc(source.Module.ResolveMethod(BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(afterHandle.End - 4, 4)))))
            {
                replacement = info.GetTokenFor(initializerBoundary.TypeHandle);
                initializerPairs[name]++;
                initializerTokens.Add(new { method = source.ToString(), instructionOffset, token = $"0x{token:X8}", resolved = vectorType.ToString(),
                    mapped_host_type = initializerBoundary.FullName, managed_call = runClassConstructor.ToString(), opcodes_preserved = true });
            }
            else if (op.OperandType == OperandType.InlineMethod && op == OpCodes.Call && source == caller && initializerBoundary != null
                && IsRcc(source.Module.ResolveMethod(token))
                && decoded.Any(p => p.Value.End == instructionOffset && p.Value.Op == OpCodes.Ldtoken
                    && source.Module.ResolveMember(BinaryPrimitives.ReadInt32LittleEndian(source.GetMethodBody()!.GetILAsByteArray()!.AsSpan(p.Value.End - 4, 4))) == vectorType))
                replacement = info.GetTokenFor(runClassConstructor.MethodHandle);
            else if (op.OperandType == OperandType.InlineString && !reachable.Contains(instructionOffset)
                && source.Module.ResolveString(token) is { } warning && warning.StartsWith("Warning: ", StringComparison.Ordinal))
                replacement = info.GetTokenFor(warning);
            else if (op.OperandType == OperandType.InlineMethod && op == OpCodes.Call && !reachable.Contains(instructionOffset)
                && source.Module.ResolveMethod(token) is MethodInfo { Name: "NoteDecompilerIssue", DeclaringType.FullName: "Cpp2ILInjected.Cpp2ILHelpers" })
            {
                replacement = info.GetTokenFor(typeof(DiagnosticTrap).GetMethod(nameof(DiagnosticTrap.Fail))!.MethodHandle);
                unreachableWarningCalls++;
            }
            else if (op.OperandType == OperandType.InlineTok)
            {
                var resolved = source.Module.ResolveMember(token);
                initializerTokens.Add(new { method = source.ToString(), instructionOffset, token = $"0x{token:X8}", resolved = resolved?.ToString(),
                    next_opcode = decoded.TryGetValue(decoded[instructionOffset].End, out var next) ? next.Op.Name : null });
                throw new Exception("Unreviewed type-handle boundary: " + resolved);
            }
            else throw new Exception("Unexpected token/call; diagnostic helpers are forbidden: " + op);
            BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(offset, 4), replacement);
            offset += 4;
        }
        if (tailExperiment && name == "RecoveredNestedTweenCaller")
        {
            var last = decoded.Last();
            if (reachable.Contains(last.Key) || unreachableWarningCalls != 1 || last.Value.Op != OpCodes.Call)
                throw new Exception("Expected one statically unreachable trailing warning call");
            code = code.Concat(new byte[] { 0x14, 0x7a }).ToArray(); // ldnull; throw: experiment only
        }
        info.SetCode(code, body.MaxStackSize);
        return dynamic;
    }
    var recoveredAdd = Clone(addition, "RecoveredVector3Add", typeof(Vec3), [typeof(Vec3), typeof(Vec3)], null);
    var recoveredCaller = Clone(caller, "RecoveredNestedTweenCaller", typeof(void), [typeof(object), typeof(TweenData)], recoveredAdd, typeof(VectorInitializationBoundary));
    InitCheck(initializerPairs["RecoveredNestedTweenCaller"] == 1, "one original class-handle/call pair");
    InitCheck(InitializationObservation.Effects == 0 && InitializationObservation.Marker == 0, "host .cctor has not executed before original caller request");
    if (nestedAddresses != 18) throw new Exception("Expected two nested addresses for each of six reads and three writes");
    callerNestedAddresses = nestedAddresses;
    var relative = recoveredCaller.CreateDelegate<Action<object?, TweenData>>();
    using var fixture = JsonDocument.Parse(File.ReadAllText(fixturePath));
    var marker = Vec3.From([0x3f123456u, 0xbf654321u, 0x00800001u]);
    foreach (var row in fixture.RootElement.EnumerateArray())
    {
        var a = row.GetProperty("a").EnumerateArray().Select(v => v.GetUInt32()).ToArray();
        var b = row.GetProperty("b").EnumerateArray().Select(v => v.GetUInt32()).ToArray();
        var want = row.GetProperty("result").EnumerateArray().Select(v => v.GetUInt32()).ToArray();
        var tween = new TweenData { startValue = new() { value = Vec3.From(b) }, endValue = new() { value = Vec3.From(a) }, changeValue = new() { value = marker } };
        relative(null, tween);
        InitCheck(InitializationObservation.Effects == 1, "initializer executes once across original caller invocations");
        InitCheck(InitializationObservation.Marker == 0x51F2A17, "nondefault observable initializer effect retained");
        var got = tween.endValue.value.Bits();
        checks += 9;
        if (!got.SequenceEqual(want) || !tween.startValue.value.Bits().SequenceEqual(b) || !tween.changeValue.value.Bits().SequenceEqual(marker.Bits()))
            failures.Add(new { index = cases, got, want });
        cases++;
    }
    InitCheck(InitializationObservation.Effects == 1, "final once-only class effect");
    var throwingCaller = Clone(caller, "RecoveredNestedTweenCallerThrowingBoundary", typeof(void), [typeof(object), typeof(TweenData)], recoveredAdd, typeof(VectorThrowingInitializationBoundary))
        .CreateDelegate<Action<object?, TweenData>>();
    InitCheck(initializerPairs["RecoveredNestedTweenCallerThrowingBoundary"] == 1, "throwing fixture retains one original handle/call pair");
    InitCheck(InitializationObservation.ThrowEffects == 0, "throwing .cctor remains uninitialized before request");
    for (int attempt = 0; attempt < 2; attempt++)
    {
        var tween = new TweenData { startValue = new() { value = marker }, endValue = new() { value = marker }, changeValue = new() { value = marker } };
        Exception? observed = null;
        try { throwingCaller(null, tween); } catch (Exception error) { observed = error; }
        throwingInitializerRequests++;
        InitCheck(observed is TypeInitializationException, "original RCC propagates persistent type-initialization failure");
        InitCheck(InitializationObservation.ThrowEffects == 1, "throwing constructor body executes only once");
        foreach (var value in new[] { tween.startValue.value, tween.endValue.value, tween.changeValue.value })
            foreach (var pair in value.Bits().Zip(marker.Bits())) InitCheck(pair.First == pair.Second, "failure precedes original game-field writes");
    }
    if (testIdentities)
    {
        var convert = pluginType.GetMethod("ConvertToStartValue", BindingFlags.Public | BindingFlags.Instance)!;
        var unwrap = wrapperType.GetMethods(BindingFlags.Public | BindingFlags.Static).Single(m => m.Name == "op_Implicit" && m.ReturnType == vectorType);
        var wrap = wrapperType.GetMethods(BindingFlags.Public | BindingFlags.Static).Single(m => m.Name == "op_Implicit" && m.ReturnType == wrapperType);
        var converted = Clone(convert, "RecoveredWrapperConvert", typeof(VecWrapper), [typeof(object), typeof(TweenData), typeof(VecWrapper)], null)
            .CreateDelegate<Func<object?, TweenData?, VecWrapper, VecWrapper>>();
        var unwrapped = Clone(unwrap, "RecoveredWrapperUnwrap", typeof(Vec3), [typeof(VecWrapper)], null).CreateDelegate<Func<VecWrapper, Vec3>>();
        var wrapped = Clone(wrap, "RecoveredWrapperWrap", typeof(VecWrapper), [typeof(Vec3)], null).CreateDelegate<Func<Vec3, VecWrapper>>();
        string path = Guard("analysis/il2cpp/nested-hfa-identity-native-fixtures-v1.json");
        identityFixtureHash = Hash(path);
        using var identities = JsonDocument.Parse(File.ReadAllText(path));
        foreach (var row in identities.RootElement.EnumerateArray())
        {
            string method = row.GetProperty("method").GetString()!;
            var input = row.GetProperty("input").EnumerateArray().Select(v => v.GetUInt32()).ToArray();
            var expected = row.GetProperty("result").EnumerateArray().Select(v => v.GetUInt32()).ToArray();
            var vector = Vec3.From(input);
            var got = method switch
            {
                "convert" => converted(null, null, new VecWrapper { value = vector }).value.Bits(),
                "unwrap" => unwrapped(new VecWrapper { value = vector }).Bits(),
                "wrap" => wrapped(vector).value.Bits(),
                _ => throw new Exception("Unknown native identity fixture")
            };
            if (!got.SequenceEqual(expected)) failures.Add(new { method, identity_index = identityCases, got, expected });
            identityCases++;
            identityChecks += 3;
        }
        if (identityCases != 240) throw new Exception("Expected 80 original cases for each of three distinct identity methods");
    }
}
catch (Exception ex) { fatal = ex.GetType().FullName + ": " + ex.Message; }
var report = new
{
    status = fatal == null && failures.Count == 0 && cases > 0
        ? (tailExperiment ? "PASS_EXPERIMENTAL_UNREACHABLE_TAIL_TERMINATION_ONLY"
            : testIdentities ? "PASS_RECOVERED_NESTED_HFA_AND_CALLER_NATIVE_COMPARISON" : "PASS_RECOVERED_NESTED_GENERIC_CALLER_VS_ORIGINAL_NATIVE")
        : "RECOVERED_NESTED_GENERIC_CALLER_LIMITATION",
    recovery_run = run, cases, checks, nested_field_address_instructions = nestedAddresses, caller_nested_field_addresses = callerNestedAddresses,
    identity_cases = identityCases, identity_checks = identityChecks, total_checks = checks + identityChecks + initializerChecks, failure_count = failures.Count,
    statically_unreachable_analysis_warning_calls = unreachableWarningCalls,
    diagnostic_tail_termination_experiment = tailExperiment,
    first_failures = failures.Take(8), fatal, body_il_sha256 = bodyHashes,
    initialization_token_observations = initializerTokens,
    initialization_native_witness = initializerNativeWitness, initialization_pair_counts = initializerPairs,
    initializer_boundary_checks = initializerChecks, initializer_effect_count = InitializationObservation.Effects,
    initializer_nondefault_marker = InitializationObservation.Marker, throwing_initializer_requests = throwingInitializerRequests,
    throwing_initializer_effect_count = InitializationObservation.ThrowEffects,
    vector_assembly_sha256 = Hash(vectorPath), tween_assembly_sha256 = Hash(tweenPath), fixture_sha256 = Hash(fixturePath),
    identity_fixture_sha256 = identityFixtureHash,
    scope = "Actual recovered caller and addition CIL, with exact vector/wrapper/closed-generic field tokens replaced by isolated equivalent storage types. Scalar instructions, local layout, branches and stores retained; managed addition call target replaced by the actual recovered addition DynamicMethod. The exact original UnityEngine.Vector3 ldtoken/RuntimeHelpers.RunClassConstructor pair is retained; only its handle token maps to disclosed host initialization fixtures. Nondefault once-only effects and persistent constructor failure before all tween writes are measured. This is an explicit initializer-content boundary, not execution/parity of original Unity/game .cctor contents or original global initialization ordering. Appended analysis-warning calls are allowed only after full reachability proves them unreachable and map to a throwing trap without removing bytes. Three resulting component bits and six unchanged start/change bits per native math case. Every reachable diagnostic/helper or unreviewed substitution is rejected. No whole assembly, complete SetStage or portable-game claim. Original caller/initializer-request evidence: reports/native-fp-class-guard-caller.json."
        + (tailExperiment ? " EXPERIMENT ONLY: appends ldnull/throw to the proven-unreachable warning tail to isolate the JIT failure; this is not acceptance of unchanged recovered CIL." : "")
        + (testIdentities ? " Also executes three actual recovered nested-wrapper argument/return methods against all 240 original-code identity fixtures (720 checks); no game-method call substitutions in those identities." : "")
};
var output = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
File.WriteAllText(Guard($"reports/recovered-nested-tween-{run}{(tailExperiment ? "-tail-experiment" : testIdentities ? "-with-identities" : "")}.json"), output + "\n");
Console.WriteLine(output);
return fatal == null && failures.Count == 0 && cases > 0 ? 0 : 2;

public struct Vec3
{
    public float x, y, z;
    public static Vec3 From(uint[] b) => new() { x = BitConverter.Int32BitsToSingle(unchecked((int)b[0])), y = BitConverter.Int32BitsToSingle(unchecked((int)b[1])), z = BitConverter.Int32BitsToSingle(unchecked((int)b[2])) };
    public uint[] Bits() => [unchecked((uint)BitConverter.SingleToInt32Bits(x)), unchecked((uint)BitConverter.SingleToInt32Bits(y)), unchecked((uint)BitConverter.SingleToInt32Bits(z))];
}
public struct VecWrapper { public Vec3 value; }
public sealed class TweenData { public VecWrapper startValue, endValue, changeValue; }
public static class DiagnosticTrap { public static void Fail(string message) => throw new InvalidOperationException("Recovered analysis warning became reachable: " + message); }
public static class InitializationObservation
{
    public static int Effects, Marker, ThrowEffects;
}
public sealed class VectorInitializationBoundary
{
    static VectorInitializationBoundary()
    {
        System.Threading.Interlocked.Increment(ref InitializationObservation.Effects);
        InitializationObservation.Marker = 0x51F2A17;
    }
}
public sealed class VectorThrowingInitializationBoundary
{
    static VectorThrowingInitializationBoundary()
    {
        System.Threading.Interlocked.Increment(ref InitializationObservation.ThrowEffects);
        throw new InvalidOperationException("Explicit host class-initialization boundary failure");
    }
}
