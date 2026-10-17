using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;
using LibCpp2IL;

if (args.Length != 1) throw new ArgumentException("Verified USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
if (!string.Equals(root, @"F:\SF2SwitchPC", StringComparison.OrdinalIgnoreCase)) throw new IOException("Unexpected canonical USB workspace");
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? dir = new(Path.GetDirectoryName(path)!); dir != null; dir = dir.Parent)
        if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point");
    return path;
}
string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
string BytesHash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
var tests = new List<object>(); var rawSites = new List<object>(); var emitted = new List<object>();
string? fatal = null; int checks = 0; int ssaResultVersion = -1, ssaClassVersion = -1;
void Check(string name, bool passed)
{
    tests.Add(new { name, status = passed ? "PASS" : "FAIL" }); checks++;
    if (!passed) throw new InvalidDataException(name);
}
string binary = Guard("unpacked/effective/exefs/main"), metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
string coreHash = Hash(typeof(Cpp2IlApi).Assembly.Location);
try
{
    Check("original input hashes", Hash(binary) == "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
        && Hash(metadata) == "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85");
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
    Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
    Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
    var app = Cpp2IlApi.CurrentAppContext!;
    var boolean = app.SystemTypes.SystemBooleanType;
    var reader = app.AllTypes.Single(t => t.FullName == "BestHTTP.WebSocket.Frames.WebSocketFrameReader");
    ulong target = LegacyArm64ClassLayoutAbi.Target;
    Check("exact reviewed target accepted", target == 0xB04F60 && LegacyArm64ClassLayoutAbi.IsKnownTarget(app, target));
    Check("distinct cctor helper rejected", !LegacyArm64ClassLayoutAbi.IsKnownTarget(app, 0xB2E720));
    Check("interior address rejected", !LegacyArm64ClassLayoutAbi.IsKnownTarget(app, target + 4));
    Check("zero target rejected", !LegacyArm64ClassLayoutAbi.IsKnownTarget(app, 0));
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", null);
    Check("disabled opt-in rejected after cache populated", !LegacyArm64ClassLayoutAbi.IsKnownTarget(app, target));
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
    Check("reenabled exact target accepted", LegacyArm64ClassLayoutAbi.IsKnownTarget(app, target));

    Check("exact original frame is 140 bytes", LegacyArm64ValueThisThunks.TryGetExactBodyRange(app, target, out int size) && size == 140);
    Check("native helper maps to original loaded image", app.Binary.TryMapVirtualAddressToRaw(target, out var helperRaw));
    byte[] image = app.Binary.GetRawBinaryContent().ToArray();
    Check("derived relocated image identity is explicit", image.Length == LegacyArm64ClassLayoutAbi.DerivedLoadedImageSize
        && BytesHash(image) == LegacyArm64ClassLayoutAbi.DerivedLoadedImageSha256);
    Check("actual immutable image/frame guard accepts", LegacyArm64ClassLayoutAbi.MatchesReviewedImage(image, helperRaw, size));
    Check("old incomplete 112-byte frame rejected", !LegacyArm64ClassLayoutAbi.MatchesReviewedImage(image, helperRaw, 112));
    Check("larger frame rejected", !LegacyArm64ClassLayoutAbi.MatchesReviewedImage(image, helperRaw, 144));
    Check("negative raw offset rejected", !LegacyArm64ClassLayoutAbi.MatchesReviewedImage(image, -1, size));
    Check("overflow raw offset rejected", !LegacyArm64ClassLayoutAbi.MatchesReviewedImage(image, long.MaxValue, size));
    Check("out-of-range raw offset rejected", !LegacyArm64ClassLayoutAbi.MatchesReviewedImage(image, image.Length, size));
    Check("truncated loaded image rejected", !LegacyArm64ClassLayoutAbi.MatchesReviewedImage(image.AsSpan(0, image.Length - 1), helperRaw, size));
    var altered = image.ToArray(); altered[checked((int)helperRaw)] ^= 1;
    Check("changed native helper byte rejected on copied image", !LegacyArm64ClassLayoutAbi.MatchesReviewedImage(altered, helperRaw, size));
    altered[checked((int)helperRaw)] ^= 1; altered[0] ^= 1;
    Check("changed non-helper image byte rejected on copied image", !LegacyArm64ClassLayoutAbi.MatchesReviewedImage(altered, helperRaw, size));
    Check("probe did not modify application image", BytesHash(app.Binary.GetRawBinaryContent()) == LegacyArm64ClassLayoutAbi.DerivedLoadedImageSha256);

    int serial = 0;
    Fixture Make(bool seed = true)
    {
        var owner = new InjectedMethodAnalysisContext(reader, "ClassLayoutAbiFixture" + serial++, boolean, MethodAttributes.Public | MethodAttributes.Static, []);
        var call = LegacyArm64ClassLayoutAbi.CreateCall(owner, 1, target) ?? throw new InvalidDataException("Exact helper call construction rejected");
        var setup = new Instruction(0, OpCode.Move, new Register(null, "X0"), app.SystemTypes.SystemByteType);
        owner.ControlFlowGraph = new ISILControlFlowGraph([setup, call, new Instruction(2, OpCode.Return, new Register(null, "X0"))]);
        owner.DominatorInfo = new DominatorInfo(owner.ControlFlowGraph);
        SsaForm.Build(owner); LocalVariables.CreateAll(owner);
        if (seed) LegacyArm64ClassLayoutAbi.SeedResults(owner);
        return new(owner, call, (LocalVariable)call.Operands[1], (LocalVariable)call.Operands[2], setup);
    }
    var valid = Make();
    Check("SSA class and result remain separate original X0 versions", valid.Result.Register.Name == "X0" && valid.Class.Register.Name == "X0"
        && !ReferenceEquals(valid.Result, valid.Class) && valid.Result.Register.Version > valid.Class.Register.Version);
    ssaResultVersion = valid.Result.Register.Version; ssaClassVersion = valid.Class.Register.Version;
    Check("original class source provenance retained", ReferenceEquals(valid.Setup.Destination, valid.Class)
        && ReferenceEquals(valid.Setup.Operands[1], app.SystemTypes.SystemByteType));
    Check("Boolean seed is canonical and original result reaches return", ReferenceEquals(valid.Result.Type, boolean)
        && valid.Owner.ControlFlowGraph!.Instructions.Single(i => i.OpCode == OpCode.Return).Operands is [LocalVariable r] && ReferenceEquals(r, valid.Result));
    Check("only the one real class operand remains a source", valid.Call.Operands.Count == 3 && valid.Call.Sources.Count == 1
        && ReferenceEquals(valid.Call.Sources[0], valid.Class) && valid.Call.ImplicitDefinition == null);
    DeadCodeEliminator.Run(valid.Owner);
    Check("unused-effect DCE cannot remove the helper call", valid.Owner.ControlFlowGraph!.Instructions.Contains(valid.Call) && valid.Call.OpCode == OpCode.Call);
    Check("valid typed ABI is emission eligible only as unresolved call", LegacyArm64ClassLayoutAbi.ValidForEmission(valid.Call, valid.Owner));
    Check("wrong target never constructs a narrowed call", LegacyArm64ClassLayoutAbi.CreateCall(valid.Owner, 99, target + 4) == null);
    var clone = new Instruction(valid.Call.Index, valid.Call.OpCode, valid.Call.Operands.ToList()) { NativeClassLayoutAbi = valid.Call.NativeClassLayoutAbi };
    Check("fresh identity clone preserves immutable ABI carrier", !ReferenceEquals(clone, valid.Call)
        && ReferenceEquals(clone.NativeClassLayoutAbi, valid.Call.NativeClassLayoutAbi) && LegacyArm64ClassLayoutAbi.ValidForEmission(clone, valid.Owner));
    Check("production indirect-return clone explicitly preserves carrier", File.ReadAllText(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64IndirectReturns.cs"))
        .Contains("NativeClassLayoutAbi = row.NativeClassLayoutAbi", StringComparison.Ordinal));
    Check("foreign owner rejects same carrier", !LegacyArm64ClassLayoutAbi.IsProvenCall(Make().Owner, valid.Call));
    foreach (var (name, mutate) in new (string, Action<Fixture>)[] {
        ("stale target", f => f.Call.SetOperand(0, new Immediate(unchecked((long)target + 4)))),
        ("stale void opcode", f => f.Call.OpCode = OpCode.CallVoid),
        ("missing class argument", f => f.Call.RemoveOperandAt(2)),
        ("extra stale X1 input", f => f.Call.AddOperands([new LocalVariable("stale", new Register(null, "X1"))])),
        ("missing carrier", f => f.Call.NativeClassLayoutAbi = null),
        ("conflicting result type", f => f.Result.Type = app.SystemTypes.SystemInt32Type),
    }) { var f = Make(); mutate(f); Check(name + " rejects emission", !LegacyArm64ClassLayoutAbi.ValidForEmission(f.Call, f.Owner)); }
    foreach (var (name, mutate) in new (string, Action<Fixture>)[] {
        ("conflicting preexisting type", f => f.Result.Type = app.SystemTypes.SystemInt32Type),
        ("wrong result register", f => f.Call.SetOperand(1, new LocalVariable("other", new Register(null, "X2")))),
        ("wrong class input register", f => f.Call.SetOperand(2, new LocalVariable("other", new Register(null, "X1")))),
        ("stale target before seeding", f => f.Call.SetOperand(0, new Immediate(unchecked((long)target + 4)))),
    }) { var f = Make(false); mutate(f); bool rejected = false; try { LegacyArm64ClassLayoutAbi.SeedResults(f.Owner); }
        catch (InvalidOperationException) { rejected = true; } Check(name + " fails closed at SSA seed", rejected); }

    void InvokePrivate(string name, MethodAnalysisContext owner) => typeof(MetadataResolver).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, [owner]);
    bool IsStillNative(Fixture f) => f.Call.OpCode == OpCode.Call && f.Call.Operands is [Immediate t, _, _]
        && t.UnsignedValue == target && LegacyArm64ClassLayoutAbi.IsProvenCall(f.Owner, f.Call);
    var oldAliases = app.MethodsByAddress.GetValueOrDefault(target);
    var aliasA = new InjectedMethodAnalysisContext(reader, "SyntheticNativeAliasA", boolean, MethodAttributes.Public | MethodAttributes.Static, []);
    var aliasB = new InjectedMethodAnalysisContext(reader, "SyntheticNativeAliasB", boolean, MethodAttributes.Public | MethodAttributes.Static, []);
    try
    {
        app.MethodsByAddress[target] = [aliasA];
        var f = Make(); InvokePrivate("ResolveCalls", f.Owner);
        Check("single managed alias cannot capture reviewed helper", IsStillNative(f));
        app.MethodsByAddress[target] = [aliasA, aliasB]; f = Make(); MetadataResolver.ResolveAmbiguousCalls(f.Owner);
        Check("interchangeable managed aliases cannot capture helper", IsStillNative(f));
        app.MethodsByAddress.Remove(target); f = Make(); f.Call.SetOperand(2, new RuntimeMethodInfoAnalysisContext(aliasA, reader.DeclaringAssembly));
        MetadataResolver.ResolveCallsViaMethodInfo(f.Owner);
        Check("stale MethodInfo does not resolve helper to unrelated method", IsStillNative(f));
        var ctor = new InjectedMethodAnalysisContext(reader, ".ctor", app.SystemTypes.SystemVoidType, MethodAttributes.Public, []);
        app.MethodsByAddress[target] = [ctor]; f = Make(); f.Class.Type = reader;
        f.Setup.OpCode = OpCode.Newobj; f.Setup.SetOperands(f.Class, reader);
        MetadataResolver.ResolveConstructorCalls(f.Owner);
        Check("synthetic allocation context cannot reinterpret helper as ctor", IsStillNative(f));
        var literal = app.LibCpp2IlContext.Metadata.metadataUsageDic![(uint)MetadataUsageType.StringLiteral].First();
        ulong literalSlot = app.Binary.GetRawMetadataUsage(literal.Key);
        Check("string-accessor negative uses real registered literal slot", app.LibCpp2IlContext.GetLiteralByAddress(literalSlot) != null);
        f = Make(); f.Call.SetOperand(2, new Immediate(unchecked((long)literalSlot)));
        InvokePrivate("ResolveStringLiteralAccessors", f.Owner);
        Check("literal slot argument cannot erase helper call", IsStillNative(f));
        app.MethodsByAddress[target] = [aliasA];
        var method = app.MethodsByAddress[0x4A0D70].Single(m => m.DeclaringType?.FullName == reader.FullName && m.Name == "Read");
        var raw = app.InstructionSet.GetIsilFromMethod(method);
        var calls = raw.Where(i => i.IsCall && i.Operands[0] is Immediate t && t.UnsignedValue == target).ToArray();
        Check("actual original reader has all four narrowed helper sites before alias selection", calls.Length == 4
            && calls.All(c => c.Operands is [Immediate, Register { Name: "X0" }, Register { Name: "X0" }]
                && LegacyArm64ClassLayoutAbi.IsProvenCall(method, c)));
        rawSites.AddRange(calls.Select(c => (object)new { index = c.Index, operands = c.Operands.Count,
            input_register = "X0", result_register = "X0", managed_alias_bypassed = true }));
    }
    finally { if (oldAliases == null) app.MethodsByAddress.Remove(target); else app.MethodsByAddress[target] = oldAliases; }

    var corlib = ModuleDefinition.FromFile(typeof(bool).Assembly.Location);
    boolean.PutExtraData("AsmResolverType", corlib.TopLevelTypes.Single(t => t.FullName == "System.Boolean"));
    var module = new ModuleDefinition("ClassLayoutAbiDiagnosticFixture.dll");
    var assembly = new AssemblyDefinition("ClassLayoutAbiDiagnosticFixture", new Version(1, 0)); assembly.Modules.Add(module);
    var holder = new TypeDefinition("Fixtures", "Diagnostic", AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes.Public, module.CorLibTypeFactory.Object.Type);
    module.TopLevelTypes.Add(holder);
    MethodDefinition Emit(Fixture f, string name)
    {
        f.Owner.ReturnType = app.SystemTypes.SystemVoidType;
        f.Owner.ControlFlowGraph = new ISILControlFlowGraph([f.Call, new Instruction(100, OpCode.Return)]);
        var definition = new MethodDefinition(name, AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Public | AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Static,
            MethodSignature.CreateStatic(module.CorLibTypeFactory.Void)); holder.Methods.Add(definition);
        IlGenerator.GenerateIl(f.Owner, definition); return definition;
    }
    var diagnostic = Emit(Make(), "OriginalNativeHelperDiagnostic");
    var cil = diagnostic.CilMethodBody!.Instructions;
    Check("real emitter preserves exact unresolved helper diagnostic", cil.Count(i => i.OpCode == CilOpCodes.Ldstr && Equals(i.Operand, "Method not found @B04F60")) == 1
        && cil.Count(i => i.OpCode == CilOpCodes.Call) == 1);
    Check("emitter does not replace helper with Boolean true or managed cctor", !cil.Any(i => i.OpCode == CilOpCodes.Ldc_I4_1)
        && !cil.Any(i => i.Operand?.ToString()?.Contains("RunClassConstructor", StringComparison.Ordinal) == true));
    emitted.Add(new { name = diagnostic.Name?.ToString(), diagnostic_preserved = true, executed = false,
        instructions = cil.Select(i => new { opcode = i.OpCode.ToString(), operand = i.Operand?.ToString() }) });
    var stale = Make(); stale.Call.SetOperand(0, new Immediate(unchecked((long)target + 4))); bool refused = false;
    try { Emit(stale, "StaleTargetMustNotEmit"); } catch (InvalidOperationException) { refused = true; }
    Check("real emitter refuses stale carrier target", refused);
    Check("original input file hashes remain unchanged", Hash(binary) == "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
        && Hash(metadata) == "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85");
}
catch (Exception error) { fatal = error.ToString(); }
var report = new { status = fatal == null ? "PASS_EXACT_NATIVE_CLASS_LAYOUT_ABI_ONLY_CONTRACT" : "CLASS_LAYOUT_ABI_ONLY_CONTRACT_FAILED", checks, fatal, tests,
    core_sha256 = coreHash, original_binary_sha256 = Hash(binary), metadata_sha256 = Hash(metadata),
    probe_source_sha256 = Hash(Guard("src/re/ClassLayoutAbiContractProbe/Program.cs")),
    helper_source_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64ClassLayoutAbi.cs")),
    native_source_report_sha256 = Hash(Guard("reports/class-layout-runtime-source-v37.json")), native_oracle_report_sha256 = Hash(Guard("reports/native-class-layout-bool-v37.json")),
    target = "0xB04F60", helper_bytes = LegacyArm64ClassLayoutAbi.NativeBodySize, helper_sha256 = LegacyArm64ClassLayoutAbi.NativeBodySha256,
    derived_loaded_image_bytes = LegacyArm64ClassLayoutAbi.DerivedLoadedImageSize, derived_loaded_image_sha256 = LegacyArm64ClassLayoutAbi.DerivedLoadedImageSha256,
    ssa_result_version = ssaResultVersion, ssa_class_source_version = ssaClassVersion, original_reader_raw_sites = rawSites,
    emitted_diagnostic_fixtures = emitted, core_modified = false, original_inputs_modified = false, recovered_output_modified = false,
    native_code_executed = false, recovered_game_methods_executed = 0, cold_layout_effects_implemented = false, managed_cctor_substituted = false,
    scope = "Original input metadata and exact derived-image/frame guards plus independent raw-ISIL/SSA/local/resolver/emitter fixtures. Copied image negatives and temporary synthetic alias dictionaries are in-process only and restored; no game output or inputs are changed. Deliberately invalid native class inputs test resolver exclusion only and are never executed. Four original reader call sites are inspected before analysis to verify production signature capture. The real emitter preserves an unresolved helper diagnostic and is never invoked as executable game behavior. Native initialized-path evidence is bound separately; cold layout setup, locking, assertion termination, exceptions and managed execution remain unproved." };
File.WriteAllText(Guard("reports/class-layout-abi-contract-v37.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { report.status, checks, fatal }));
return fatal == null ? 0 : 2;

record Fixture(InjectedMethodAnalysisContext Owner, Instruction Call, LocalVariable Result, LocalVariable Class, Instruction Setup);
