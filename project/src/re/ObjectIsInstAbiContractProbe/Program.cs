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
if (!string.Equals(root, @"F:\SF2SwitchPC", StringComparison.OrdinalIgnoreCase)) throw new IOException("Unexpected USB workspace");
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point");
    return path;
}
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
string BytesHash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
var tests = new List<object>(); var rawSites = new List<object>(); var emitted = new List<object>(); string? fatal = null;
int sourceVersion = -1, resultVersion = -1, classVersion = -1;
void Check(string name, bool pass) { tests.Add(new { name, status = pass ? "PASS" : "FAIL" }); if (!pass) throw new InvalidDataException(name); }
string binary = Guard("unpacked/effective/exefs/main"), metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
string coreHash = Hash(typeof(Cpp2IlApi).Assembly.Location);
try
{
    Check("exact reviewed v40 Core", coreHash == "14232d46ca291ffb67944705e94ec5460bc8ee70c3df88ee3ef27e77b6e736d6");
    Check("original local input hashes", Hash(binary) == "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
        && Hash(metadata) == "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85");
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
    Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
    Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
    var app = Cpp2IlApi.CurrentAppContext!;
    var objectType = app.SystemTypes.SystemObjectType;
    var profile = app.AllTypes.Single(t => t.FullName == "InControl.PlayStation4MacBTProfile");
    ulong target = LegacyArm64ObjectIsInstAbi.Target;
    Check("exact target and nominal mscorlib Object metadata", target == 0xB5B390 && objectType.FullName == "System.Object"
        && ReferenceEquals(objectType.DeclaringAssembly, app.GetAssemblyByName("mscorlib")) && LegacyArm64ObjectIsInstAbi.IsKnownTarget(app, target));
    Check("interior/zero/other runtime helpers reject", !LegacyArm64ObjectIsInstAbi.IsKnownTarget(app, target + 4)
        && !LegacyArm64ObjectIsInstAbi.IsKnownTarget(app, 0) && !LegacyArm64ObjectIsInstAbi.IsKnownTarget(app, 0xB04F60)
        && !LegacyArm64ObjectIsInstAbi.IsKnownTarget(app, 0xB4D960));
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", null);
    Check("disabled opt-in rejects after cache populated", !LegacyArm64ObjectIsInstAbi.IsKnownTarget(app, target));
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
    Check("exact FDE is244bytes", LegacyArm64ValueThisThunks.TryGetExactBodyRange(app, target, out int size) && size == 244);
    Check("helper maps inside derived loaded image", app.Binary.TryMapVirtualAddressToRaw(target, out var raw));
    var image = app.Binary.GetRawBinaryContent().ToArray();
    Check("derived relocated image identity remains explicit", image.Length == LegacyArm64ClassLayoutAbi.DerivedLoadedImageSize
        && BytesHash(image) == LegacyArm64ClassLayoutAbi.DerivedLoadedImageSha256);
    Check("exact image/frame/body guard accepts", LegacyArm64ObjectIsInstAbi.MatchesReviewedImage(image, raw, size));
    foreach (int frame in new[] { 0, 240, 248 }) Check("wrong frame rejects:" + frame, !LegacyArm64ObjectIsInstAbi.MatchesReviewedImage(image, raw, frame));
    foreach (long offset in new[] { -1L, long.MaxValue, image.Length }) Check("invalid raw offset rejects:" + offset, !LegacyArm64ObjectIsInstAbi.MatchesReviewedImage(image, offset, size));
    Check("truncated image rejects", !LegacyArm64ObjectIsInstAbi.MatchesReviewedImage(image.AsSpan(0, image.Length - 1), raw, size));
    var changed = image.ToArray(); changed[checked((int)raw)] ^= 1;
    Check("copied changed helper byte rejects", !LegacyArm64ObjectIsInstAbi.MatchesReviewedImage(changed, raw, size));
    changed[checked((int)raw)] ^= 1; changed[0] ^= 1;
    Check("copied changed nonhelper image byte rejects", !LegacyArm64ObjectIsInstAbi.MatchesReviewedImage(changed, raw, size));
    Check("application image is unmodified", BytesHash(app.Binary.GetRawBinaryContent()) == LegacyArm64ClassLayoutAbi.DerivedLoadedImageSha256);
    int serial = 0;
    Fixture Make(bool seed = true, bool unused = false)
    {
        var owner = new InjectedMethodAnalysisContext(profile, "IsInstAbiFixture" + serial++, unused ? app.SystemTypes.SystemVoidType : objectType,
            MethodAttributes.Public | MethodAttributes.Static, []);
        var call = LegacyArm64ObjectIsInstAbi.CreateCall(owner, 2, target) ?? throw new InvalidDataException("Known helper rejected");
        var setupObject = new Instruction(0, OpCode.Move, new Register(null, "X0"), new Immediate(0x11111110L));
        var setupClass = new Instruction(1, OpCode.Move, new Register(null, "X1"), new Immediate(0x22222220L));
        owner.ControlFlowGraph = new ISILControlFlowGraph([setupObject, setupClass, call,
            unused ? new Instruction(3, OpCode.Return) : new Instruction(3, OpCode.Return, new Register(null, "X0"))]);
        owner.DominatorInfo = new DominatorInfo(owner.ControlFlowGraph);
        SsaForm.Build(owner); LocalVariables.CreateAll(owner);
        if (seed) LegacyArm64ObjectIsInstAbi.SeedResults(owner);
        return new(owner, call, (LocalVariable)call.Operands[1], (LocalVariable)call.Operands[2], (LocalVariable)call.Operands[3], setupObject, setupClass);
    }
    var f = Make(); sourceVersion = f.Object.Register.Version; resultVersion = f.Result.Register.Version; classVersion = f.Class.Register.Version;
    Check("four raw ABI operands survive SSA as distinct X0 input/result plus X1class", f.Call.Operands.Count == 4 && f.Call.Sources.Count == 2
        && f.Result.Register.Name == "X0" && f.Object.Register.Name == "X0" && f.Class.Register.Name == "X1"
        && !ReferenceEquals(f.Result, f.Object) && f.Result.Register.Version > f.Object.Register.Version);
    Check("both original source values retained by identity", ReferenceEquals(f.SetupObject.Destination, f.Object) && ReferenceEquals(f.SetupClass.Destination, f.Class)
        && ReferenceEquals(f.Call.Sources[0], f.Object) && ReferenceEquals(f.Call.Sources[1], f.Class)
        && f.SetupObject.Operands[1] is Immediate o && o.UnsignedValue == 0x11111110
        && f.SetupClass.Operands[1] is Immediate c && c.UnsignedValue == 0x22222220);
    Check("nominal canonical Object result reaches original return", ReferenceEquals(f.Result.Type, objectType)
        && ReferenceEquals(f.Owner.ControlFlowGraph!.Instructions.Single(i => i.OpCode == OpCode.Return).Operands[0], f.Result));
    Check("unknown then canonical Object seeds without semantic narrowing", LegacyArm64ObjectIsInstAbi.SeedResults(f.Owner) == 1
        && LegacyArm64ObjectIsInstAbi.ValidForEmission(f.Call, f.Owner));
    var unused = Make(unused: true); DeadCodeEliminator.Run(unused.Owner);
    Check("unused result retains effectful numeric helper call", unused.Owner.ControlFlowGraph!.Instructions.Contains(unused.Call)
        && unused.Call.OpCode == OpCode.Call && unused.Call.Operands.Count == 4);
    var clone = new Instruction(f.Call.Index, f.Call.OpCode, f.Call.Operands.ToList()) { NativeObjectIsInstAbi = f.Call.NativeObjectIsInstAbi };
    Check("clone preserves immutable carrier and typed ABI", !ReferenceEquals(clone, f.Call) && ReferenceEquals(clone.NativeObjectIsInstAbi, f.Call.NativeObjectIsInstAbi)
        && LegacyArm64ObjectIsInstAbi.ValidForEmission(clone, f.Owner));
    Check("real indirect-return clone explicitly carries proof", File.ReadAllText(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64IndirectReturns.cs"))
        .Contains("NativeObjectIsInstAbi = row.NativeObjectIsInstAbi", StringComparison.Ordinal));
    Check("foreign owner rejects carrier", !LegacyArm64ObjectIsInstAbi.IsProvenCall(Make().Owner, f.Call));
    Check("wrong address cannot create narrowed call", LegacyArm64ObjectIsInstAbi.CreateCall(f.Owner, 9, target + 4) == null);
    foreach (var (name, mutate) in new (string, Action<Fixture>)[] {
        ("target", x => x.Call.SetOperand(0, new Immediate(unchecked((long)target + 4)))),
        ("opcode", x => x.Call.OpCode = OpCode.CallVoid), ("missing source", x => x.Call.RemoveOperandAt(3)),
        ("extra source", x => x.Call.AddOperands([new Immediate(0L)])), ("carrier", x => x.Call.NativeObjectIsInstAbi = null),
        ("result type", x => x.Result.Type = app.SystemTypes.SystemInt32Type), ("result operand", x => x.Call.SetOperand(1, new Immediate(0L))) })
    { var x = Make(); mutate(x); Check("stale " + name + " rejects emission", !LegacyArm64ObjectIsInstAbi.ValidForEmission(x.Call, x.Owner)); }
    foreach (var (name, mutate) in new (string, Action<Fixture>)[] {
        ("conflicting Int32", x => x.Result.Type = app.SystemTypes.SystemInt32Type),
        ("conflicting Boolean", x => x.Result.Type = app.SystemTypes.SystemBooleanType),
        ("noncanonical Object context", x => x.Result.Type = new TypeAnalysisContext(objectType.Definition, objectType.DeclaringAssembly)),
        ("wrong result register", x => x.Call.SetOperand(1, new LocalVariable("wrong", new Register(null, "X2")))),
        ("wrong object register", x => x.Call.SetOperand(2, new LocalVariable("wrong", new Register(null, "X2")))),
        ("wrong class register", x => x.Call.SetOperand(3, new LocalVariable("wrong", new Register(null, "X2")))),
        ("shared result/source identity", x => x.Call.SetOperand(1, x.Object)),
        ("stale target", x => x.Call.SetOperand(0, new Immediate(unchecked((long)target + 4)))) })
    {
        var x = Make(false); mutate(x); bool rejected = false;
        try { LegacyArm64ObjectIsInstAbi.SeedResults(x.Owner); } catch (InvalidOperationException) { rejected = true; }
        Check(name + " fails closed during initial SSA seed", rejected);
    }
    bool StillNative(Fixture x) => x.Call.OpCode == OpCode.Call && x.Call.Operands.Count == 4 && x.Call.Operands[0] is Immediate t
        && t.UnsignedValue == target && LegacyArm64ObjectIsInstAbi.IsProvenCall(x.Owner, x.Call);
    void PrivateRoute(string name, Fixture x) => typeof(MetadataResolver).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, [x.Owner]);
    var oldAliases = app.MethodsByAddress.GetValueOrDefault(target);
    var alias = new InjectedMethodAnalysisContext(profile, "SyntheticIsInstAlias", objectType, MethodAttributes.Public | MethodAttributes.Static, []);
    var alias2 = new InjectedMethodAnalysisContext(profile, "SyntheticIsInstAlias2", objectType, MethodAttributes.Public | MethodAttributes.Static, []);
    try
    {
        app.MethodsByAddress[target] = [alias]; var x = Make(); PrivateRoute("ResolveCalls", x);
        Check("single managed alias cannot capture helper", StillNative(x));
        app.MethodsByAddress[target] = [alias, alias2]; x = Make(); MetadataResolver.ResolveAmbiguousCalls(x.Owner);
        Check("ambiguous managed aliases cannot capture helper", StillNative(x));
        app.MethodsByAddress.Remove(target); x = Make(); x.Call.SetOperand(3, new RuntimeMethodInfoAnalysisContext(alias, profile.DeclaringAssembly));
        MetadataResolver.ResolveCallsViaMethodInfo(x.Owner); Check("MethodInfo route cannot capture helper", StillNative(x));
        var ctor = new InjectedMethodAnalysisContext(profile, ".ctor", app.SystemTypes.SystemVoidType, MethodAttributes.Public, []);
        app.MethodsByAddress[target] = [ctor]; x = Make(); x.Object.Type = profile; x.SetupObject.OpCode = OpCode.Newobj; x.SetupObject.SetOperands(x.Object, profile);
        MetadataResolver.ResolveConstructorCalls(x.Owner); Check("constructor route cannot capture helper", StillNative(x));
        var literal = app.LibCpp2IlContext.Metadata.metadataUsageDic![(uint)MetadataUsageType.StringLiteral].First();
        ulong slot = app.Binary.GetRawMetadataUsage(literal.Key);
        Check("literal negative uses real registered slot", app.LibCpp2IlContext.GetLiteralByAddress(slot) != null);
        x = Make(); x.Call.SetOperand(3, new Immediate(unchecked((long)slot))); PrivateRoute("ResolveStringLiteralAccessors", x);
        Check("string-literal route cannot erase helper", StillNative(x));
        app.MethodsByAddress[target] = [alias];
        var original = app.MethodsByAddress[0x11A4CC0].Single(m => ReferenceEquals(m.DeclaringType, profile) && m.Name == ".ctor");
        var rawRows = app.InstructionSet.GetIsilFromMethod(original);
        var calls = rawRows.Where(i => i.IsCall && i.Operands[0] is Immediate t && t.UnsignedValue == target).ToArray();
        Check("all28 actual original native calls use narrowed ABI before alias selection", calls.Length == 28 && calls.All(i =>
            i.Operands is [Immediate, Register { Name: "X0" }, Register { Name: "X0" }, Register { Name: "X1" }]
            && LegacyArm64ObjectIsInstAbi.IsProvenCall(original, i)));
        rawSites.AddRange(calls.Select(i => (object)new { index = i.Index, operand_count = i.Operands.Count,
            original_object_register = "X0", original_class_register = "X1", nominal_result_register = "X0" }));
    }
    finally { if (oldAliases == null) app.MethodsByAddress.Remove(target); else app.MethodsByAddress[target] = oldAliases; }

    var corlib = ModuleDefinition.FromFile(typeof(object).Assembly.Location);
    objectType.PutExtraData("AsmResolverType", corlib.TopLevelTypes.Single(t => t.FullName == "System.Object"));
    app.SystemTypes.SystemBooleanType.PutExtraData("AsmResolverType", corlib.TopLevelTypes.Single(t => t.FullName == "System.Boolean"));
    var module = new ModuleDefinition("IsInstAbiDiagnosticFixture.dll"); var outputAssembly = new AssemblyDefinition("IsInstAbiDiagnosticFixture", new Version(1, 0)); outputAssembly.Modules.Add(module);
    var holder = new TypeDefinition("Fixtures", "Diagnostic", AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes.Public, module.CorLibTypeFactory.Object.Type); module.TopLevelTypes.Add(holder);
    MethodDefinition Emit(Fixture x, string name)
    {
        x.Owner.ReturnType = app.SystemTypes.SystemVoidType;
        x.Owner.ControlFlowGraph = new ISILControlFlowGraph([x.Call, new Instruction(100, OpCode.Return)]);
        var definition = new MethodDefinition(name, AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Public | AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Static,
            MethodSignature.CreateStatic(module.CorLibTypeFactory.Void)); holder.Methods.Add(definition); IlGenerator.GenerateIl(x.Owner, definition); return definition;
    }
    var diagnostic = Emit(Make(unused: true), "OriginalHelperDiagnosticRetained"); var cil = diagnostic.CilMethodBody!.Instructions;
    Check("real emitter retains exact numeric helper diagnostic", cil.Count(i => i.OpCode == CilOpCodes.Ldstr && Equals(i.Operand, "Method not found @B5B390")) == 1
        && cil.Count(i => i.OpCode == CilOpCodes.Call) == 1);
    Check("emitter introduces no semantic isinst/array-store/null/constant result", !cil.Any(i => i.OpCode == CilOpCodes.Isinst || i.OpCode == CilOpCodes.Stelem_Ref
        || i.OpCode == CilOpCodes.Ldnull || i.OpCode.Code.ToString().StartsWith("Ldc", StringComparison.Ordinal) || i.OpCode == CilOpCodes.Newobj));
    emitted.Add(new { name = diagnostic.Name?.ToString(), numeric_diagnostic_retained = true, semantic_helper_executed = false,
        instructions = cil.Select(i => new { opcode = i.OpCode.ToString(), operand = i.Operand?.ToString() }) });
    foreach (var (name, mutate) in new (string, Action<Fixture>)[] {
        ("target", x => x.Call.SetOperand(0, new Immediate(unchecked((long)target + 4)))), ("opcode", x => x.Call.OpCode = OpCode.CallVoid),
        ("shape", x => x.Call.RemoveOperandAt(3)), ("result", x => x.Result.Type = app.SystemTypes.SystemBooleanType) })
    {
        var x = Make(); mutate(x); bool rejected = false;
        try { Emit(x, "Stale" + name); } catch (InvalidOperationException e) when (e.Message.Contains("Object::IsInst ABI", StringComparison.Ordinal)) { rejected = true; }
        Check("real emitter rejects stale " + name + " carrier", rejected);
    }
    Check("input files still match original hashes", Hash(binary) == "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
        && Hash(metadata) == "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85");
}
catch (Exception error) { fatal = error.ToString(); }
var report = new { status = fatal == null ? "PASS_EXACT_OBJECT_ISINST_ABI_ONLY_CONTRACT" : "OBJECT_ISINST_ABI_CONTRACT_FAILED", checks = tests.Count, tests, fatal,
    core_sha256 = coreHash, source_sha256 = Hash(Guard("src/re/ObjectIsInstAbiContractProbe/Program.cs")),
    helper_source_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64ObjectIsInstAbi.cs")),
    original_binary_sha256 = Hash(binary), original_metadata_sha256 = Hash(metadata),
    native_source_report_sha256 = Hash(Guard("reports/object-isinst-official-source-v40.json")),
    native_wrapper_oracle_sha256 = Hash(Guard("reports/native-object-isinst-abi-v40.json")),
    target = "0xB5B390", native_bytes = LegacyArm64ObjectIsInstAbi.NativeBodySize, native_sha256 = LegacyArm64ObjectIsInstAbi.NativeBodySha256,
    original_object_ssa_version = sourceVersion, original_class_ssa_version = classVersion, result_ssa_version = resultVersion,
    raw_original_profile_sites = rawSites, emitted_diagnostic_fixtures = emitted,
    semantic_isinst_recovered = false, class_provenance_recovered = false, original_game_methods_invoked = 0,
    native_helpers_executed_by_this_probe = 0, original_outputs_modified = false,
    scope = "Exact signature shield only: original X0 object plus X1 class inputs and distinct canonical nominal Object result. Initial SSA register/type identity guards, alias exclusions, raw28-call captures, carrier clone and stale emitter checks are independent fixtures. Final emission checks owner/target/Call4shape/Object result; arbitrary post-SSA source mutation is not prohibited or promoted to provenance proof. The numeric diagnostic remains; no semantic IsInst, assignability, CLR type test, array-store fusion, object/default return or COM/error recovery is implemented or executed. Supplied pointer-shaped operands test ABI/alias exclusion only and never execute game/native code. Native wrapper oracle is a separate supplied-assignability boundary." };
File.WriteAllText(Guard("reports/object-isinst-abi-contract-v40.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { report.status, report.checks, fatal }));
return fatal == null ? 0 : 2;

record Fixture(InjectedMethodAnalysisContext Owner, Instruction Call, LocalVariable Result, LocalVariable Object, LocalVariable Class, Instruction SetupObject, Instruction SetupClass);
