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
var tests = new List<object>(); var rawSites = new List<object>(); var emitted = new List<object>(); var overflowSites = new List<object>();
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
    Check("exact final dual-helper Core identity", coreHash == "36d9e25cb26d4b51881a29cb23dfb613de4e14582a6abe6e184b7b8c415026eb");
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

    ulong overflowTarget = LegacyArm64OverflowExceptionAbi.Target;
    var exception = app.SystemTypes.SystemExceptionType;
    Check("overflow helper exact target and canonical base metadata", overflowTarget == 0xB4D960
        && exception.FullName == "System.Exception" && ReferenceEquals(exception.DeclaringAssembly, app.GetAssemblyByName("mscorlib"))
        && LegacyArm64OverflowExceptionAbi.IsKnownTarget(app, overflowTarget));
    Check("overflow helper rejects class-layout and cctor addresses", !LegacyArm64OverflowExceptionAbi.IsKnownTarget(app, target)
        && !LegacyArm64OverflowExceptionAbi.IsKnownTarget(app, 0xB2E720));
    Check("overflow helper rejects interior and zero addresses", !LegacyArm64OverflowExceptionAbi.IsKnownTarget(app, overflowTarget + 4)
        && !LegacyArm64OverflowExceptionAbi.IsKnownTarget(app, 0));
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", null);
    Check("overflow disabled opt-in rejects after cache populated", !LegacyArm64OverflowExceptionAbi.IsKnownTarget(app, overflowTarget));
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
    Check("overflow exact frame is 52 bytes", LegacyArm64ValueThisThunks.TryGetExactBodyRange(app, overflowTarget, out int overflowSize) && overflowSize == 52);
    Check("overflow maps into original loaded image", app.Binary.TryMapVirtualAddressToRaw(overflowTarget, out var overflowRaw));
    Check("overflow exact immutable image guard accepts", LegacyArm64OverflowExceptionAbi.MatchesReviewedImage(image, overflowRaw, overflowSize));
    foreach (var (name, at, length) in new[] { ("short frame", overflowRaw, 48), ("long frame", overflowRaw, 56),
        ("negative offset", -1L, overflowSize), ("overflow offset", long.MaxValue, overflowSize), ("out-of-range offset", (long)image.Length, overflowSize) })
        Check("overflow " + name + " rejected", !LegacyArm64OverflowExceptionAbi.MatchesReviewedImage(image, at, length));
    Check("overflow truncated image rejected", !LegacyArm64OverflowExceptionAbi.MatchesReviewedImage(image.AsSpan(0, image.Length - 1), overflowRaw, overflowSize));
    image.CopyTo(altered, 0); altered[checked((int)overflowRaw)] ^= 1;
    Check("overflow changed native byte rejected on copy", !LegacyArm64OverflowExceptionAbi.MatchesReviewedImage(altered, overflowRaw, overflowSize));
    altered[checked((int)overflowRaw)] ^= 1; altered[0] ^= 1;
    Check("overflow unrelated image-byte change rejected on copy", !LegacyArm64OverflowExceptionAbi.MatchesReviewedImage(altered, overflowRaw, overflowSize));
    Fixture FactoryMake(bool seed = true)
    {
        var owner = new InjectedMethodAnalysisContext(reader, "OverflowAbiFixture" + serial++, exception, MethodAttributes.Public | MethodAttributes.Static, []);
        var call = LegacyArm64OverflowExceptionAbi.CreateCall(owner, 1, overflowTarget) ?? throw new InvalidDataException("Exact overflow call rejected");
        var setup = new Instruction(0, OpCode.Move, new Register(null, "X0"), new Immediate(0x12345000L));
        owner.ControlFlowGraph = new ISILControlFlowGraph([setup, call, new Instruction(2, OpCode.Return, new Register(null, "X0"))]);
        owner.DominatorInfo = new DominatorInfo(owner.ControlFlowGraph);
        SsaForm.Build(owner); LocalVariables.CreateAll(owner);
        if (seed) LegacyArm64OverflowExceptionAbi.SeedResults(owner);
        return new(owner, call, (LocalVariable)call.Operands[1], (LocalVariable)call.Operands[2], setup);
    }
    var factory = FactoryMake();
    Check("overflow one native pointer input and distinct original X0 result survive SSA", factory.Call.Operands.Count == 3
        && factory.Call.Sources.Count == 1 && ReferenceEquals(factory.Call.Sources[0], factory.Class)
        && factory.Result.Register.Name == "X0" && factory.Class.Register.Name == "X0"
        && factory.Result.Register.Version > factory.Class.Register.Version && !ReferenceEquals(factory.Result, factory.Class));
    Check("overflow native message pointer is preserved without string conversion", ReferenceEquals(factory.Setup.Destination, factory.Class)
        && factory.Setup.Operands[1] is Immediate pointer && pointer.UnsignedValue == 0x12345000);
    Check("overflow result is exact base Exception and original live return", ReferenceEquals(factory.Result.Type, exception)
        && factory.Owner.ControlFlowGraph!.Instructions.Single(i => i.OpCode == OpCode.Return).Operands is [LocalVariable ret] && ReferenceEquals(ret, factory.Result));
    DeadCodeEliminator.Run(factory.Owner);
    Check("overflow effectful helper survives DCE", factory.Owner.ControlFlowGraph!.Instructions.Contains(factory.Call) && factory.Call.OpCode == OpCode.Call);
    Check("overflow base result retains diagnostic emission eligibility", LegacyArm64OverflowExceptionAbi.ValidForEmission(factory.Call, factory.Owner));
    var factoryClone = new Instruction(factory.Call.Index, factory.Call.OpCode, factory.Call.Operands.ToList()) { NativeOverflowExceptionAbi = factory.Call.NativeOverflowExceptionAbi };
    Check("overflow clone preserves distinct immutable carrier", !ReferenceEquals(factoryClone, factory.Call)
        && ReferenceEquals(factoryClone.NativeOverflowExceptionAbi, factory.Call.NativeOverflowExceptionAbi)
        && factoryClone.NativeClassLayoutAbi == null && LegacyArm64OverflowExceptionAbi.ValidForEmission(factoryClone, factory.Owner));
    Check("production clone preserves overflow carrier", File.ReadAllText(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64IndirectReturns.cs"))
        .Contains("NativeOverflowExceptionAbi = row.NativeOverflowExceptionAbi", StringComparison.Ordinal));
    Check("overflow wrong owner rejects", !LegacyArm64OverflowExceptionAbi.IsProvenCall(Make().Owner, factory.Call));
    Check("overflow wrong target never creates call", LegacyArm64OverflowExceptionAbi.CreateCall(factory.Owner, 3, target) == null);
    foreach (var (name, mutate) in new (string, Action<Fixture>)[] {
        ("stale target", f => f.Call.SetOperand(0, new Immediate(unchecked((long)overflowTarget + 4)))),
        ("stale void opcode", f => f.Call.OpCode = OpCode.CallVoid),
        ("missing message argument", f => f.Call.RemoveOperandAt(2)),
        ("extra stale MethodInfo input", f => f.Call.AddOperands([new LocalVariable("stale", new Register(null, "X1"))])),
        ("missing carrier", f => f.Call.NativeOverflowExceptionAbi = null),
        ("wrong Boolean result", f => f.Result.Type = boolean),
    }) { var f = FactoryMake(); mutate(f); Check("overflow " + name + " rejects emission", !LegacyArm64OverflowExceptionAbi.ValidForEmission(f.Call, f.Owner)); }
    foreach (var (name, mutate) in new (string, Action<Fixture>)[] {
        ("conflicting prior type", f => f.Result.Type = boolean),
        ("wrong result register", f => f.Call.SetOperand(1, new LocalVariable("other", new Register(null, "X2")))),
        ("wrong message register", f => f.Call.SetOperand(2, new LocalVariable("other", new Register(null, "X1")))),
        ("stale target", f => f.Call.SetOperand(0, new Immediate(unchecked((long)overflowTarget + 4)))),
    }) { var f = FactoryMake(false); mutate(f); bool rejected = false; try { LegacyArm64OverflowExceptionAbi.SeedResults(f.Owner); }
        catch (InvalidOperationException) { rejected = true; } Check("overflow " + name + " fails closed at SSA seed", rejected); }
    bool IsStillFactory(Fixture f) => f.Call.OpCode == OpCode.Call && f.Call.Operands is [Immediate t, _, _]
        && t.UnsignedValue == overflowTarget && LegacyArm64OverflowExceptionAbi.IsProvenCall(f.Owner, f.Call);
    var oldFactoryAliases = app.MethodsByAddress.GetValueOrDefault(overflowTarget);
    try
    {
        app.MethodsByAddress[overflowTarget] = [aliasA]; var f = FactoryMake(); InvokePrivate("ResolveCalls", f.Owner);
        Check("overflow single managed alias excluded", IsStillFactory(f));
        app.MethodsByAddress[overflowTarget] = [aliasA, aliasB]; f = FactoryMake(); MetadataResolver.ResolveAmbiguousCalls(f.Owner);
        Check("overflow interchangeable managed aliases excluded", IsStillFactory(f));
        app.MethodsByAddress.Remove(overflowTarget); f = FactoryMake();
        f.Call.SetOperand(2, new RuntimeMethodInfoAnalysisContext(aliasA, reader.DeclaringAssembly)); MetadataResolver.ResolveCallsViaMethodInfo(f.Owner);
        Check("overflow stale MethodInfo cannot substitute managed method", IsStillFactory(f));
        var ctor = new InjectedMethodAnalysisContext(reader, ".ctor", app.SystemTypes.SystemVoidType, MethodAttributes.Public, []);
        app.MethodsByAddress[overflowTarget] = [ctor]; f = FactoryMake(); f.Class.Type = reader; f.Setup.OpCode = OpCode.Newobj; f.Setup.SetOperands(f.Class, reader);
        MetadataResolver.ResolveConstructorCalls(f.Owner); Check("overflow synthetic allocation cannot reinterpret helper as ctor", IsStillFactory(f));
        var literal = app.LibCpp2IlContext.Metadata.metadataUsageDic![(uint)MetadataUsageType.StringLiteral].First();
        f = FactoryMake(); f.Call.SetOperand(2, new Immediate(unchecked((long)app.Binary.GetRawMetadataUsage(literal.Key))));
        InvokePrivate("ResolveStringLiteralAccessors", f.Owner); Check("overflow literal slot cannot erase effectful factory", IsStillFactory(f));
        app.MethodsByAddress[overflowTarget] = [aliasA];
        var method = app.MethodsByAddress[0x4A0D70].Single(m => m.DeclaringType?.FullName == reader.FullName && m.Name == "Read");
        var raw = app.InstructionSet.GetIsilFromMethod(method);
        var calls = raw.Where(i => i.IsCall && i.Operands[0] is Immediate t && t.UnsignedValue == overflowTarget).ToArray();
        Check("actual original reader preserves one factory signature before alias selection", calls.Length == 1
            && calls.All(c => c.Operands is [Immediate, Register { Name: "X0" }, Register { Name: "X0" }]
                && LegacyArm64OverflowExceptionAbi.IsProvenCall(method, c)));
        overflowSites.AddRange(calls.Select(c => (object)new { index = c.Index, operands = c.Operands.Count,
            input_register = "X0", result_register = "X0", native_message_pointer_not_converted = true, managed_alias_bypassed = true }));
    }
    finally { if (oldFactoryAliases == null) app.MethodsByAddress.Remove(overflowTarget); else app.MethodsByAddress[overflowTarget] = oldFactoryAliases; }

    var corlib = ModuleDefinition.FromFile(typeof(bool).Assembly.Location);
    boolean.PutExtraData("AsmResolverType", corlib.TopLevelTypes.Single(t => t.FullName == "System.Boolean"));
    exception.PutExtraData("AsmResolverType", corlib.TopLevelTypes.Single(t => t.FullName == "System.Exception"));
    var module = new ModuleDefinition("ClassLayoutAbiDiagnosticFixture.dll");
    var assembly = new AssemblyDefinition("ClassLayoutAbiDiagnosticFixture", new Version(1, 0)); assembly.Modules.Add(module);
    var holder = new TypeDefinition("Fixtures", "Diagnostic", AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes.Public, module.CorLibTypeFactory.Object.Type);
    module.TopLevelTypes.Add(holder);
    MethodDefinition Emit(Fixture f, string name, bool throwResult = false)
    {
        f.Owner.ReturnType = app.SystemTypes.SystemVoidType;
        f.Owner.ControlFlowGraph = new ISILControlFlowGraph([f.Call, throwResult ? new Instruction(100, OpCode.Throw, f.Result) : new Instruction(100, OpCode.Return)]);
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
    var factoryDiagnostic = Emit(FactoryMake(), "OverflowFactoryDiagnosticThenOriginalThrow", true);
    var factoryCil = factoryDiagnostic.CilMethodBody!.Instructions;
    Check("real emitter retains factory diagnostic and subsequent throw", factoryCil.Count(i => i.OpCode == CilOpCodes.Ldstr && Equals(i.Operand, "Method not found @B4D960")) == 1
        && factoryCil.Count(i => i.OpCode == CilOpCodes.Call) == 1 && factoryCil.Count(i => i.OpCode == CilOpCodes.Throw) == 1);
    Check("real emitter does not invent exception constructor or native-message conversion", !factoryCil.Any(i => i.OpCode == CilOpCodes.Newobj)
        && !factoryCil.Any(i => i.Operand?.ToString()?.Contains("GetString", StringComparison.Ordinal) == true));
    emitted.Add(new { name = factoryDiagnostic.Name?.ToString(), diagnostic_preserved = true, subsequent_throw_preserved = true, executed = false,
        instructions = factoryCil.Select(i => new { opcode = i.OpCode.ToString(), operand = i.Operand?.ToString() }) });
    var staleFactory = FactoryMake(); staleFactory.Call.SetOperand(0, new Immediate(unchecked((long)overflowTarget + 4))); refused = false;
    try { Emit(staleFactory, "StaleOverflowTargetMustNotEmit", true); }
    catch (InvalidOperationException error) when (error.Message == "Stale or invalid reviewed native overflow-factory ABI") { refused = true; }
    Check("real emitter rejects stale overflow carrier target", refused);
    var mixed = FactoryMake(); mixed.Call.NativeClassLayoutAbi = new(mixed.Owner, target); refused = false;
    try { Emit(mixed, "MixedCarrierMustNotEmit", true); }
    catch (InvalidOperationException error) when (error.Message == "Stale or invalid reviewed native class-layout ABI") { refused = true; }
    Check("real emitter rejects cross-helper carrier mixing", refused);
    Check("original input file hashes remain unchanged", Hash(binary) == "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
        && Hash(metadata) == "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85");
}
catch (Exception error) { fatal = error.ToString(); }
var report = new { status = fatal == null ? "PASS_EXACT_NATIVE_RUNTIME_HELPER_ABI_ONLY_CONTRACTS" : "RUNTIME_HELPER_ABI_ONLY_CONTRACTS_FAILED", checks, fatal, tests,
    core_sha256 = coreHash, original_binary_sha256 = Hash(binary), metadata_sha256 = Hash(metadata),
    probe_source_sha256 = Hash(Guard("src/re/RuntimeHelperAbiContractProbe/Program.cs")),
    helper_source_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64ClassLayoutAbi.cs")),
    overflow_helper_source_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64OverflowExceptionAbi.cs")),
    overflow_native_source_report_sha256 = Hash(Guard("reports/exception-factory-native-source-inventory-v37.json")),
    native_source_report_sha256 = Hash(Guard("reports/class-layout-runtime-source-v37.json")), native_oracle_report_sha256 = Hash(Guard("reports/native-class-layout-bool-v37.json")),
    target = "0xB04F60", helper_bytes = LegacyArm64ClassLayoutAbi.NativeBodySize, helper_sha256 = LegacyArm64ClassLayoutAbi.NativeBodySha256,
    derived_loaded_image_bytes = LegacyArm64ClassLayoutAbi.DerivedLoadedImageSize, derived_loaded_image_sha256 = LegacyArm64ClassLayoutAbi.DerivedLoadedImageSha256,
    ssa_result_version = ssaResultVersion, ssa_class_source_version = ssaClassVersion, original_reader_raw_sites = rawSites,
    overflow_helper = new { target = "0xB4D960", bytes = LegacyArm64OverflowExceptionAbi.NativeBodySize,
        sha256 = LegacyArm64OverflowExceptionAbi.NativeBodySha256, result_type = "mscorlib:System.Exception", native_const_char_message_input = "X0", original_reader_raw_sites = overflowSites },
    emitted_diagnostic_fixtures = emitted, core_modified = false, original_inputs_modified = false, recovered_output_modified = false,
    native_code_executed = false, recovered_game_methods_executed = 0, cold_layout_effects_implemented = false, managed_cctor_substituted = false,
    scope = "Two distinct exact native helper ABI contracts only: Class::Init(Il2CppClass*) returns Boolean; GetOverflowException(const char*) returns canonical base Exception. Original input metadata/image guards and independent raw-ISIL/SSA/local/resolver/emitter fixtures preserve original X0 input/result identities. Copied image negatives and temporary synthetic aliases are in-process and restored. Invalid native-pointer inputs test resolver exclusion only and never execute. Four class-layout sites and one factory site in the original reader are inspected before analysis. Real emission retains both numeric helper diagnostics and a factory-result throw; no helper is implemented, converted to a managed constructor, UTF-8-decoded or executed. Native initialized-layout evidence is separate. Cold layout, factory construction/message storage, locking, unwinding, assertion termination and actual recovered execution remain unproved." };
File.WriteAllText(Guard("reports/runtime-helper-abi-contract-v37.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { report.status, checks, fatal }));
return fatal == null ? 0 : 2;

record Fixture(InjectedMethodAnalysisContext Owner, Instruction Call, LocalVariable Result, LocalVariable Class, Instruction Setup);
