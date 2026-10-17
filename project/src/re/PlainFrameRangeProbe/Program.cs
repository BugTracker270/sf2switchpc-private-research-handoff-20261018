using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;
using LibCpp2IL.NintendoSwitch;

if (args.Length is < 1 or > 2 || args.Length == 2 && args[1] != "--inventory-only") throw new ArgumentException("Verified USB root and optional --inventory-only required");
bool inventoryOnly = args.Length == 2;
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? dir = new(Path.GetDirectoryName(path)!); dir != null; dir = dir.Parent)
        if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
string binary = Guard("unpacked/effective/exefs/main"), metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (Hash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Original source hashes differ");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
using var cieDoc = JsonDocument.Parse(File.ReadAllText(Guard("analysis/nso/unwind-inventory-v1/cies.json")));
var cies = cieDoc.RootElement.EnumerateArray().ToDictionary(e => e.GetProperty("rva").GetUInt64(), e => e.Clone());
var frames = new Dictionary<ulong, JsonElement>();
foreach (string line in File.ReadLines(Guard("analysis/nso/unwind-inventory-v1/frames.jsonl")))
{
    using var doc = JsonDocument.Parse(line); var row = doc.RootElement;
    frames.Add(row.GetProperty("rva").GetUInt64(), row.Clone());
}
bool Plain(JsonElement cie) => cie.GetProperty("augmentation").GetString() == "zR"
    && cie.GetProperty("lsda_encoding").GetInt32() == 255 && cie.GetProperty("personality").ValueKind == JsonValueKind.Null;
var mappings = LegacyArm64ValueThisThunks.AcceptedMappings(app);
var rows = mappings.Select(m =>
{
    var frame = frames[m.Address]; var cie = cies[frame.GetProperty("cie_rva").GetUInt64()];
    return new { method = m.Method.FullName, registered_address = $"0x{m.RegisteredAddress:X}", analysis_address = $"0x{m.Address:X}",
        exact_fde_bytes = m.Size, cie_augmentation = cie.GetProperty("augmentation").GetString(), plain_cie = Plain(cie) };
}).ToArray();
var tests = new List<object>();
string? ordinaryAnalysisError = null;
object? ordinaryProductionObservation = null;
void Check(string name, bool ok) => tests.Add(new { name, status = ok ? "PASS" : "FAIL" });
Check("original selected mappings remain287 unique bodies", mappings.Count == 287 && mappings.Select(m => m.Address).Distinct().Count() == 287);
Check("selected ranges agree with original unwind inventory", mappings.All(m => frames[m.Address].GetProperty("end_rva").GetUInt64() - m.Address == (ulong)m.Size));
if (!inventoryOnly)
{
    var helper = typeof(LegacyArm64ValueThisThunks);
    var methodApi = helper.GetMethod("TryGetExactPlainBodyRange", [typeof(MethodAnalysisContext), typeof(int).MakeByRefType()]);
    var addressApi = helper.GetMethod("TryGetExactPlainBodyRange", [typeof(ApplicationAnalysisContext), typeof(ulong), typeof(int).MakeByRefType()]);
    Check("both additive plain-range APIs present", methodApi != null && addressApi != null);
    (bool Ok, int Size) Query(ulong address)
    {
        object?[] call = [app, address, 0]; bool ok = addressApi != null && (bool)addressApi.Invoke(null, call)!;
        return (ok, (int)call[2]!);
    }
    var methods = app.Assemblies.SelectMany(a => a.Types).SelectMany(t => t.Methods).ToArray();
    var getSafe = methods.Single(m => m.FullName == "BundlesUtil::GetAssetBundleSafe");
    var unload = methods.Single(m => m.FullName == "BundlesUtil::UnloadDependencies");
    var decrypt = mappings.Single(m => m.Method.FullName == "CodeStage.AntiCheat.ObscuredTypes.ObscuredInt::InternalDecrypt");
    object?[] methodCall = [getSafe, 0]; bool methodOk = methodApi != null && (bool)methodApi.Invoke(null, methodCall)!;
    Check("plain static method wrapper returns original256byte range", methodOk && (int)methodCall[1]! == 256 && getSafe.UnderlyingPointer == 0x4A8920);
    Check("explicit plain address agrees", Query(0x4A8920) == (true, 256));
    Check("exception-bearing zPLR address rejected", Query(0x4A83A0) == (false, 0));
    object?[] exceptionCall = [unload, 0]; bool exceptionOk = methodApi != null && (bool)methodApi.Invoke(null, exceptionCall)!;
    Check("exception-bearing method wrapper rejected", !exceptionOk && (int)exceptionCall[1]! == 0);
    Check("general bounds still support exception-bearing384bytes", LegacyArm64ValueThisThunks.TryGetExactBodyRange(unload, out int exceptionSize) && exceptionSize == 384);
    Check("interior frame address rejected", Query(0x4A8924) == (false, 0));
    Check("zero address rejected", Query(0) == (false, 0));
    object?[] decryptCall = [decrypt.Method, 0]; bool decryptOk = methodApi != null && (bool)methodApi.Invoke(null, decryptCall)!;
    Check("method wrapper checks registered8byte adjustor", decryptOk && (int)decryptCall[1]! == 8);
    Check("explicit selected address checks actual520byte body", Query(decrypt.Address) == (true, 520));
    Check("selected analysis alias/pointer remain unchanged", LegacyArm64ValueThisThunks.TryGetBody(decrypt.Method, out var address, out var size)
        && address == decrypt.Address && size == 520 && decrypt.Method.UnderlyingPointer == decrypt.RegisteredAddress
        && app.MethodsByAddress[address].Count == 1 && ReferenceEquals(app.MethodsByAddress[address][0], decrypt.Method));
    byte[] original = File.ReadAllBytes(Guard("analysis/nso/main-uncompressed.nso"));
    int Raw(ulong at)
    {
        foreach (int offset in new[] { 0x10, 0x20, 0x30 })
        {
            ulong file = BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(offset, 4));
            ulong memory = BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(offset + 4, 4));
            ulong length = BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(offset + 8, 4));
            if (at >= memory && at < memory + length) return checked((int)(file + at - memory));
        }
        throw new IOException("Synthetic fixture address outside original segments");
    }
    var originalFrame = frames[0x4A8920]; var originalCie = cies[originalFrame.GetProperty("cie_rva").GetUInt64()];
    int cieTag = Raw(originalCie.GetProperty("rva").GetUInt64() + 10);
    int cieEncoding = Raw(originalCie.GetProperty("cfi_start").GetUInt64() - 1);
    int fdeAugmentation = Raw(originalFrame.GetProperty("fde_rva").GetUInt64() + 16);
    if (original[cieTag] != (byte)'R' || original[cieEncoding] != 0x1B || original[fdeAugmentation] != 0)
        throw new IOException("Original CIE/FDE fixture coordinates differ");
    (bool Bounds, int BoundsSize, bool Plain, int PlainSize) Fixture(Action<byte[]> mutate)
    {
        byte[] copy = original.ToArray(); mutate(copy);
        using var stream = new MemoryStream(copy, 0, copy.Length, true, true);
        var nso = new NsoFile(stream);
        var frameType = helper.GetNestedType("FrameTable", BindingFlags.NonPublic)!;
        object frame = Activator.CreateInstance(frameType, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance, null, [nso], null)!;
        object?[] boundsCall = [0x4A8920UL, 0]; object?[] plainCall = [0x4A8920UL, 0];
        bool boundsOk = (bool)frameType.GetMethod("TryRange")!.Invoke(frame, boundsCall)!;
        bool plainOk = (bool)frameType.GetMethod("TryPlainRange")!.Invoke(frame, plainCall)!;
        return (boundsOk, (int)boundsCall[1]!, plainOk, (int)plainCall[1]!);
    }
    Check("fresh private parser fixture preserves plain256byte range", Fixture(_ => { }) == (true, 256, true, 256));
    Check("unknown synthetic CIE tag rejects both ranges", Fixture(copy => copy[cieTag] = (byte)'Q') == (false, 0, false, 0));
    Check("synthetic nonempty zR FDE augmentation preserves general bounds but rejects new scope", Fixture(copy => copy[fdeAugmentation] = 1) == (true, 256, false, 0));
    Check("synthetic oversized FDE augmentation fails closed", Fixture(copy => copy[fdeAugmentation] = 127) == (false, 0, false, 0));
    Check("synthetic unsupported CIE pointer encoding fails closed", Fixture(copy => copy[cieEncoding] = 3) == (false, 0, false, 0));
    Check("native source file unchanged after in-memory parser fixtures", Hash(Guard("analysis/nso/main-uncompressed.nso")) == "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968");
    Check("ordinary decoder uses exact original registered256byte body", getSafe.RawBytes.Length == 256 && getSafe.UnderlyingPointer == 0x4A8920
        && Convert.ToHexString(SHA256.HashData(getSafe.RawBytes.AsSpan())).ToLowerInvariant() == "07369c1cddf45700ee6c60c559312bc29ed5debc2c953755d9ac7d7c1414991c");
    try
    {
        getSafe.Analyze();
        var instructions = getSafe.ControlFlowGraph!.Instructions;
        int requests = instructions.Count(i => i.IsCall && i.Operands[0] is MethodAnalysisContext target && target.Name == "RunClassConstructor");
        int configReads = instructions.SelectMany(i => i.Operands).Count(o => o is FieldReference f && f.Field.Name == "currentConfig" && f.Field.DeclaringType.FullName == "BundlesUtil");
        int remainingFlags = instructions.SelectMany(i => i.Operands).Count(o => o is MemoryOperand { Addend: 0x122 or 0xD4 });
        // Count original reads before later SSA forwarding can duplicate field
        // operands. Retain that later observation separately, without claiming
        // that a field operand count proves native memory-read parity.
        var staged = new MethodAnalysisContext(getSafe.Definition, getSafe.DeclaringType!);
        staged.EnsureRawBytes();
        staged.ConvertedIsil = app.InstructionSet.GetIsilFromMethod(staged);
        staged.ParameterOperands = app.InstructionSet.GetParameterOperandsFromMethod(staged);
        staged.ControlFlowGraph = new ISILControlFlowGraph(staged.ConvertedIsil);
        StackAnalyzer.Analyze(staged); staged.DominatorInfo = new DominatorInfo(staged.ControlFlowGraph);
        SsaForm.Build(staged); LocalVariables.CreateAll(staged); FlagConditionRecovery.Run(staged); DeadCodeEliminator.Run(staged);
        MetadataResolver.ResolveAll(staged); KeyFunctionRecovery.Run(staged); DeadCodeEliminator.Run(staged);
        MetadataInitGuardRemover.Run(staged); WriteBarrierRecovery.Run(staged); InjectedCheckRemover.Run(staged); InterfaceDispatchRecovery.Run(staged);
        LocalVariables.ResolveTypesAndFields(staged);
        int stagedConfigReads = staged.ControlFlowGraph.Instructions.SelectMany(i => i.Operands)
            .Count(o => o is FieldReference f && f.Field.Name == "currentConfig" && f.Field.DeclaringType.FullName == "BundlesUtil");
        string stagePath = Guard("analysis/reconstruction/class-guard-cfg-v35/get-safe-after-type-v35.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(stagePath)!);
        File.WriteAllText(stagePath, string.Join("\n", staged.ControlFlowGraph.Blocks.Select(b => b.ToString())));
        string finalPath = Guard("analysis/reconstruction/class-guard-cfg-v35/get-safe-full-analysis-v35.txt");
        File.WriteAllText(finalPath, string.Join("\n", getSafe.ControlFlowGraph.Blocks.Select(b => b.ToString())));
        ordinaryProductionObservation = new { method = getSafe.FullName, managed_class_requests = requests,
            original_current_config_reads_at_type_fixpoint = stagedConfigReads,
            later_full_analysis_current_config_operands = configReads,
            field_operand_count_is_not_native_read_parity = true,
            type_fixpoint_private_snapshot = Path.GetRelativePath(root, stagePath), type_fixpoint_snapshot_sha256 = Hash(stagePath),
            full_analysis_private_snapshot = Path.GetRelativePath(root, finalPath), full_analysis_snapshot_sha256 = Hash(finalPath),
            remaining_unsupported_class_flag_loads = remainingFlags, guest_execution_performed = false };
        Check("actual ordinary analysis preserves three constructor requests", requests == 3);
        Check("actual production type fixpoint preserves three original config reloads", stagedConfigReads == 3);
        Check("unsupported cold/Phi reload guards remain explicit", remainingFlags == 4);
    }
    catch (Exception error)
    {
        ordinaryAnalysisError = error.ToString();
        Check("actual ordinary analysis completes without suppressing errors", false);
    }
    var parallel = new bool[256]; Parallel.For(0, parallel.Length, i => parallel[i] = Query(i % 2 == 0 ? 0x4A8920UL : 0x4A83A0UL) == (i % 2 == 0, i % 2 == 0 ? 256 : 0));
    Check("parallel plain and rejected range-cache queries", parallel.All(v => v));
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", null);
    Check("plain-address API remains opt-in", Query(0x4A8920) == (false, 0));
    object?[] disabled = [getSafe, 0]; bool disabledOk = methodApi != null && (bool)methodApi.Invoke(null, disabled)!;
    Check("plain-method wrapper remains opt-in", !disabledOk && (int)disabled[1]! == 0);
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
}
bool passed = tests.All(t => JsonSerializer.Serialize(t).Contains("PASS"));
var report = new { status = passed ? (inventoryOnly ? "READ_ONLY_EXISTING_SELECTED_VALUE_THIS_CIE_INVENTORY" : "PASS_ADDITIVE_PLAIN_FRAME_RANGE_AND_LEGACY_SCOPE_GUARDS") : "PLAIN_FRAME_PROBE_EXPECTATION_FAILED",
    checks = tests.Count, tests, selected_bodies = mappings.Count, cie_groups = rows.GroupBy(r => r.cie_augmentation).Select(g => new { augmentation = g.Key, bodies = g.Count() }),
    ordinary_analysis_error = ordinaryAnalysisError, ordinary_production_observation = ordinaryProductionObservation,
    existing_selected_exception_bearing_bodies = rows.Where(r => !r.plain_cie).ToArray(), selected_mapping_inventory = rows,
    loaded_core_sha256 = Hash(typeof(Cpp2IlApi).Assembly.Location), source_binary_sha256 = Hash(binary), source_metadata_sha256 = Hash(metadata),
    frames_sha256 = Hash(Guard("analysis/nso/unwind-inventory-v1/frames.jsonl")), cies_sha256 = Hash(Guard("analysis/nso/unwind-inventory-v1/cies.json")),
    scope = "Original current Cpp2IL accepted mapping/CIE inventory, additive bounds eligibility and actual GetAssetBundleSafe analysis observations. Synthetic parser cases use fresh in-memory NSO copies; original files remain unchanged. Existing selected exception-bearing bodies are disclosed; their previous scope is not silently changed. Plain-frame API eligibility rejects exception metadata without interpreting it. Analysis checks retain the original constructor requests/config reloads and unsupported flag loads. No original guest code, initializer, stack unwinding or recovered CIL is executed, and no full-source or whole-game readiness claim is made." };
File.WriteAllText(Guard(inventoryOnly ? "reports/class-guard-existing-selected-eh-v34.json" : "reports/plain-frame-range-guards-v35.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { report.status, report.checks, selected = mappings.Count, cie_groups = report.cie_groups, old_exception_bodies = rows.Count(r => !r.plain_cie), passed }));
return passed ? 0 : 2;
