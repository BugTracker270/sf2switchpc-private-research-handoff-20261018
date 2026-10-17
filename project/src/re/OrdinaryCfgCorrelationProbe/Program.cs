using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.InstructionSets;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;
using Disarm;

if (args.Length != 1) throw new ArgumentException("Verified USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? dir = new(Path.GetDirectoryName(path)!); dir != null; dir = dir.Parent)
        if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string BytesHash(ReadOnlySpan<byte> value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
string FileHash(string path) => BytesHash(File.ReadAllBytes(path));
string binary = Guard("unpacked/effective/exefs/main"), metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (FileHash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || FileHash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Original input hashes differ");
var tests = new List<object>(); var rejections = new List<object>(); var candidateRows = new List<object>();
void Check(string name, bool passed) => tests.Add(new { name, status = passed ? "PASS" : "FAIL" });
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!; var keys = app.GetOrCreateKeyFunctionAddresses();
string coreHash = FileHash(typeof(Cpp2IlApi).Assembly.Location);
byte[] original = File.ReadAllBytes(Guard("analysis/nso/main-uncompressed.nso"));
if (BytesHash(original) != "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968") throw new IOException("Original uncompressed image differs");
int Raw(ulong address)
{
    foreach (int h in new[] { 0x10, 0x20, 0x30 })
    {
        ulong file = BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(h, 4));
        ulong start = BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(h + 4, 4));
        ulong size = BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(h + 8, 4));
        if (address >= start && address < start + size) return checked((int)(file + address - start));
    }
    throw new IOException("Native address outside original segments");
}
using var cieDoc = JsonDocument.Parse(File.ReadAllText(Guard("analysis/nso/unwind-inventory-v1/cies.json")));
var cies = cieDoc.RootElement.EnumerateArray().ToDictionary(r => r.GetProperty("rva").GetUInt64(), r => r.Clone());
var frames = new Dictionary<ulong, JsonElement>();
foreach (string line in File.ReadLines(Guard("analysis/nso/unwind-inventory-v1/frames.jsonl")))
{
    using var doc = JsonDocument.Parse(line); var row = doc.RootElement; frames.Add(row.GetProperty("rva").GetUInt64(), row.Clone());
}
ulong writable = BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(0x34, 4));
ulong writableEnd = writable + BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(0x38, 4)) + BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(0x3C, 4));
var convert = typeof(NewArmV8InstructionSet).GetMethod("ConvertInstructionStatement", BindingFlags.NonPublic | BindingFlags.Instance)!;
var pages = typeof(NewArmV8InstructionSet).GetField("adrpOffsets", BindingFlags.NonPublic | BindingFlags.Static)!;
var selected = new List<object>(); int examined = 0, analyzed = 0;

void ThroughTypeFixpoint(MethodAnalysisContext method)
{
    method.ConvertedIsil = app.InstructionSet.GetIsilFromMethod(method);
    method.ParameterOperands = app.InstructionSet.GetParameterOperandsFromMethod(method);
    method.ControlFlowGraph = new ISILControlFlowGraph(method.ConvertedIsil);
    StackAnalyzer.Analyze(method); method.DominatorInfo = new DominatorInfo(method.ControlFlowGraph);
    SsaForm.Build(method); LocalVariables.CreateAll(method); FlagConditionRecovery.Run(method); DeadCodeEliminator.Run(method);
    MetadataResolver.ResolveAll(method); KeyFunctionRecovery.Run(method); DeadCodeEliminator.Run(method);
    MetadataInitGuardRemover.Run(method); WriteBarrierRecovery.Run(method); InjectedCheckRemover.Run(method); InterfaceDispatchRecovery.Run(method);
    LocalVariables.ResolveTypesAndFields(method);
}

foreach (var (address, aliases) in app.MethodsByAddress.OrderBy(p => p.Key))
{
    if (selected.Count != 0 || analyzed >= 32) break;
    if (aliases.Count != 1 || aliases[0].Definition == null || LegacyArm64ValueThisThunks.TryGetBody(aliases[0], out _, out _)
        || !frames.TryGetValue(address, out var frame) || frame.GetProperty("end_rva").GetUInt64() - address > 4096) continue;
    var cie = cies[frame.GetProperty("cie_rva").GetUInt64()];
    if (cie.GetProperty("augmentation").GetString() != "zR" || !LegacyArm64ValueThisThunks.TryGetExactPlainBodyRange(app, address, out int size)) continue;
    var method = aliases[0]; examined++;
    byte[] body = original.AsSpan(Raw(address), size).ToArray();
    var native = Disassembler.Disassemble(body, address, new Disassembler.Options(true, true, false)).ToArray();
    var classCalls = native.Where(i => i.Mnemonic == Arm64Mnemonic.BL && i.BranchTarget == keys.il2cpp_codegen_runtime_class_init).ToArray();
    if (classCalls.Length == 0) continue;
    var oldSites = LegacyArm64AllocationPattern.ClassInitSites(body, address).Where(s => s.Target == keys.il2cpp_codegen_runtime_class_init).Select(s => s.Start).ToHashSet();
    var cfg = LegacyArm64CfgInitializationPattern.Match(body, address, keys.il2cpp_codegen_initialize_method, keys.il2cpp_codegen_runtime_class_init, writable, writableEnd);
    var added = cfg.ClassGuards.Where(s => !oldSites.Contains(s.Start)).ToArray();
    if (added.Length == 0) continue;
    var semanticCalls = native.Where(i => i.Mnemonic == Arm64Mnemonic.BL && i.BranchTarget != keys.il2cpp_codegen_runtime_class_init && i.BranchTarget != keys.il2cpp_codegen_initialize_method).ToArray();
    if (semanticCalls.Length == 0 || semanticCalls.Any(i => !app.MethodsByAddress.TryGetValue(i.BranchTarget, out var targets) || targets.Count != 1)) continue;
    candidateRows.Add(new { method = method.FullName, rva = $"0x{address:X}", bytes = size, body_sha256 = BytesHash(body), new_cfg_sites = added.Length });
    analyzed++;
    try
    {
        // Raw physical-register decoding without either macro, followed by the
        // actual production GetIsil. This invokes the current converter only;
        // no native or managed game method runs and no IR is patched by the probe.
        var rawBaseline = new List<Instruction>(); var rawAddresses = new List<ulong>();
        pages.SetValue(null, new Dictionary<string, ulong>());
        foreach (var instruction in native) convert.Invoke(app.InstructionSet, [instruction, rawBaseline, rawAddresses, method]);
        var production = app.InstructionSet.GetIsilFromMethod(method);
        // Production changes only these exact flag-load instructions into an
        // initialized metadata value or a semantic class-constructor request.
        // Register-based loads cannot be classified by MemoryOperand.Addend:
        // that addend is only the displacement, while the matcher carries the
        // absolute writable flag address. Retain every other memory effect.
        var overwrittenLoads = cfg.MetadataGuards.Select(g => g.Load)
            .Concat(cfg.ClassGuards.Select(g => g.Start)).Concat(oldSites).ToHashSet();
        bool ConstructorCall(Instruction i) => i.IsCall && i.Operands[0] is Immediate t && t.UnsignedValue == keys.il2cpp_codegen_runtime_class_init;
        string[] Effects(IEnumerable<Instruction> instructions) => instructions.Where(i =>
            i.IsCall && !ConstructorCall(i)
            || i.OpCode == OpCode.Move && (i.Operands[0] is MemoryOperand || i.Operands.Count > 1 && i.Operands[1] is MemoryOperand))
            .Select(i => i.OpCode + "|" + string.Join("|", i.Operands.Select(o => o.ToString()))).ToArray();
        if (rawBaseline.Count != rawAddresses.Count) throw new InvalidDataException("Direct-conversion address cardinality differs");
        var baselineUnchanged = rawBaseline.Where((i, index) => !overwrittenLoads.Contains(rawAddresses[index])).ToArray();
        foreach (var addressToReplace in overwrittenLoads)
        {
            var atAddress = rawBaseline.Where((i, index) => rawAddresses[index] == addressToReplace).ToArray();
            if (atAddress.Length != 1 || atAddress[0].OpCode != OpCode.Move || atAddress[0].Operands.Count != 2
                || atAddress[0].Operands[0] is not Register || atAddress[0].Operands[1] is not MemoryOperand)
                throw new InvalidDataException("Exact replaced flag instruction is not a single register-from-memory load");
        }
        string[] baselineEffects = Effects(baselineUnchanged), productionEffects = Effects(production);
        if (!baselineEffects.SequenceEqual(productionEffects))
        {
            string mismatchFolder = Guard($"analysis/reconstruction/class-guard-cfg-v35/ordinary-{address:x}-rejected");
            Directory.CreateDirectory(mismatchFolder);
            File.WriteAllText(Path.Combine(mismatchFolder, "native.txt"), string.Join("\n", native.Select(i => i.ToString())));
            File.WriteAllText(Path.Combine(mismatchFolder, "direct-raw-isil.txt"), string.Join("\n", rawBaseline));
            File.WriteAllText(Path.Combine(mismatchFolder, "production-raw-isil.txt"), string.Join("\n", production));
            File.WriteAllText(Path.Combine(mismatchFolder, "direct-effects.txt"), string.Join("\n", baselineEffects));
            File.WriteAllText(Path.Combine(mismatchFolder, "production-effects.txt"), string.Join("\n", productionEffects));
            throw new InvalidDataException($"Non-scaffolding raw loads/stores/calls differ from direct decoding (effects {baselineEffects.Length}/{productionEffects.Length}); private evidence {Path.GetRelativePath(root, mismatchFolder)}");
        }
        if (!method.RawBytes.AsSpan().SequenceEqual(body)) throw new InvalidDataException("Production raw body differs from original exact FDE");
        var staged = new MethodAnalysisContext(method.Definition, method.DeclaringType!); staged.EnsureRawBytes(); ThroughTypeFixpoint(staged);
        var stageInstructions = staged.ControlFlowGraph!.Instructions;
        int requests = stageInstructions.Count(i => i.IsCall && i.Operands[0] is MethodAnalysisContext target && target.Name == "RunClassConstructor");
        int residual = stageInstructions.Count(ConstructorCall);
        int remainingFlags = stageInstructions.SelectMany(i => i.Operands).Count(o => o is MemoryOperand { Addend: 0x122 or 0xD4 });
        var expectedCalls = semanticCalls.Select(i => app.MethodsByAddress[i.BranchTarget][0]).GroupBy(m => m.UnderlyingPointer).ToDictionary(g => g.Key, g => g.Count());
        var actualCalls = stageInstructions.Where(i => i.IsCall && i.Operands[0] is MethodAnalysisContext m && m.Name != "RunClassConstructor")
            .Select(i => (MethodAnalysisContext)i.Operands[0]).GroupBy(m => m.UnderlyingPointer).ToDictionary(g => g.Key, g => g.Count());
        bool callsPreserved = expectedCalls.Count == actualCalls.Count && expectedCalls.All(p => actualCalls.GetValueOrDefault(p.Key) == p.Value);
        if (requests != classCalls.Length || residual != 0 || remainingFlags != 0 || !callsPreserved)
            throw new InvalidDataException($"Typed stage requests/raw/flags/semantic call comparison failed: {requests}/{residual}/{remainingFlags}/{callsPreserved}");
        string folder = Guard($"analysis/reconstruction/class-guard-cfg-v35/ordinary-{address:x}"); Directory.CreateDirectory(folder);
        string Save(string name, string text)
        {
            string path = Guard($"analysis/reconstruction/class-guard-cfg-v35/ordinary-{address:x}/{name}"); File.WriteAllText(path, text); return FileHash(path);
        }
        string nativeHash = Save("native.txt", string.Join("\n", native.Select(i => i.ToString())));
        string baselineHash = Save("direct-raw-isil.txt", string.Join("\n", rawBaseline));
        string productionHash = Save("production-raw-isil.txt", string.Join("\n", production));
        string stageHash = Save("after-type-isil.txt", string.Join("\n", staged.ControlFlowGraph.Blocks.Select(b => b.ToString())));
        selected.Add(new { method = method.FullName, registered_address = $"0x{method.UnderlyingPointer:X}", analysis_address = $"0x{address:X}",
            exact_fde_bytes = size, cie_augmentation = "zR", body_sha256 = BytesHash(body), raw_bytes_equal_original = method.RawBytes.AsSpan().SequenceEqual(body),
            newly_accepted_cfg_guards = added.Select(g => new { start = $"0x{g.Start:X}", skip = $"0x{g.Skip:X}", class_load = $"0x{g.ClassLoad:X}" }),
            original_native_constructor_requests = classCalls.Length, actual_managed_constructor_requests = requests, remaining_raw_requests = residual,
            remaining_class_flag_loads = remainingFlags, non_scaffolding_raw_effects = baselineEffects.Length,
            exact_replaced_flag_load_sites = overwrittenLoads.Order().Select(a => $"0x{a:X}").ToArray(),
            baseline_exclusion_requires_exact_native_witness_and_single_load = true,
            raw_effect_sequence_equal = true, original_semantic_call_sites = semanticCalls.Length, typed_semantic_call_sites_preserved = callsPreserved,
            private_evidence_folder = Path.GetRelativePath(root, folder), native_snapshot_sha256 = nativeHash, direct_raw_snapshot_sha256 = baselineHash,
            production_raw_snapshot_sha256 = productionHash, type_fixpoint_snapshot_sha256 = stageHash });
    }
    catch (Exception error) { rejections.Add(new { method = method.FullName, rva = $"0x{address:X}", error = error.ToString() }); }
}
Check("at least one newly matched ordinary plain-frame body traverses actual production analysis", selected.Count == 1);
Check("Unload exception-bearing frame remains excluded", !LegacyArm64ValueThisThunks.TryGetExactPlainBodyRange(app, 0x4A83A0, out int unloadSize) && unloadSize == 0);
using var parserDoc = JsonDocument.Parse(File.ReadAllText(Guard("reports/plain-frame-range-guards-v35.json")));
var parser = parserDoc.RootElement;
Check("current parser and reload-stage gate passes on the same Core", parser.GetProperty("status").GetString() == "PASS_ADDITIVE_PLAIN_FRAME_RANGE_AND_LEGACY_SCOPE_GUARDS" && parser.GetProperty("loaded_core_sha256").GetString() == coreHash);
var getSafe = parser.GetProperty("ordinary_production_observation");
Check("unsupported GetSafe cold/Phi reload shapes remain explicit", getSafe.GetProperty("original_current_config_reads_at_type_fixpoint").GetInt32() == 3 && getSafe.GetProperty("remaining_unsupported_class_flag_loads").GetInt32() == 4);
bool passed = tests.All(t => JsonSerializer.Serialize(t).Contains("PASS"));
var report = new { status = passed ? "PASS_PLAIN_FRAME_ORDINARY_NATIVE_AND_PRODUCTION_ISIL_CORRELATION" : "ORDINARY_CFG_PRODUCTION_CORRELATION_LIMITATIONS",
    checks = tests.Count, tests, examined_plain_registered_frames = examined, candidate_analysis_attempts = analyzed, accepted_ordinary_bodies = selected.Count,
    selected, candidate_summaries = candidateRows, candidate_rejections = rejections, core_sha256 = coreHash,
    plain_parser_report_sha256 = FileHash(Guard("reports/plain-frame-range-guards-v35.json")),
    native_source_sha256 = BytesHash(original), binary_sha256 = FileHash(binary), metadata_sha256 = FileHash(metadata),
    value_this_source_sha256 = FileHash(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64ValueThisThunks.cs")),
    instruction_set_source_sha256 = FileHash(Guard("refs/Cpp2IL/Cpp2IL.Core/InstructionSets/NewArmV8InstructionSet.cs")),
    cfg_matcher_source_sha256 = FileHash(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64CfgInitializationPattern.cs")),
    probe_source_sha256 = FileHash(Guard("src/re/OrdinaryCfgCorrelationProbe/Program.cs")),
    core_source_edited_by_probe = false, ir_rewritten_by_probe = false, guest_execution_performed = false,
    scope = "Original native exact plain-FDE and actual production decoder/type-fixpoint correlation only. Raw loads/stores and non-constructor calls retain the same canonical ordered operands as direct native instruction conversion, except exact metadata/class flag-load instruction addresses proven replaced by matcher witnesses; each exclusion must be one register-from-memory load. No generic offset exclusion is used. Typed constructor and semantic call sites must survive the real pipeline. Complete native/IR snapshots are private ignored evidence. The probe does not execute original or recovered game code, certify all operand types/branch paths/field-read timing, implement exception handling, or claim portable/full source. GetSafe has3 native/type-fixpoint config reads and5 later propagated field operands; those stages are explicitly distinct. Unload zPLR stays excluded." };
File.WriteAllText(Guard("reports/plain-frame-ordinary-native-correlation-v35.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { report.status, report.checks, examined, analyzed, accepted = selected.Count, rejections = rejections.Count }));
return passed ? 0 : 2;
