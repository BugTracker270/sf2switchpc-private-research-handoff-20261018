using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;

if (args.Length != 1 && (args.Length != 2 || args[1] != "--game-methods")) throw new ArgumentException("Verified USB root and optional --game-methods required");
bool gameMethods = args.Length == 2;
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string FileHash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
var binary = Guard("unpacked/effective/exefs/main");
var metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (FileHash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || FileHash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Input differs");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var address = typeof(MetadataResolver).GetMethod("LiteralSlotAddress", BindingFlags.NonPublic | BindingFlags.Static)!;
var selected = new[] { "FyberPlugin.User", "InControl.GoogleNexusPlayerRemoteProfile", "Nekki.SF2.Core.Fights.Model.Components.Nodes.ModelNode", "BackKeyManager", "Nekki.Utils.DetailedLog", "ScreenTypeExtension", "CocosAnimationAbstractRenderer", "Nekki.SF2.Core.GameCenter.GameCenterManager" };
var methods = app.Assemblies.SelectMany(assembly => assembly.Types).Where(type => gameMethods
        ? type.DeclaringAssembly.Name is "Assembly-CSharp" or "Assembly-CSharp-firstpass" : selected.Contains(type.FullName))
    .SelectMany(type => type.Methods).Where(method => method.UnderlyingPointer != 0).ToArray();
var observations = new List<object>(); var errors = new List<object>();
int analyzed = 0, callCount = 0, processed = 0;
foreach (var method in methods)
{
    if (observations.Count >= 24) break;
    processed++;
    try
    {
        method.EnsureRawBytes();
        // Reproduce MethodAnalysisContext.Analyze only up to its first metadata
        // resolver invocation. No game methods or candidate helpers execute.
        if (Cpp2IL.Core.Model.Contexts.MethodAnalysisContext.MaxMethodSizeBytes != -1
            && method.RawBytes.Length > Cpp2IL.Core.Model.Contexts.MethodAnalysisContext.MaxMethodSizeBytes) continue;
        method.ConvertedIsil = app.InstructionSet.GetIsilFromMethod(method);
        method.ParameterOperands = app.InstructionSet.GetParameterOperandsFromMethod(method);
        if (method.ConvertedIsil.Count == 0) continue;
        method.ControlFlowGraph = new ISILControlFlowGraph(method.ConvertedIsil);
        StackAnalyzer.Analyze(method);
        method.DominatorInfo = new DominatorInfo(method.ControlFlowGraph);
        SsaForm.Build(method); LocalVariables.CreateAll(method);
        FlagConditionRecovery.Run(method); DeadCodeEliminator.Run(method);
        var definitions = method.ControlFlowGraph.Instructions.Where(instruction => instruction.Destination is LocalVariable)
            .GroupBy(instruction => (LocalVariable)instruction.Destination!).ToDictionary(group => group.Key, group => group.Last());
        foreach (var instruction in method.ControlFlowGraph.Instructions)
        {
            if (instruction.OpCode != OpCode.Call || instruction.Operands[1] is not LocalVariable) continue;
            callCount++;
            for (int argument = 2; argument < instruction.Operands.Count; argument++)
            {
                if (address.Invoke(null, [instruction.Operands[argument], definitions]) is not ulong slot
                    || app.LibCpp2IlContext.GetLiteralByAddress(slot) is not string literal) continue;
                ulong? target = instruction.Operands[0] is Immediate immediate ? immediate.UnsignedValue : null;
                var names = target.HasValue && app.MethodsByAddress.TryGetValue(target.Value, out var aliases)
                    ? aliases.Select(alias => alias.FullName).Distinct().ToArray() : [];
                observations.Add(new { caller = method.FullName, caller_rva = $"0x{method.UnderlyingPointer:X}",
                    isil_index = instruction.Index, target_rva = target.HasValue ? $"0x{target:X}" : null,
                    target_kind = instruction.Operands[0].GetType().Name, target_metadata_methods = names,
                    argument_position = argument - 2, inferred_argument_count = instruction.Operands.Count - 2,
                    literal_slot = $"0x{slot:X}", literal_length = literal.Length, literal_sha256 = Hash(literal) });
                File.WriteAllText(Guard($"analysis/il2cpp/string-accessor-pre-resolve-{method.UnderlyingPointer:X}.txt"),
                    string.Join("\n", method.ControlFlowGraph.Blocks.Select(block => block.ToString())) + "\n");
                break;
            }
        }
        analyzed++;
    }
    catch (Exception exception) { errors.Add(new { caller = method.FullName, error = exception.GetType().FullName + ": " + exception.Message }); }
}
var report = new { status = "BOUNDED_LITERAL_ACCESSOR_PRE_RESOLUTION_OBSERVATIONS_ONLY", selected_types = gameMethods ? [] : selected,
    selected_methods = methods.Length, processed_methods = processed, exhausted_selection = processed == methods.Length,
    analyzed_methods = analyzed, inspected_returning_calls = callCount,
    rewrite_candidates = observations.Count, candidates = observations, errors,
    tool_core_sha256 = FileHash(typeof(MetadataResolver).Assembly.Location),
    source_resolver_sha256 = FileHash(Guard("refs/Cpp2IL/Cpp2IL.Core/Analysis/MetadataResolver.cs")),
    game_code_executed = false, core_source_edited = false, whole_game_source_ready = false,
    scope = "Reproduce pre-MetadataResolver SSA stages for a bounded actual-method selection and apply only the current private literal-slot-address recognition predicate. Record targets and inferred argument positions of actual candidate whole-call rewrites. This is observation only: no candidate is certified as a literal accessor and no counterexample is claimed until native callees/argument roles are independently inspected." };
File.WriteAllText(Guard(gameMethods ? "reports/string-accessor-survey-game-v30.json" : "reports/string-accessor-survey-v30.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine($"Survey: {analyzed}/{methods.Length} methods, {observations.Count} candidates, {errors.Count} errors");
