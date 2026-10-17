using System.Security.Cryptography;
using System.Text.Json;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;

if (args.Length != 1) throw new ArgumentException("Verified USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
if (!string.Equals(root, @"F:\SF2SwitchPC", StringComparison.OrdinalIgnoreCase)) throw new IOException("Unexpected USB workspace");
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? directory = new(Path.GetDirectoryName(path)!); directory != null; directory = directory.Parent)
        if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var tests = new List<(string Name, bool Passed)>();
void Check(string name, bool passed) => tests.Add((name, passed));
List<Instruction> Fixture()
{
    var normalReturn = new Instruction(5, OpCode.Return);
    return [new(0, OpCode.Nop), new(1, OpCode.Jump, normalReturn), new(2, OpCode.Nop),
        new(3, OpCode.CallVoid, new Immediate(0x12345678)), new(4, OpCode.Return), normalReturn];
}
List<Instruction> CloneBranches(List<Instruction> source)
{
    // Only this probe's primitive/branch fixture is supported, not arbitrary mutable operand graphs.
    var map = new Dictionary<Instruction, Instruction>();
    foreach (var instruction in source)
    {
        if (!map.TryAdd(instruction, new Instruction(instruction.Index, instruction.OpCode, instruction.Operands.ToList())))
            throw new InvalidOperationException("Duplicate instruction identity");
    }
    foreach (var instruction in map.Values)
        for (int index = 0; index < instruction.Operands.Count; index++)
            if (instruction.Operands[index] is Instruction oldTarget)
            {
                if (!map.TryGetValue(oldTarget, out var target)) throw new InvalidOperationException("Target outside cloned method");
                instruction.SetOperand(index, target);
            }
    return source.Select(instruction => map[instruction]).ToList();
}
string loaded = typeof(ISILControlFlowGraph).Assembly.Location;
string loadedHash = Hash(loaded);
using var provenance = JsonDocument.Parse(File.ReadAllText(Guard("logs/cpp2il-nso-plain-frame-cfg-v35-result.json")));
Check("loaded Core matches frozen v35 recovery provenance", loadedHash == provenance.RootElement.GetProperty("tool_assembly_sha256").GetProperty("Cpp2IL.Core.dll").GetString());
var original = Fixture();
var target = original[5];
var shallow = original.ToList();
var graph = new ISILControlFlowGraph(shallow);
Check("CFG construction rewrites shared branch operand to a Block", original[1].Operands[0] is Block);
Check("shallow list copy preserves shared mutable Instruction instances", ReferenceEquals(original[1], shallow[1]));
Check("branch rewrite resolves original normal-return instruction identity", ReferenceEquals(((Block)original[1].Operands[0]).Instructions[0], target));
Check("handler-shaped instructions physically exist before pruning", original.Skip(2).Take(3).All(instruction => graph.FindBlockByInstruction(instruction) != null));
Check("entry-only instruction enumeration omits handler-shaped instructions", original.Skip(2).Take(3).All(instruction => !graph.Instructions.Contains(instruction)));
int before = graph.Blocks.Count;
graph.RemoveUnreachableBlocks();
Check("normal reachability pruning removes all handler-shaped blocks", original.Skip(2).Take(3).All(instruction => graph.FindBlockByInstruction(instruction) == null) && graph.Blocks.Count < before);
Check("pruning keeps the normal return", graph.FindBlockByInstruction(target) != null);
var isolatedOriginal = Fixture();
var originalJumpTarget = isolatedOriginal[1].Operands[0];
var cloned = CloneBranches(isolatedOriginal);
Check("branch clone maps targets to cloned identity before CFG construction", ReferenceEquals(cloned[1].Operands[0], cloned[5]) && !ReferenceEquals(cloned[5], isolatedOriginal[5]));
var clonedGraph = new ISILControlFlowGraph(cloned);
Check("cloned CFG rewrites only the cloned branch", cloned[1].Operands[0] is Block && ReferenceEquals(isolatedOriginal[1].Operands[0], originalJumpTarget));
Check("all original fixture instructions remain unmodified by cloned CFG", isolatedOriginal[1].Operands[0] is Instruction && isolatedOriginal.All(instruction => instruction.Operands.All(operand => operand is not Block)));
bool duplicateRejected = false;
try { CloneBranches([isolatedOriginal[0], isolatedOriginal[0]]); } catch (InvalidOperationException) { duplicateRejected = true; }
Check("duplicate identity rejects before temporary CFG construction", duplicateRejected);
var outside = Fixture();
outside[1].SetOperand(0, new Instruction(99, OpCode.Return));
bool outsideRejected = false;
try { CloneBranches(outside); } catch (InvalidOperationException) { outsideRejected = true; }
Check("outside branch target rejects without mutating source", outsideRejected && outside[1].Operands[0] is Instruction { Index: 99 });
var report = new
{
    status = tests.All(test => test.Passed) ? "PASS_CURRENT_CORE_CFG_BOUNDARY_PROBE" : "FAIL_CURRENT_CORE_CFG_BOUNDARY_PROBE",
    checks = tests.Count, failures = tests.Count(test => !test.Passed),
    tests = tests.Select(test => new { name = test.Name, passed = test.Passed }),
    loaded_core_sha256 = loadedHash,
    core_source_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/Graphs/ISILControlFlowGraph.cs")),
    instruction_source_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/ISIL/Instruction.cs")),
    probe_source_sha256 = Hash(Guard("src/re/ExceptionGraphBoundaryProbe/Program.cs")),
    core_built = false, core_edited = false, original_game_inputs_read = false, game_code_executed = false,
    production_eh_ready = false,
    scope = "Actual existing Core CFG construction and pruning on original synthetic ISIL only. Handler-shaped blocks have no EH descriptor in current Core and are omitted/pruned by normal reachability. A shallow list copy shares mutable instructions; a branch-remapped fixture clone preserves the source. No general mutable-operand clone, SSA exception semantics, native unwinding or CIL EH emission is tested."
};
File.WriteAllText(Guard("reports/exception-graph-boundary-v36.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + Environment.NewLine);
Console.WriteLine(JsonSerializer.Serialize(new { report.status, report.checks, report.failures, report.loaded_core_sha256 }));
return report.failures == 0 ? 0 : 1;
