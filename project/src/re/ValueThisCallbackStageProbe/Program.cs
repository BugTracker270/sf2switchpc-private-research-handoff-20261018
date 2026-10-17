using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;

if (args.Length != 1) throw new ArgumentException("Verified USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative) { string path = Path.GetFullPath(Path.Combine(root, relative)); if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace"); for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent) if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point"); return path; }
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
string binary = Guard("unpacked/effective/exefs/main"), metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (Hash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238" || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Input differs");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1"); Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins")); Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var method = app.Assemblies.SelectMany(a => a.Types).Single(t => t.FullName == "CodeStage.AntiCheat.ObscuredTypes.ObscuredInt").Methods.Single(m => m.Name == "InternalDecrypt");
method.ConvertedIsil = app.InstructionSet.GetIsilFromMethod(method); method.ParameterOperands = app.InstructionSet.GetParameterOperandsFromMethod(method); method.ControlFlowGraph = new ISILControlFlowGraph(method.ConvertedIsil);
StackAnalyzer.Analyze(method); method.DominatorInfo = new DominatorInfo(method.ControlFlowGraph); SsaForm.Build(method); LocalVariables.CreateAll(method); FlagConditionRecovery.Run(method); DeadCodeEliminator.Run(method);
MetadataResolver.ResolveAll(method); KeyFunctionRecovery.Run(method); DeadCodeEliminator.Run(method); MetadataInitGuardRemover.Run(method); WriteBarrierRecovery.Run(method); InjectedCheckRemover.Run(method); InterfaceDispatchRecovery.Run(method); LocalVariables.ResolveTypesAndFields(method);
var graph = method.ControlFlowGraph!;
var definitions = graph.Instructions.Where(i => i.Destination is LocalVariable).GroupBy(i => (LocalVariable)i.Destination!).ToDictionary(g => g.Key, g => g.ToArray());
object Describe(IOperand? operand) => operand switch { LocalVariable l => new { kind = "local", l.Name, register = l.Register.Name, version = l.Register.Version, type = l.Type?.FullName, parameter_root = method.ParameterLocals.Contains(l) }, MethodAnalysisContext m => new { kind = "method", m.FullName }, MemoryOperand m => new { kind = "memory", m.Addend, description = m.ToString() }, _ => new { kind = operand?.GetType().Name, description = operand?.ToString() } };
object Chain(IOperand? operand) { var rows = new List<object>(); var seen = new HashSet<LocalVariable>(); for (int n = 0; n < 32 && operand is LocalVariable local && seen.Add(local); n++) { var found = definitions.GetValueOrDefault(local) ?? []; rows.Add(new { local = Describe(local), definitions = found.Select(i => new { i.Index, opcode = i.OpCode.ToString(), operands = i.Operands.Select(Describe).ToArray() }).ToArray() }); if (found.Length != 1 || found[0].OpCode != OpCode.Move || found[0].Operands is not [_, LocalVariable next]) break; operand = next; } return rows; }
var calls = graph.Instructions.Where(i => i.OpCode == OpCode.IndirectCall).Select(call => new { call.Index, operands = call.Operands.Select(Describe).ToArray(), receiver_chain = Chain(call.Operands.ElementAtOrDefault(2)), result_definition_count = call.Destination is LocalVariable r ? definitions.GetValueOrDefault(r)?.Length : null,
    result_top_level_uses = call.Destination is LocalVariable result ? graph.Instructions.Count(i => i.Sources.Any(s => ReferenceEquals(s, result))) : -1 }).ToArray();
string privatePath = Guard("analysis/reconstruction/value-this-regression-v36/callback-after-type-stage.json"); Directory.CreateDirectory(Path.GetDirectoryName(privatePath)!);
File.WriteAllText(privatePath, JsonSerializer.Serialize(new { calls, graph = string.Join("\n", graph.Blocks.Select(b => b.ToString())) }, new JsonSerializerOptions { WriteIndented = true }) + "\n");
var report = new { status = "READ_ONLY_ACTUAL_VALUE_THIS_CALLBACK_STAGE", core_sha256 = Hash(typeof(KeyFunctionRecovery).Assembly.Location), registered_rva = "0x" + method.UnderlyingPointer.ToString("X"), indirect_calls = calls.Length,
    private_stage_path = Path.GetRelativePath(root, privatePath), private_stage_sha256 = Hash(privatePath), probe_source_sha256 = Hash(Guard("src/re/ValueThisCallbackStageProbe/Program.cs")), core_modified = false, game_methods_invoked = 0, scope = "Unchanged one-method production SSA/type graph observation only; no alternate receiver root or void dispatch witness is implemented or accepted." };
File.WriteAllText(Guard("reports/value-this-callback-stage-v36.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n"); Console.WriteLine(JsonSerializer.Serialize(report));
