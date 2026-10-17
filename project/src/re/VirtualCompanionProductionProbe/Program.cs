using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;

if (args.Length != 1) throw new ArgumentException("Verified USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative) { string p = Path.GetFullPath(Path.Combine(root, relative)); if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB"); for (DirectoryInfo? d = new(Path.GetDirectoryName(p)!); d != null; d = d.Parent) if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point"); return p; }
string Hash(string relative) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Guard(relative)))).ToLowerInvariant();
var checks = new List<object>(); var methods = new List<object>(); string? fatal = null;
void Check(string name, bool passed) { checks.Add(new { name, passed }); if (!passed) throw new InvalidDataException(name); }
string coreHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(typeof(Cpp2IlApi).Assembly.Location))).ToLowerInvariant();
try
{
    string binary = Guard("unpacked/effective/exefs/main"), metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
    Check("original native and metadata input hashes", Hash("unpacked/effective/exefs/main") == "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238" && Hash("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat") == "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85");
    using var inventoryDocument = JsonDocument.Parse(File.ReadAllText(Guard("analysis/reconstruction/virtual-copy-root-v38/native-inventory.json")));
    var native = inventoryDocument.RootElement.GetProperty("methods").EnumerateArray().Single(m => m.GetProperty("start").GetInt32() == 0x15CA080);
    Check("exact original76-byte TryGetAttribute native witness", native.GetProperty("bytes").GetInt32() == 76 && native.GetProperty("end").GetInt32() == 0x15CA0CC && native.GetProperty("sha256").GetString() == "31624d0e92a6f3d234085049e27d6d43d93a464f4c6d4f51856901ec77d48c00");
    Check("current unchanged native source bound", Hash("analysis/nso/main-uncompressed.nso") == inventoryDocument.RootElement.GetProperty("native_sha256").GetString());
    var nativeRows = native.GetProperty("instructions").EnumerateArray().ToDictionary(r => r.GetProperty("address").GetInt32());
    Check("original paired188/190 load and X8 to X1 copy", nativeRows[0x15CA098].GetProperty("mnemonic").GetString() == "ldp" && nativeRows[0x15CA098].GetProperty("operands").GetString() == "x9, x8, [x8, #0x188]"
        && nativeRows[0x15CA0A0].GetProperty("mnemonic").GetString() == "mov" && nativeRows[0x15CA0A0].GetProperty("operands").GetString() == "x1, x8" && nativeRows[0x15CA0A4].GetProperty("mnemonic").GetString() == "blr");
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1"); Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins")); Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
    var app = Cpp2IlApi.CurrentAppContext!; var types = app.Assemblies.SelectMany(a => a.Types).ToArray();
    var xml = types.Single(t => t.FullName == "XmlExtensions");
    var selected = new[] { xml.Methods.Single(m => m.Name == "TryGetAttribute"), xml.Methods.Single(m => m.Name == "FirstAttribute"),
        types.Single(t => t.FullName == "YamlDotNet.Core.Emitter").Methods.Single(m => m.Name == "Write" && m.Parameters.Count == 1 && m.Parameters[0].ParameterType.FullName == "System.Char"),
        types.Single(t => t.FullName == "BestHTTP.WebSocket.Frames.WebSocketFrameReader").Methods.Single(m => m.Name == "Read") };
    var target = types.Single(t => t.FullName == "System.Xml.XmlNode").Methods.Single(m => m.Name == "get_Attributes" && m.Parameters.Count == 0);
    Check("original slot6 reference target signature", target.Definition!.slot == 6 && target.IsVirtual && !target.IsStatic && target.ReturnType.FullName == "System.Xml.XmlAttributeCollection");
    foreach (var method in selected)
    {
        string label = method.Name == "Read" ? "StreamRead" : method.Name == "Write" ? "YamlWrite" : method.Name;
        var stages = new List<object>();
        void Snapshot(string stage)
        {
            var rows = method.ControlFlowGraph!.Instructions.ToArray(); var proofs = rows.Where(i => i.NativeVirtualDispatch != null).ToArray();
            bool isFinal = stage == "emitter-input";
            if (label == "TryGetAttribute") Check(stage + " original copied-companion virtual call accepted", proofs.Length == 1 && proofs[0].Index == 13 && ReferenceEquals(proofs[0].Operands[0], target)
                && LegacyArm64VirtualDispatch.ValidForEmission(proofs[0], method) && proofs[0].NativeVirtualDispatch!.ParameterRoot is { } parameter && method.ParameterLocals.Contains(parameter) && parameter.Type?.FullName == "System.Xml.XmlNode");
            else if (label == "FirstAttribute") Check(stage + " prior two parameter-root getters accepted but producer-root Count stays indirect", proofs.Length == 2 && proofs.Select(i => i.Index).Order().SequenceEqual(new[] { 12, 33 }) && rows.Any(i => i.Index == 16 && i.OpCode == OpCode.IndirectCall && i.NativeVirtualDispatch == null));
            else if (label == "YamlWrite") Check(stage + " void plus explicit argument stays rejected", proofs.Length == 0 && rows.Any(i => i.Index == 10 && i.OpCode == OpCode.IndirectCall));
            else
            {
                Check(stage + " both original Stream virtual identities retained", proofs.Length == 2 && proofs.Select(i => i.Index).Order().SequenceEqual(new[] { 26, 36 }) && proofs.All(i => LegacyArm64VirtualDispatch.ValidForEmission(i, method)));
                var layout = rows.Where(i => i.NativeClassLayoutAbi != null).ToArray(); var overflow = rows.Where(i => i.NativeOverflowExceptionAbi != null).ToArray();
                Check(stage + " all four numeric layout diagnostics retain Boolean results and sole argument", layout.Length == 4 && layout.All(i => i.OpCode == OpCode.Call && i.Operands.Count == 3 && i.Operands[0] is Immediate n && n.UnsignedValue == 0xB04F60 && i.Destination is LocalVariable result && ReferenceEquals(result.Type, app.SystemTypes.SystemBooleanType)));
                Check(stage + " numeric overflow diagnostic and exact following throw retained", overflow.Length == 1 && overflow[0].OpCode == OpCode.Call && overflow[0].Operands.Count == 3 && overflow[0].Operands[0] is Immediate n && n.UnsignedValue == 0xB4D960 && overflow[0].Destination is LocalVariable r && ReferenceEquals(r.Type, app.SystemTypes.SystemExceptionType)
                    && rows.Any(i => i.Index == 207 && i.OpCode == OpCode.Throw && ReferenceEquals(i.Operands[0], overflow[0].Destination)));
                if (isFinal) Check("Stream final emission validation preserves both helper contracts and dead companion", layout.All(i => LegacyArm64ClassLayoutAbi.ValidForEmission(i, method)) && LegacyArm64OverflowExceptionAbi.ValidForEmission(overflow[0], method)
                    && !rows.Any(i => i.OpCode == OpCode.Move && i.Operands.Count == 2 && i.Operands[1] is MemoryOperand { Addend: 0x260 }));
            }
            var path = Guard($"analysis/il2cpp/virtual-companion-{label}-{stage}-v38.txt"); File.WriteAllText(path, string.Join("\n", method.ControlFlowGraph.Blocks.Select(b => b.ToString())));
            stages.Add(new { stage, proven_virtual_indices = proofs.Select(i => i.Index).ToArray(), indirect_indices = rows.Where(i => i.OpCode == OpCode.IndirectCall).Select(i => i.Index).ToArray(), private_graph = Path.GetRelativePath(root, path), private_graph_sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant() });
        }
        method.ConvertedIsil = app.InstructionSet.GetIsilFromMethod(method); method.ParameterOperands = app.InstructionSet.GetParameterOperandsFromMethod(method); method.ControlFlowGraph = new ISILControlFlowGraph(method.ConvertedIsil);
        StackAnalyzer.Analyze(method); method.DominatorInfo = new DominatorInfo(method.ControlFlowGraph); SsaForm.Build(method); LocalVariables.CreateAll(method); LegacyArm64ClassLayoutAbi.SeedResults(method); LegacyArm64OverflowExceptionAbi.SeedResults(method); FlagConditionRecovery.Run(method); DeadCodeEliminator.Run(method);
        if (label == "TryGetAttribute")
        {
            var rows = method.ControlFlowGraph.Instructions.ToArray(); var raw = rows.Single(i => i.Index == 13); var definitions = rows.Where(i => i.Destination is LocalVariable).GroupBy(i => (LocalVariable)i.Destination!).ToDictionary(g => g.Key, g => g.ToArray());
            var companion = (LocalVariable)raw.Operands[3]; var copy = definitions[companion].Single();
            Check("actual raw13 has original18operand ABI with X1 copy12", raw.OpCode == OpCode.IndirectCall && raw.Operands.Count == 18 && companion.Register.Name == "X1" && copy.Index == 12 && copy.OpCode == OpCode.Move && copy.Operands[1] is LocalVariable);
            var terminal = (LocalVariable)copy.Operands[1]; var load = definitions[terminal].Single();
            Check("actual companion copy reaches unique X8 paired memory load10", terminal.Register.Name == "X8" && load.Index == 10 && load.OpCode == OpCode.Move && load.Operands[1] is MemoryOperand { Addend: 0x190, Index: null, Scale: 0 });
            var block = method.ControlFlowGraph.Blocks.Single(b => b.Instructions.Contains(raw));
            Check("actual copy and terminal load are in dispatch block and ordered", block.Instructions.Contains(copy) && block.Instructions.Contains(load) && block.Instructions.IndexOf(load) < block.Instructions.IndexOf(copy) && block.Instructions.IndexOf(copy) < block.Instructions.IndexOf(raw));
        }
        MetadataResolver.ResolveAll(method); KeyFunctionRecovery.Run(method); DeadCodeEliminator.Run(method); MetadataInitGuardRemover.Run(method); WriteBarrierRecovery.Run(method); InjectedCheckRemover.Run(method); InterfaceDispatchRecovery.Run(method); LocalVariables.ResolveTypesAndFields(method); Snapshot("after-type");
        MetadataInitGuardRemover.RunRgctx(method); MetadataInitGuardRemover.RewriteUnguardedInits(method); DelegateInvokeRecovery.Run(method); BooleanFlagSimplifier.Run(method); DeadCodeEliminator.Run(method); SsaSimplifier.Run(method); for (int i = 0; i < 8 && ConstantFolder.Run(method); i++) SsaSimplifier.Run(method); Snapshot("simplified-ssa");
        InternalCallGuardRemover.Run(method); KeyFunctionRecovery.Run(method); SsaForm.Remove(method); CopyCoalescer.Run(method); Simplifier.Simplify(method); FloatLiteralRecovery.Run(method); ArrayRecovery.Run(method); LocalVariables.TypeAddressedLocals(method); ConstantBranchFolder.Run(method); EqualityBranchInverter.Run(method); CallArgumentTrimmer.Run(method); DeadCodeEliminator.Run(method); LocalVariables.RemoveUnused(method); Snapshot("emitter-input");
        methods.Add(new { label, registered_rva = "0x" + method.UnderlyingPointer.ToString("X"), stages });
    }
}
catch (Exception error) { fatal = error.ToString(); }
string status = fatal == null ? "PASS_ORIGINAL_COMPANION_COPY_THROUGH_PRODUCTION_WITH_SCOPE_REJECTIONS" : "VIRTUAL_COMPANION_PRODUCTION_GATE_FAILED";
var report = new { status, checks = checks.Count, tests = checks, methods, fatal, core_sha256 = coreHash, binary_sha256 = Hash("unpacked/effective/exefs/main"), metadata_sha256 = Hash("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat"),
    helper_source_sha256 = Hash("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64VirtualDispatch.cs"), probe_source_sha256 = Hash("src/re/VirtualCompanionProductionProbe/Program.cs"), private_native_inventory_sha256 = Hash("analysis/reconstruction/virtual-copy-root-v38/native-inventory.json"),
    core_modified_by_probe = false, game_methods_executed = 0, native_code_executed = false, recovered_cil_edited = false, full_clean_decompile_ready = false,
    scope = "Independent original four-method production pipeline survey. The exact76-byte native witness pins class/paired-slot/X8-to-X1/BLR flow. Actual TryGetAttribute rawSSA copy chain, proven same-parameter receiver identity and carrier survive to emitter input; the producer-root Count and void/argument Yaml call remain indirect. Existing Stream virtual sites and both numeric helper ABIs/explicit throw remain. Native override execution and actual recovered TryGetAttribute callvirt require separate evidence." };
File.WriteAllText(Guard("reports/virtual-companion-production-v38.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n"); Console.WriteLine(JsonSerializer.Serialize(new { status, checks = checks.Count, fatal })); return fatal == null ? 0 : 2;
