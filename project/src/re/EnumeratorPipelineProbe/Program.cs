using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;

if (args.Length != 1 && (args.Length != 2 || args[1] is not ("--prototype-hidden-buffer" or "--prototype-native-buffer"))) throw new ArgumentException("Verified USB root and optional explicit prototype mode required");
bool prototype = args.Length == 2;
bool nativePrototype = prototype && args[1] == "--prototype-native-buffer";
if (prototype) Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
string suffix = nativePrototype ? "v32-native-prototype" : prototype ? "v32-prototype" : "v31";
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point");
    return path;
}
string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
string binary = Guard("unpacked/effective/exefs/main"), metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (Hash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Original input differs");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var method = app.Assemblies.SelectMany(a => a.Types).Single(t => t.FullName == "Nekki.SF2.Core.Fights.Fight")
    .Methods.Single(m => m.Name == "SetStage" && m.UnderlyingPointer == 0xC9F3F0);
method.EnsureRawBytes();
var converted = app.InstructionSet.GetIsilFromMethod(method);
var copies = converted.ToDictionary(i => i, i => new Instruction(i.Index, i.OpCode, i.Operands.ToList()) { ImplicitDefinition = i.ImplicitDefinition });
foreach (var copy in copies.Values)
    for (int i = 0; i < copy.Operands.Count; i++)
        if (copy.Operands[i] is Instruction target) copy.SetOperand(i, copies[target]);
method.ConvertedIsil = converted.Select(i => copies[i]).ToList();
method.ParameterOperands = app.InstructionSet.GetParameterOperandsFromMethod(method);
method.ControlFlowGraph = new ISILControlFlowGraph(method.ConvertedIsil);
var stages = new List<object>();
var privateStages = new List<object>();
object? prototypeGuards = null;
object? nativeDescriptor = null;
object? finalIrAssertions = null;
void Snapshot(string stage)
{
    var instructions = method.ControlFlowGraph!.Instructions.ToArray();
    ulong Target(IOperand operand) => operand is Immediate immediate ? immediate.UnsignedValue : operand is MethodAnalysisContext resolved ? resolved.UnderlyingPointer : 0;
    var relevantCalls = instructions.Where(i => i.IsCall && (i.Index is 86 or 95 or 101 or 135 || Target(i.Operands[0]) is 0x1585F60 or 0x11DD3E0 or 0x11DD540 or 0x11DD3B0)).ToArray();
    stages.Add(new
    {
        stage, instructions = instructions.Length,
        calls = relevantCalls.Select(i => new { i.Index, target_rva = $"0x{Target(i.Operands[0]):X}",
            target_context = i.Operands[0].GetType().Name, resolved_method = i.Operands[0] is MethodAnalysisContext m ? m.FullName : null,
            destination = i.Destination?.ToString(), argument_operands = i.Operands.Skip(i.OpCode == OpCode.Call ? 2 : 1).Select(o => new { kind = o.GetType().Name, value = o.ToString() }).ToArray(),
            implicit_definition = i.ImplicitDefinition?.ToString() }).ToArray(),
        tracked_storage_definitions = instructions.Where(i => i.Destination?.ToString()?.Contains("stack_-68") == true)
            .Select(i => new { i.Index, op = i.OpCode.ToString(), destination = i.Destination!.ToString(),
                source_operands = i.SourcesAndConstants.Select(o => new { kind = o.GetType().Name, value = o.ToString() }).ToArray() }).ToArray(),
        stack_addresses = instructions.Where(i => i.Operands.Any(o => o is AddressOf || o is StackOffset))
            .Select(i => new { i.Index, op = i.OpCode.ToString(), destination = i.Destination?.ToString(),
                address_operands = i.Operands.OfType<AddressOf>().Select(o => new { kind = o.Target.GetType().Name, target = o.Target.ToString() }).ToArray(),
                implicit_definition = i.ImplicitDefinition?.ToString() }).ToArray()
    });
    privateStages.Add(new { stage, blocks = method.ControlFlowGraph.Blocks.Select(b => b.ToString()).ToArray() });
}
Snapshot("raw-converted-before-stack");
if (prototype)
{
    var call = method.ConvertedIsil.Single(i => i.OpCode == OpCode.Call && i.Operands[0] is Immediate target && target.UnsignedValue == 0x1585F60);
    int position = method.ConvertedIsil.IndexOf(call);
    var previous = method.ConvertedIsil[position - 1];
    if (previous.OpCode != OpCode.Move || previous.Operands[0] is not Register { Name: "X8" }
        || previous.Operands[1] is not AddressOf { Target: StackOffset buffer } || buffer.Offset != 8)
        throw new InvalidOperationException("Exact adjacent direct-SP hidden-buffer witness differs");
    var aliases = app.MethodsByAddress[0x1585F60];
    var callee = aliases.OrderByDescending(m => m.Parameters.Count + (m.IsStatic ? 0 : 1)).First();
    bool hidden = app.InstructionSet.CallingConventionResolver!.ReturnsViaHiddenBuffer(callee);
    bool hfa = LegacyArm64Hfa.ReturnShape(callee) != null;
    bool UsesX0(IOperand operand) => operand switch
    {
        Register { Name: "X0" } => true,
        MemoryOperand memory => memory.Base is Register { Name: "X0" } || memory.Index is Register { Name: "X0" },
        AddressOf { Target: Register { Name: "X0" } } => true,
        _ => false
    };
    var callBlock = method.ControlFlowGraph!.Blocks.Single(b => b.Instructions.Contains(call));
    var queue = new Queue<(Block block, int start)>();
    queue.Enqueue((callBlock, callBlock.Instructions.IndexOf(call) + 1));
    var visited = new HashSet<(Block, int)>();
    int visitedInstructions = 0, stoppedOnOverwrite = 0;
    while (queue.Count > 0)
    {
        var (block, start) = queue.Dequeue();
        if (!visited.Add((block, start))) continue;
        bool overwritten = false;
        foreach (var row in block.Instructions.Skip(start))
        {
            visitedInstructions++;
            if (row.SourcesAndConstants.Any(UsesX0)) throw new InvalidOperationException($"Native X0 pointer remains live at ISIL {row.Index}");
            if (row.Destination is Register { Name: "X0" } || row.ImplicitDefinition is Register { Name: "X0" })
            { overwritten = true; stoppedOnOverwrite++; break; }
        }
        if (!overwritten) foreach (var next in block.Successors) queue.Enqueue((next, 0));
    }
    bool nativeDescriptorAccepted = false;
    if (nativePrototype)
    {
        ulong metadataSlot = app.Binary.ReadPointerAtVirtualAddress(0x39D61A0);
        var concrete = app.ResolveContextForMethod(app.LibCpp2IlContext.GetMethodGlobalByAddress(metadataSlot)) as ConcreteGenericMethodAnalysisContext
            ?? throw new InvalidOperationException("Actual concrete method context missing");
        if (metadataSlot != 0x3B4CE60 || concrete.UnderlyingPointer is not (0 or 0x1585F60)
            || concrete.ReturnType is not GenericInstanceTypeAnalysisContext concreteReturn)
            throw new InvalidOperationException("Exact caller metadata usage differs");
        var matchingRegistered = aliases.OfType<ConcreteGenericMethodAnalysisContext>().Where(a =>
            ReferenceEquals(a.BaseMethodContext, concrete.BaseMethodContext)
            && a.TypeGenericParameters.SequenceEqual(concrete.TypeGenericParameters)
            && a.MethodGenericParameters.SequenceEqual(concrete.MethodGenericParameters)
            && a.UnderlyingPointer == 0x1585F60).ToArray();
        if (matchingRegistered.Length == 0) throw new InvalidOperationException("No equivalent concrete registered native alias");
        bool ContainsUnknown(TypeAnalysisContext t) => t is GenericParameterTypeAnalysisContext
            || (t is GenericInstanceTypeAnalysisContext g ? g.GenericArguments.Any(ContainsUnknown) : t.GenericParameters.Count != 0);
        bool IsKnownReference(TypeAnalysisContext t) => !t.IsValueType && !ContainsUnknown(t)
            && t is not ByRefTypeAnalysisContext and not PointerTypeAnalysisContext;
        if (!ReferenceEquals(concreteReturn.GenericType.DeclaringType, concrete.BaseMethodContext.DeclaringType))
            throw new InvalidOperationException("Nested enumerator ownership differs from List definition");
        int concreteCount = 0, openDefinitionCount = 0;
        foreach (var alias in aliases)
        {
            if (alias.Name != "GetEnumerator" || alias.IsStatic || alias.Parameters.Count != 0 || alias.GenericParameters.Count != 0)
                throw new InvalidOperationException("Shared native callee signature ambiguity");
            if (alias is not ConcreteGenericMethodAnalysisContext closed)
            {
                if (!ReferenceEquals(alias, concrete.BaseMethodContext)) throw new InvalidOperationException("Unrelated open alias");
                openDefinitionCount++; continue;
            }
            if (!ReferenceEquals(closed.BaseMethodContext, concrete.BaseMethodContext)
                || closed.TypeGenericParameters.Count != 1 || closed.MethodGenericParameters.Count != 0
                || !IsKnownReference(closed.TypeGenericParameters[0])
                || closed.ReturnType is not GenericInstanceTypeAnalysisContext resultType
                || !ReferenceEquals(resultType.GenericType, concreteReturn.GenericType) || resultType.GenericArguments.Count != 1
                || !ReferenceEquals(resultType.GenericArguments[0], closed.TypeGenericParameters[0])
                || !resultType.IsValueType || LegacyArm64Hfa.ReturnShape(closed) != null)
                throw new InvalidOperationException("Unknown/non-reference shared return alias rejected");
            concreteCount++;
        }
        if (openDefinitionCount != 1 || concreteCount != 278) throw new InvalidOperationException("Reviewed alias set differs");
        byte[] Code(ulong rva, int length) => app.Binary.GetRawBinaryContent().Slice(checked((int)app.Binary.MapVirtualAddressToRaw(rva)), length).ToArray();
        string BytesHash(byte[] code) => Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant();
        if (BytesHash(Code(0x1585F60, 36)) != "43694a140756dab00d417fb317762c8d7e917bea857ba9368f482b6e80c7235a"
            || BytesHash(Code(0x11DD130, 16)) != "93f97aee4056e153eb26e662e2518b5597090fb7491333fa0a160c01ed376afe")
            throw new InvalidOperationException("Reviewed native return/constructor body differs");
        string framesPath = Guard("analysis/nso/unwind-inventory-v1/frames.jsonl");
        if (Hash(framesPath) != "aa464d27b080531baa5dfbd5591c63ba331fbded3091ff8eca6f054d87369abf") throw new InvalidOperationException("Reviewed FDE inventory differs");
        var frames = new Dictionary<int, int>();
        foreach (string line in File.ReadLines(framesPath))
        {
            using var json = JsonDocument.Parse(line);
            int rva = json.RootElement.GetProperty("rva").GetInt32();
            if (rva is 0x1585F60 or 0x11DD130) frames.Add(rva, json.RootElement.GetProperty("end_rva").GetInt32());
        }
        if (frames.GetValueOrDefault(0x1585F60) != 0x1585F84 || frames.GetValueOrDefault(0x11DD130) != 0x11DD140)
            throw new InvalidOperationException("Reviewed native FDE boundaries differ");
        var nativeReport = JsonDocument.Parse(File.ReadAllText(Guard("reports/enumerator-native-return-v31.json"))).RootElement;
        if (nativeReport.GetProperty("status").GetString() != "PASS_ORIGINAL_NATIVE_INDIRECT_ENUMERATOR_RETURN_ONLY"
            || nativeReport.GetProperty("native_source_sha256").GetString() != "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968"
            || nativeReport.GetProperty("checks").GetInt32() != 36) throw new InvalidOperationException("Bounded native return witness differs");
        nativeDescriptorAccepted = true;
        nativeDescriptor = new { kind = "EXACT_NATIVE_REVIEWED_LIST_REFERENCE_ENUMERATOR_RETURN_ONLY", byte_size = 24,
            target_rva = "0x1585F60", concrete_aliases_verified = concreteCount, open_signature_definition_verified = openDefinitionCount,
            actual_concrete_methodinfo = concrete.FullName, methodinfo_metadata_slot = "0x3B4CE60",
            methodinfo_context_pointer = $"0x{concrete.UnderlyingPointer:X}", matching_registered_native_aliases = matchingRegistered.Length,
            methodinfo_pointer_scope = "MetadataUsage.AsGenericMethodRef constructs a fresh metadata-only method ref without assigning GenericVariantPtr. The exact direct BL target is independently matched through registered aliases using the same base and concrete generic type identities.",
            existing_classifier_result = hidden, existing_metadata_size = TypeSizes.UnboxedSize(concreteReturn, 8),
            complete_native_code_hash_and_fde_match = true, native_report_sha256 = Hash(Guard("reports/enumerator-native-return-v31.json")),
            inference_scope = "This explicit descriptor overrides the false size-zero classification only for this reviewed native shared reference-enumerator body and copied SetStage experiment. It is not a general generic-size or ABI rule." };
    }
    if ((!hidden || hfa) && !nativeDescriptorAccepted)
    {
        ulong metadataSlot = app.Binary.ReadPointerAtVirtualAddress(0x39D61A0);
        var concrete = app.ResolveContextForMethod(app.LibCpp2IlContext.GetMethodGlobalByAddress(metadataSlot));
        object Describe(MethodAnalysisContext candidate) => new { method = candidate.FullName, return_type = candidate.ReturnType.FullName,
            return_context = candidate.ReturnType.GetType().Name, value_type = candidate.ReturnType.IsValueType,
            metadata_unboxed_size = TypeSizes.UnboxedSize(candidate.ReturnType, 8),
            hidden_buffer = app.InstructionSet.CallingConventionResolver.ReturnsViaHiddenBuffer(candidate),
            hfa = LegacyArm64Hfa.ReturnShape(candidate) != null };
        File.WriteAllText(Guard("reports/enumerator-pipeline-v32-prototype-blocker.json"), JsonSerializer.Serialize(new
        {
            status = "BLOCKED_EXISTING_RETURN_BUFFER_CLASSIFIER_REJECTS_ACTUAL_CALLEE", core_edited = false,
            copied_ir_mutated = false, core_sha256 = Hash(typeof(SsaForm).Assembly.Location),
            probe_source_sha256 = Hash(Guard("src/re/EnumeratorPipelineProbe/Program.cs")),
            native_x0_read_before_overwrite = false, visited_instructions = visitedInstructions, stopped_on_overwrite = stoppedOnOverwrite,
            selected_alias = Describe(callee), aliases = aliases.Select(Describe).ToArray(),
            methodinfo_got_address = "0x39D61A0", methodinfo_metadata_slot = $"0x{metadataSlot:X}",
            actual_concrete_methodinfo = concrete == null ? null : Describe(concrete)
        }, new JsonSerializerOptions { WriteIndented = true }));
        throw new InvalidOperationException("Selected actual callee hidden-buffer classification differs; exact type/metadata and native X0 liveness observations saved");
    }
    prototypeGuards = new { alias_count = aliases.Count, selected_callee = callee.FullName, return_type = callee.ReturnType.FullName,
        returns_via_hidden_buffer = hidden, hfa_return = hfa, buffer_offset = buffer.Offset,
        explicit_native_descriptor_used = nativeDescriptorAccepted,
        native_x0_read_before_overwrite = false, visited_instructions = visitedInstructions, stopped_on_overwrite = stoppedOnOverwrite,
        native_x8_address_is_unchanged_adjacent_operand = true, changed_isil_call_index = call.Index,
        original_destination = call.Destination!.ToString(), replacement = buffer.ToString() };
    call.Destination = buffer;
    Snapshot("counterfactual-direct-buffer-call-destination-before-stack");
}
StackAnalyzer.Analyze(method); Snapshot("stack-normalized-before-ssa");
method.DominatorInfo = new DominatorInfo(method.ControlFlowGraph!);
SsaForm.Build(method); Snapshot("ssa-before-local-allocation");
LocalVariables.CreateAll(method); Snapshot("ssa-with-local-identities");
if (prototype)
{
    FlagConditionRecovery.Run(method); DeadCodeEliminator.Run(method);
    MetadataResolver.ResolveAll(method);
    KeyFunctionRecovery.Run(method); DeadCodeEliminator.Run(method);
    MetadataInitGuardRemover.Run(method); WriteBarrierRecovery.Run(method); InjectedCheckRemover.Run(method);
    InterfaceDispatchRecovery.Run(method); LocalVariables.ResolveTypesAndFields(method);
    MetadataInitGuardRemover.RunRgctx(method); MetadataInitGuardRemover.RewriteUnguardedInits(method);
    DelegateInvokeRecovery.Run(method); BooleanFlagSimplifier.Run(method); DeadCodeEliminator.Run(method);
    SsaSimplifier.Run(method);
    for (var i = 0; i < 8 && ConstantFolder.Run(method); i++) SsaSimplifier.Run(method);
    InternalCallGuardRemover.Run(method); KeyFunctionRecovery.Run(method);
    SsaForm.Remove(method); CopyCoalescer.Run(method); Simplifier.Simplify(method);
    FloatLiteralRecovery.Run(method); ArrayRecovery.Run(method); LocalVariables.TypeAddressedLocals(method);
    ConstantBranchFolder.Run(method); EqualityBranchInverter.Run(method); CallArgumentTrimmer.Run(method);
    DeadCodeEliminator.Run(method); LocalVariables.RemoveUnused(method);
    var finalRows = method.ControlFlowGraph!.Instructions;
    var resultCall = finalRows.Single(i => i.Index == 86);
    if (resultCall.OpCode != OpCode.Call || resultCall.Destination is not LocalVariable result
        || result.Type is not GenericInstanceTypeAnalysisContext resultType || !resultType.IsValueType
        || resultCall.Operands[0] is not ConcreteGenericMethodAnalysisContext resultMethod || resultMethod.Name != "GetEnumerator"
        || resultType.GenericArguments.Count != 1 || resultType.GenericArguments[0].FullName != "Nekki.SF2.Core.Fights.Model.Model")
        throw new InvalidOperationException("Counterfactual final result type or closed method differs");
    var expected = new[] { (index: 95, name: "MoveNext"), (index: 101, name: "get_Current"), (index: 135, name: "Dispose") };
    var consumers = new List<object>();
    foreach (var entry in expected)
    {
        var row = finalRows.Single(i => i.Index == entry.index);
        if (!row.IsCall || row.Operands[0] is not MethodAnalysisContext consumer || consumer.Name != entry.name
            || row.Operands[row.OpCode == OpCode.Call ? 2 : 1] is not AddressOf { Target: LocalVariable receiver }
            || !ReferenceEquals(receiver, result)) throw new InvalidOperationException("Counterfactual consumer storage mismatch");
        consumers.Add(new { isil_index = entry.index, method = consumer.FullName, same_result_storage_identity = true });
    }
    int definitions = finalRows.Count(i => ReferenceEquals(i.Destination, result));
    int zeroStores = finalRows.Count(i => i.OpCode == OpCode.Move && ReferenceEquals(i.Destination, result)
        && i.Operands[1] is Immediate literal && literal.UnsignedValue == 0);
    if (definitions != 1 || zeroStores != 0) throw new InvalidOperationException("Counterfactual result storage retains another definition");
    finalIrAssertions = new { status = "PASS_EXACT_COPIED_IR_RESULT_AND_CONSUMER_STORAGE_ONLY", checks = 6,
        result_type = result.Type.FullName, resolved_getenumerator = resultMethod.FullName,
        result_storage = result.Register.ToString(), consumers, result_storage_definitions = definitions, scalar_zero_stores = zeroStores,
        game_executed = false, recovered_cil_generated = false, production_changed = false };
    Snapshot("counterfactual-through-existing-final-IR-pipeline");
}
var options = new JsonSerializerOptions { WriteIndented = true };
File.WriteAllText(Guard($"analysis/il2cpp/enumerator-pipeline-stages-{suffix}.json"), JsonSerializer.Serialize(privateStages, options));
File.WriteAllText(Guard($"reports/enumerator-pipeline-{suffix}.json"), JsonSerializer.Serialize(new
{
    status = prototype ? "COUNTERFACTUAL_DIRECT_BUFFER_RESULT_PIPELINE_OBSERVATIONS_ONLY" : "READ_ONLY_ACTUAL_CALLER_STACK_AND_SSA_OBSERVATIONS", caller = method.FullName, caller_rva = "0xC9F3F0",
    prototype, nativePrototype, prototype_guards = prototypeGuards, native_descriptor = nativeDescriptor, final_ir_assertions = finalIrAssertions,
    probe_source_sha256 = Hash(Guard("src/re/EnumeratorPipelineProbe/Program.cs")),
    tool_core_sha256 = Hash(typeof(SsaForm).Assembly.Location), original_binary_sha256 = Hash(binary), original_metadata_sha256 = Hash(metadata),
    source_hashes = new[] { "InstructionSets/NewArmV8InstructionSet.cs", "Analysis/StackAnalyzer.cs", "Analysis/SsaForm.cs", "Analysis/LocalVariables.cs", "Model/Contexts/MethodAnalysisContext.cs" }
        .Select(p => new { file = "refs/Cpp2IL/Cpp2IL.Core/" + p, sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/" + p)) }),
    original_game_code_executed = false, core_modified = false, production_output_modified = false, stages,
    scope = prototype ? "Counterfactual prototype on a fresh copied actual SetStage ISIL only: change a verified direct-SP-buffer managed-call destination before SSA, then run existing passes. No production source/CIL/binary changed, no game method executed. Symbolic observations do not establish recovered behavior; actual output CIL, source and runtime must still be tested."
        : "Unmodified actual SetStage conversion, stack normalization, SSA and local allocation only. Symbolic operand identities are observations, not recovered behavior. No initializer/default-value substitution, call retargeting or production fixes. The original native ownership and CIL counterexamples are tested separately."
}, options));
Console.WriteLine($"Actual caller pipeline observation saved: {stages.Count} stages; prototype={prototype}; no production changes");
