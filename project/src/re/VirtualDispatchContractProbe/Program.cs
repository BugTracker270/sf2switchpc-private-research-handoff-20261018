using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using IOp = Cpp2IL.Core.ISIL.OpCode;

if (args.Length is < 1 or > 2 || args.Length == 2 && args[1] is not ("--v37" or "--v37-final")) throw new ArgumentException("Verified USB root and optional --v37/--v37-final required");
string reportLabel = args.Length == 2 ? args[1][2..] : "v36";
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string p = Path.GetFullPath(Path.Combine(root, relative));
    if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(p)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point");
    return p;
}
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var checks = new List<object>(); var selections = new List<object>(); var emissions = new List<object>(); var runtime = new List<object>();
string? fatal = null; int cases = 0;
void Check(string name, bool passed) { checks.Add(new { name, status = passed ? "PASS" : "FAIL" }); if (!passed) throw new Exception(name); }
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
    var stream = app.GetAssemblyByName("mscorlib")!.Types.Single(t => t.FullName == "System.IO.Stream");
    var reader = app.Assemblies.SelectMany(a => a.Types).Single(t => t.FullName == "BestHTTP.WebSocket.Frames.WebSocketFrameReader");
    var target = stream.Methods.Single(m => m.Name == "ReadByte" && m.Parameters.Count == 0);
    var integer = app.SystemTypes.SystemInt32Type;
    Check("original Stream ReadByte slot/signature", target.Definition!.slot == 19 && target.UnderlyingPointer == 0x8491A0
        && target.IsVirtual && !target.IsStatic && ReferenceEquals(target.ReturnType, integer));
    int identity = 0;
    Fixture Make()
    {
        var owner = new InjectedMethodAnalysisContext(reader, "VirtualWitness" + identity++, integer, MethodAttributes.Public | MethodAttributes.Static, [stream, stream]);
        var parameter = new LocalVariable("stream", new Register(null, "X0", -1), stream);
        var other = new LocalVariable("other_stream", new Register(null, "X1", -1), stream);
        owner.ParameterLocals.AddRange([parameter, other]);
        var copy = new LocalVariable("saved_stream", new Register(null, "X20", 1), stream);
        var klass = new LocalVariable("klass", new Register(null, "X8", 1), new RuntimeClassTypeAnalysisContext(stream, stream.DeclaringAssembly));
        var function = new LocalVariable("function", new Register(null, "X9", 1));
        var companion = new LocalVariable("method_info", new Register(null, "X1", 1));
        var receiver = new LocalVariable("receiver", new Register(null, "X0", 1), stream);
        var result = new LocalVariable("result", new Register(null, "X0", 2), integer);
        var instructions = new List<Instruction> {
            new(0, IOp.Move, copy, parameter), new(1, IOp.Move, klass, new MemoryOperand(copy)),
            new(2, IOp.Move, function, new MemoryOperand(klass, addend: 0x258)),
            new(3, IOp.Move, companion, new MemoryOperand(klass, addend: 0x260)), new(4, IOp.Move, receiver, copy)
        };
        var operands = new List<IOperand> { function, result, receiver, companion };
        for (int i = 2; i < 8; i++) operands.Add(new LocalVariable("raw_X" + i, new Register(null, "X" + i, -1)));
        for (int i = 0; i < 8; i++) operands.Add(new LocalVariable("raw_V" + i, new Register(null, "V" + i, -1)));
        var call = new Instruction(5, IOp.IndirectCall, operands); instructions.Add(call); instructions.Add(new(6, IOp.Return, result));
        owner.ControlFlowGraph = new ISILControlFlowGraph(instructions);
        var block = owner.ControlFlowGraph.Blocks.Single(b => b.Instructions.Contains(call));
        return new(owner, parameter, other, copy, klass, function, companion, receiver, result, call, block, target, 19);
    }
    string Snapshot(Fixture f) => string.Join("\n", f.Owner.ControlFlowGraph!.Blocks.Select(b => b.ToString()));
    void Selection(string name, bool expected, Action<Fixture>? mutate = null)
    {
        var f = Make(); mutate?.Invoke(f); string before = Snapshot(f);
        bool actual = LegacyArm64VirtualDispatch.TryProve(f.Owner, f.Call, f.Target, f.Klass, f.Slot, out var proof);
        Check(name, actual == expected && (actual ? proof != null && ReferenceEquals(proof.ParameterRoot, f.Parameter) : proof == null));
        Check(name + " proof is read-only", before == Snapshot(f));
        selections.Add(new { name, expected, accepted = actual });
    }
    Selection("exact paired slot19 and same original receiver", true);
    Selection("compatible reference return in X0", true, f => {
        f.Target = app.SystemTypes.SystemObjectType.Methods.Single(m => m.Name == "ToString" && m.Parameters.Count == 0);
        f.Slot = f.Target.Definition!.slot; f.Result.Type = f.Target.ReturnType;
        f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Function)).SetOperand(1, new MemoryOperand(f.Klass, addend: 0x128 + 16L * f.Slot));
        f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Companion)).SetOperand(1, new MemoryOperand(f.Klass, addend: 0x130 + 16L * f.Slot));
    });
    Selection("same receiver preserved through extra bounded copy", true, f => {
        var middle = new LocalVariable("middle", new Register(null, "copy", 1), stream);
        f.Block.Instructions.Insert(1, new Instruction(70, IOp.Move, middle, f.Copy));
        f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Klass)).SetOperand(1, new MemoryOperand(middle));
    });
    Selection("field store before class dereference keeps its original timing", true, f => f.Block.Instructions.Insert(0,
        new Instruction(68, IOp.Move, new MemoryOperand(f.Other, addend: 8), new Immediate(1))));
    Selection("semantic call after dispatch is outside the null-fault window", true, f => f.Block.Instructions.Insert(f.Block.Instructions.Count - 1,
        new Instruction(69, IOp.CallVoid, new Immediate(0x1000), f.Other)));
    Selection("missing raw argument", false, f => f.Call.RemoveOperandAt(17));
    Selection("wrong raw companion register", false, f => f.Companion.Register = new Register(null, "X2", 1));
    Selection("slot declaration mismatch", false, f => f.Slot = 18);
    Selection("negative slot", false, f => f.Slot = -1);
    Selection("large slot", false, f => f.Slot = int.MaxValue);
    Selection("wrong function offset", false, f => f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Function)).SetOperand(1, new MemoryOperand(f.Klass, addend: 0x268)));
    Selection("wrong companion offset", false, f => f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Companion)).SetOperand(1, new MemoryOperand(f.Klass, addend: 0x268)));
    Selection("indexed function-slot load", false, f => f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Function)).SetOperand(1, new MemoryOperand(f.Klass, f.Copy, 0x258, 1)));
    Selection("wrong companion class identity", false, f => f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Companion)).SetOperand(1,
        new MemoryOperand(new LocalVariable("other_klass", new Register(null, "other_klass", 1), f.Klass.Type), addend: 0x260)));
    Selection("wrong function class identity", false, f => f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Function)).SetOperand(1,
        new MemoryOperand(new LocalVariable("other_klass", new Register(null, "other_klass", 1), f.Klass.Type), addend: 0x258)));
    Selection("receiver from a different same-typed parameter", false, f => f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Receiver)).SetOperand(1, f.Other));
    Selection("wrong object class-header offset", false, f => f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Klass)).SetOperand(1, new MemoryOperand(f.Copy, addend: 8)));
    Selection("duplicate class definition", false, f => f.Block.Instructions.Insert(2, new Instruction(71, IOp.Move, f.Klass, new MemoryOperand(f.Copy))));
    Selection("late class definition", false, f => { var row = f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Klass)); f.Block.Instructions.Remove(row); f.Block.Instructions.Insert(f.Block.Instructions.IndexOf(f.Call) + 1, row); });
    Selection("copy-origin cycle", false, f => f.Block.Instructions[0].SetOperand(1, f.Receiver));
    Selection("receiver Phi origin", false, f => { var row = f.Block.Instructions.Single(i => ReferenceEquals(i.Destination, f.Receiver)); row.OpCode = IOp.Phi; row.SetOperands(f.Receiver, f.Parameter, f.Other); });
    Selection("root parameter address escape", false, f => f.Block.Instructions.Insert(0, new Instruction(72, IOp.Move,
        new LocalVariable("address_sink", new Register(null, "sink", 1)), new AddressOf(f.Parameter))));
    Selection("class address escape after call", false, f => f.Block.Instructions.Insert(f.Block.Instructions.Count - 1, new Instruction(73, IOp.Move,
        new LocalVariable("address_sink", new Register(null, "sink", 1)), new AddressOf(f.Klass))));
    Selection("field store in null-fault timing window", false, f => f.Block.Instructions.Insert(4, new Instruction(74, IOp.Move, new MemoryOperand(f.Parameter, addend: 8), new Immediate(1))));
    Selection("additional field read in null-fault timing window", false, f => f.Block.Instructions.Insert(4, new Instruction(75, IOp.Move,
        new LocalVariable("effect_load", new Register(null, "effect", 1)), new MemoryOperand(f.Parameter, addend: 8))));
    Selection("semantic call in null-fault timing window", false, f => f.Block.Instructions.Insert(4, new Instruction(76, IOp.CallVoid, new Immediate(0x1000), f.Parameter)));
    Selection("non-dominating original receiver copy", false, f => {
        var graph = f.Owner.ControlFlowGraph!; var entry = graph.EntryBlock; entry.Successors.Clear(); f.Block.Predecessors.Clear();
        var left = new Block { ID = 100 }; var right = new Block { ID = 101 };
        void Edge(Block a, Block b) { a.Successors.Add(b); b.Predecessors.Add(a); }
        Edge(entry, left); Edge(entry, right); Edge(left, f.Block); Edge(right, f.Block); graph.Blocks.AddRange([left, right]);
        var copy = f.Block.Instructions[0]; f.Block.Instructions.RemoveAt(0); left.Instructions.Add(copy);
    });
    Selection("duplicate graph block", false, f => f.Owner.ControlFlowGraph!.Blocks.Add(f.Block));
    Selection("asymmetric predecessor", false, f => f.Block.Predecessors.Clear());
    Selection("off-cone one-sided incoming successor edge", false, f => {
        var outside = new Block { ID = 201 }; outside.Successors.Add(f.Block); f.Owner.ControlFlowGraph!.Blocks.Add(outside);
    });
    Selection("off-cone one-sided incoming predecessor edge", false, f => {
        var outside = new Block { ID = 202 }; f.Block.Predecessors.Add(outside); f.Owner.ControlFlowGraph!.Blocks.Add(outside);
    });
    (Block A, Block B) LaterMalformed(Fixture f)
    {
        var graph = f.Owner.ControlFlowGraph!; var a = new Block { ID = 203 }; var b = new Block { ID = 204 };
        var ret = f.Block.Instructions[^1]; f.Block.Instructions.RemoveAt(f.Block.Instructions.Count - 1);
        graph.ExitBlock.Predecessors.Remove(f.Block); f.Block.Successors.Remove(graph.ExitBlock);
        f.Block.Successors.Add(a); a.Predecessors.Add(f.Block); a.Instructions.Add(new Instruction(77, IOp.Nop));
        a.Successors.Add(b); // Deliberate later-only missing reciprocal predecessor.
        b.Instructions.Add(ret); b.Successors.Add(graph.ExitBlock); graph.ExitBlock.Predecessors.Add(b);
        graph.Blocks.AddRange([a, b]); return (a, b);
    }
    Selection("genuinely later unrelated malformed subgraph does not certify whole-method topology", true, f => LaterMalformed(f));
    Selection("later malformed subgraph returning into the call cone rejects", false, f => {
        var later = LaterMalformed(f); later.B.Successors.Add(f.Block); f.Block.Predecessors.Add(later.B);
    });
    Selection("value-type represented receiver", false, f => f.Klass.Type = new RuntimeClassTypeAnalysisContext(integer, integer.DeclaringAssembly));
    Selection("interface represented receiver", false, f => { var t = app.GetAssemblyByName("mscorlib")!.Types.Single(t => t.FullName == "System.IDisposable"); f.Klass.Type = new RuntimeClassTypeAnalysisContext(t, t.DeclaringAssembly); });
    Selection("static target", false, f => { f.Target = new MethodAnalysisContext(target.Definition, stream); f.Target.Attributes |= MethodAttributes.Static; });
    Selection("nonvirtual target", false, f => { f.Target = new MethodAnalysisContext(target.Definition, stream); f.Target.Attributes &= ~MethodAttributes.Virtual; });
    Selection("generic method target", false, f => { f.Target = new MethodAnalysisContext(target.Definition, stream);
        var generic = app.GetAssemblyByName("mscorlib")!.Types.Single(t => t.FullName == "System.Collections.Generic.List`1"); f.Target.GenericParameters.Add(generic.GenericParameters[0]); });
    foreach (var resultType in new[] { app.SystemTypes.SystemSingleType, app.SystemTypes.SystemDoubleType, app.SystemTypes.SystemVoidType, new ByRefTypeAnalysisContext(integer) })
        Selection("unproved return ABI " + resultType.FullName, false, f => { f.Target = new MethodAnalysisContext(target.Definition, stream); f.Target.ReturnType = resultType; });
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", null);
    Selection("opt-in disabled", false);
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");

    Fixture Proven()
    {
        var f = Make(); Check("fresh semantic fixture proof", LegacyArm64VirtualDispatch.TryProve(f.Owner, f.Call, target, f.Klass, 19, out var proof));
        f.Call.OpCode = IOp.Call; f.Call.SetOperands(target, f.Result, f.Parameter); f.Call.NativeVirtualDispatch = proof;
        f.Owner.ControlFlowGraph = new ISILControlFlowGraph([f.Call, new Instruction(90, IOp.Return, f.Result)]);
        f.Owner.Locals = [f.Parameter, f.Other, f.Result]; return f;
    }
    var valid = Proven(); Check("proven Call emission accepts exact original root", LegacyArm64VirtualDispatch.ValidForEmission(valid.Call, valid.Owner));
    var cloned = new Instruction(valid.Call.Index, valid.Call.OpCode, valid.Call.Operands.ToList()) { NativeVirtualDispatch = valid.Call.NativeVirtualDispatch };
    valid.Owner.ControlFlowGraph = new ISILControlFlowGraph([cloned, new Instruction(91, IOp.Return, valid.Result)]);
    Check("fresh instruction clone retains exact immutable proof/root", !ReferenceEquals(cloned, valid.Call)
        && ReferenceEquals(cloned.NativeVirtualDispatch, valid.Call.NativeVirtualDispatch) && LegacyArm64VirtualDispatch.ValidForEmission(cloned, valid.Owner));
    var stale = Proven(); stale.Call.SetOperand(0, new MethodAnalysisContext(target.Definition, stream));
    Check("stale target rejects", !LegacyArm64VirtualDispatch.ValidForEmission(stale.Call, stale.Owner));
    stale = Proven(); stale.Call.SetOperand(2, stale.Other);
    Check("same-type second-parameter receiver substitution rejects", !LegacyArm64VirtualDispatch.ValidForEmission(stale.Call, stale.Owner));
    stale = Proven(); stale.Owner.ControlFlowGraph = new ISILControlFlowGraph([new Instruction(92, IOp.Move, stale.Parameter, stale.Other), stale.Call, new Instruction(93, IOp.Return, stale.Result)]);
    Check("redefined original root rejects", !LegacyArm64VirtualDispatch.ValidForEmission(stale.Call, stale.Owner));
    stale = Proven(); var old = stale.Call.NativeVirtualDispatch!; stale.Call.NativeVirtualDispatch = new(old.Owner, old.Target, old.Slot);
    Check("forged default-null proof root rejects", !LegacyArm64VirtualDispatch.ValidForEmission(stale.Call, stale.Owner));
    stale = Proven(); stale.Call.OpCode = IOp.Move;
    Check("stale opcode rejects", !LegacyArm64VirtualDispatch.ValidForEmission(stale.Call, stale.Owner));
    stale = Proven(); var foreign = Make(); Check("foreign owner rejects", !LegacyArm64VirtualDispatch.ValidForEmission(stale.Call, foreign.Owner));
    var forwarded = Proven(); var forwardedReceiver = new LocalVariable("forwarded_receiver", forwarded.Parameter.Register.Copy(1), stream);
    forwarded.Call.SetOperand(2, forwardedReceiver); forwarded.Owner.ControlFlowGraph = new ISILControlFlowGraph([new Instruction(94, IOp.Move, forwardedReceiver, forwarded.Parameter), forwarded.Call, new Instruction(95, IOp.Return, forwarded.Result)]);
    Check("legitimate same-root forwarding remains valid", LegacyArm64VirtualDispatch.ValidForEmission(forwarded.Call, forwarded.Owner));
    CopyCoalescer.Run(forwarded.Owner);
    Check("CopyCoalescer preserves exact protected proof root", LegacyArm64VirtualDispatch.ValidForEmission(forwarded.Call, forwarded.Owner)
        && ReferenceEquals(forwarded.Call.NativeVirtualDispatch!.ParameterRoot, forwarded.Parameter));

    // The real emitter is exercised with an explicit independent host member/type
    // boundary. Its emitted call opcode is copied, never changed by this probe.
    var module = new ModuleDefinition("VirtualContractFixture.dll");
    var assembly = new AssemblyDefinition("VirtualContractFixture", new Version(1, 0)); assembly.Modules.Add(module);
    var hostType = new TypeDefinition("Fixtures", "DispatchBase", AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes.Public, module.CorLibTypeFactory.Object.Type); module.TopLevelTypes.Add(hostType);
    var targetDefinition = new MethodDefinition("ReadByte", AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Public | AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Virtual,
        MethodSignature.CreateInstance(module.CorLibTypeFactory.Int32)); hostType.Methods.Add(targetDefinition);
    stream.PutExtraData("AsmResolverType", hostType); target.PutExtraData("AsmResolverMethod", targetDefinition);
    var corlib = ModuleDefinition.FromFile(typeof(int).Assembly.Location);
    integer.PutExtraData("AsmResolverType", corlib.TopLevelTypes.Single(t => t.FullName == "System.Int32"));
    var callerType = new TypeDefinition("Fixtures", "Caller", AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes.Public, module.CorLibTypeFactory.Object.Type); module.TopLevelTypes.Add(callerType);
    MethodDefinition Emit(Fixture f, string name, bool discard = false, bool clearProof = false)
    {
        if (discard) { f.Call.OpCode = IOp.CallVoid; f.Call.SetOperands(target, f.Parameter); f.Owner.ReturnType = app.SystemTypes.SystemVoidType;
            f.Owner.ControlFlowGraph = new ISILControlFlowGraph([f.Call, new Instruction(96, IOp.Return)]); }
        if (clearProof) f.Call.NativeVirtualDispatch = null;
        var definition = new MethodDefinition(name, AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Public | AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Static,
            MethodSignature.CreateStatic(discard ? module.CorLibTypeFactory.Void : module.CorLibTypeFactory.Int32, [hostType.ToTypeSignature(false), hostType.ToTypeSignature(false)]));
        definition.Parameters[0].GetOrCreateDefinition().Name = "stream"; definition.Parameters[1].GetOrCreateDefinition().Name = "other_stream";
        callerType.Methods.Add(definition); IlGenerator.GenerateIl(f.Owner, definition); return definition;
    }
    var callFixture = Proven(); var virtualDefinition = Emit(callFixture, "Virtual");
    var directFixture = Proven(); var directDefinition = Emit(directFixture, "DirectBase", clearProof: true);
    var discardFixture = Proven(); var discardDefinition = Emit(discardFixture, "VirtualDiscard", discard: true);
    Check("CallVoid with proven nonvoid target keeps dispatch identity", LegacyArm64VirtualDispatch.ValidForEmission(discardFixture.Call, discardFixture.Owner));
    foreach (var (name, definition, expected) in new[] { ("virtual", virtualDefinition, CilOpCodes.Callvirt), ("direct-base", directDefinition, CilOpCodes.Call), ("virtual-discard", discardDefinition, CilOpCodes.Callvirt) })
    {
        var calls = definition.CilMethodBody!.Instructions.Where(i => i.OpCode == CilOpCodes.Call || i.OpCode == CilOpCodes.Callvirt).ToArray();
        Check(name + " exact emitted target and opcode", calls.Length == 1 && calls[0].OpCode == expected && ReferenceEquals(calls[0].Operand, targetDefinition));
        emissions.Add(new { name, opcodes = definition.CilMethodBody.Instructions.Select(i => i.OpCode.ToString()), exact_target_identity_retained = true });
    }
    Check("discard emits a real result pop", discardDefinition.CilMethodBody!.Instructions.Count(i => i.OpCode == CilOpCodes.Pop) == 1);
    var invalidEmission = Proven(); invalidEmission.Call.SetOperand(2, invalidEmission.Other); bool emitterRejected = false;
    try { Emit(invalidEmission, "StaleReceiver"); } catch (InvalidOperationException error) when (error.Message.Contains("Stale or invalid proven native virtual dispatch")) { emitterRejected = true; }
    Check("real emitter refuses stale receiver instead of falling back to ordinary call", emitterRejected);
    var staleTargetEmission = Proven(); staleTargetEmission.Call.SetOperand(0, new MethodAnalysisContext(target.Definition, stream)); emitterRejected = false;
    try { Emit(staleTargetEmission, "StaleTarget"); } catch (InvalidOperationException error) when (error.Message.Contains("Stale or invalid proven native virtual dispatch")) { emitterRejected = true; }
    Check("real emitter refuses stale target before importing an unrelated descriptor", emitterRejected);
    string indirectCloneSource = File.ReadAllText(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64IndirectReturns.cs"));
    Check("existing temporary-graph clone source explicitly preserves the carrier", indirectCloneSource.Contains("NativeVirtualDispatch = row.NativeVirtualDispatch", StringComparison.Ordinal));

    Delegate Bind(MethodDefinition definition, bool discard)
    {
        var dynamic = new DynamicMethod("actual_emitter_" + definition.Name, discard ? typeof(void) : typeof(int), [typeof(DispatchBase), typeof(DispatchBase)], typeof(Program).Module, true);
        var il = dynamic.GetILGenerator(); var body = definition.CilMethodBody!;
        foreach (var local in body.LocalVariables) il.DeclareLocal(local.VariableType.FullName == "System.Int32" ? typeof(int) : typeof(DispatchBase));
        var labels = body.Instructions.ToDictionary(i => i, _ => il.DefineLabel());
        foreach (var row in body.Instructions)
        {
            il.MarkLabel(labels[row]);
            if (row.OpCode == CilOpCodes.Nop) il.Emit(OpCodes.Nop);
            else if (row.OpCode == CilOpCodes.Ldarg) il.Emit(OpCodes.Ldarg, (short)((AsmResolver.DotNet.Collections.Parameter)row.Operand!).Index);
            else if (row.OpCode == CilOpCodes.Ldarg_0) il.Emit(OpCodes.Ldarg_0);
            else if (row.OpCode == CilOpCodes.Ldarg_1) il.Emit(OpCodes.Ldarg_1);
            else if (row.OpCode == CilOpCodes.Ldloc) il.Emit(OpCodes.Ldloc, (short)((CilLocalVariable)row.Operand!).Index);
            else if (row.OpCode == CilOpCodes.Stloc) il.Emit(OpCodes.Stloc, (short)((CilLocalVariable)row.Operand!).Index);
            else if (row.OpCode == CilOpCodes.Call || row.OpCode == CilOpCodes.Callvirt)
            { if (!ReferenceEquals(row.Operand, targetDefinition)) throw new InvalidDataException("Unapproved emitted target boundary"); il.Emit(row.OpCode == CilOpCodes.Callvirt ? OpCodes.Callvirt : OpCodes.Call, typeof(DispatchBase).GetMethod(nameof(DispatchBase.ReadByte))!); }
            else if (row.OpCode == CilOpCodes.Br) il.Emit(OpCodes.Br, labels[((CilInstructionLabel)row.Operand!).Instruction!]);
            else if (row.OpCode == CilOpCodes.Pop) il.Emit(OpCodes.Pop);
            else if (row.OpCode == CilOpCodes.Ret) il.Emit(OpCodes.Ret);
            else throw new InvalidDataException("Unexpected real emitter opcode at explicit host boundary: " + row.OpCode);
        }
        return dynamic.CreateDelegate(discard ? typeof(Action<DispatchBase, DispatchBase>) : typeof(Func<DispatchBase, DispatchBase, int>));
    }
    var virt = (Func<DispatchBase?, DispatchBase?, int>)Bind(virtualDefinition, false);
    var direct = (Func<DispatchBase?, DispatchBase?, int>)Bind(directDefinition, false);
    var discardCall = (Action<DispatchBase?, DispatchBase?>)Bind(discardDefinition, true);
    for (int i = 0; i < 32; i++)
    {
        Effects.Reset(); int result = virt(new DispatchDerived(), null); cases++;
        Check("CLR virtual override result/effect " + i, result == 29 && Effects.Derived == 1 && Effects.Base == 0);
        Effects.Reset(); result = direct(new DispatchDerived(), null); cases++;
        Check("CLR deliberate base call retains direct result/effect " + i, result == 17 && Effects.Base == 1 && Effects.Derived == 0);
        Effects.Reset(); discardCall(new DispatchDerived(), null); cases++;
        Check("CLR CallVoid discard preserves override effect " + i, Effects.Derived == 1 && Effects.Base == 0);
    }
    foreach (var (name, invoke) in new (string, Action)[] { ("virtual-null", () => virt(null, new DispatchDerived())), ("discard-null", () => discardCall(null, new DispatchDerived())) })
    {
        Effects.Reset(); Exception? observed = null; try { invoke(); } catch (Exception error) { observed = error; } cases++;
        Check(name + " rejects before any base/override effect", observed is NullReferenceException && Effects.Base == 0 && Effects.Derived == 0);
        runtime.Add(new { name, exception = observed!.GetType().FullName, base_effects = Effects.Base, override_effects = Effects.Derived });
    }
    Effects.Reset(); int nullBase = direct(null, new DispatchDerived()); cases++;
    Check("direct base control may run a body that does not dereference null this", nullBase == 17 && Effects.Base == 1 && Effects.Derived == 0);
    runtime.Add(new { name = "direct-null-control", result = nullBase, base_effects = Effects.Base, override_effects = Effects.Derived });
}
catch (Exception error) { fatal = error.ToString(); }
bool passed = fatal == null && checks.All(c => JsonSerializer.Serialize(c).Contains("PASS"));
var output = new { status = passed ? "PASS_NATIVE_VIRTUAL_WITNESS_AND_REAL_EMITTER_CLR_CONTRACT" : "VIRTUAL_WITNESS_CONTRACT_GATE_FAILED",
    checks = checks.Count, cases, tests = checks, selections, emissions, runtime_controls = runtime, fatal,
    core_sha256 = coreHash, binary_sha256 = Hash(binary), metadata_sha256 = Hash(metadata),
    helper_source_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64VirtualDispatch.cs")),
    emitter_source_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/IlGenerator.cs")),
    instruction_source_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/ISIL/Instruction.cs")),
    probe_source_sha256 = Hash(Guard("src/re/VirtualDispatchContractProbe/Program.cs")),
    core_modified_by_probe = false, game_methods_executed = 0, native_code_executed = false,
    emitter_tests_are_synthetic = true, actual_recovered_runtime_performed = false, emitted_call_opcodes_rewritten_by_probe = 0,
    host_fixture_member_substitutions = 1, host_fixture_type_boundary = "Original Stream metadata target is bound to explicitly authored DispatchBase.ReadByte() for CLR opcode-contract tests only",
    scope = "Independent synthetic raw-ISIL selection and proof-carrier/emitter tests using exact original Stream.ReadByte metadata. The real production proof and IlGenerator run; emitted call/callvirt and target identity are retained at an explicitly authored host type/member boundary, then executed to distinguish override/direct/null effects. FP/void targets remain unproved native return ABIs; CallVoid tests discard a proven nonvoid target only. This does not execute an original/recovered game caller, repair MethodInfo diagnostic loads, validate native null exceptions or claim full decompilation. Actual recovered-prefix and unchanged-native fixture reports are separate." };
File.WriteAllText(Guard($"reports/virtual-dispatch-contract-{reportLabel}.json"), JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { output.status, output.checks, cases, fatal }));
return passed ? 0 : 2;

sealed class Fixture(MethodAnalysisContext owner, LocalVariable parameter, LocalVariable other, LocalVariable copy, LocalVariable klass,
    LocalVariable function, LocalVariable companion, LocalVariable receiver, LocalVariable result, Instruction call, Block block, MethodAnalysisContext target, int slot)
{
    public MethodAnalysisContext Owner = owner, Target = target;
    public LocalVariable Parameter = parameter, Other = other, Copy = copy, Klass = klass, Function = function, Companion = companion, Receiver = receiver, Result = result;
    public Instruction Call = call; public Block Block = block; public int Slot = slot;
}
public static class Effects { public static int Base, Derived; public static void Reset() { Base = Derived = 0; } }
public class DispatchBase { public virtual int ReadByte() { Effects.Base++; return 17; } }
public sealed class DispatchDerived : DispatchBase { public override int ReadByte() { Effects.Derived++; return 29; } }
