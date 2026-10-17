using System;
using System.Collections.Generic;
using System.Linq;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;

namespace Cpp2IL.Core.Utils;

/// <summary>One bounded, side-effect-free reference-receiver native vtable dispatch witness.</summary>
public static class LegacyArm64VirtualDispatch
{
    public static bool ValidForEmission(Instruction call, MethodAnalysisContext owner)
    {
        if (call.NativeVirtualDispatch is not { } proof || !ReferenceEquals(proof.Owner, owner)
            || !LegacyArm64Hfa.Enabled(owner) || call.OpCode is not (OpCode.Call or OpCode.CallVoid)
            || call.Operands.Count == 0 || !ReferenceEquals(call.Operands[0], proof.Target)
            || !ValidTarget(proof.Target, proof.Slot)) return false;
        int receiver = call.OpCode == OpCode.Call ? 2 : 1;
        if (call.Operands.Count <= receiver || proof.ParameterRoot is not { Type: { } parameterType } originalRoot
            || call.Operands[receiver] is not LocalVariable { Type: { IsValueType: false, IsInterface: false } receiverType } value
            || receiverType is ByRefTypeAnalysisContext or PointerTypeAnalysisContext
            || !DeclaresOnBase(proof.Target, receiverType) || owner.ControlFlowGraph is not { } graph) return false;
        var witness = new Witness(owner, graph);
        return witness.Ready && witness.Location(call, out var place) && witness.Prepare(place.Block)
            && witness.SameParameter(value, place, originalRoot, place, parameterType, out var root)
            && ReferenceEquals(root, originalRoot);
    }

    public static bool TryProve(MethodAnalysisContext owner, Instruction call, MethodAnalysisContext target,
        LocalVariable klass, int slot, out Instruction.NativeVirtualDispatchProof? proof)
    {
        proof = null;
        if (!LegacyArm64Hfa.Enabled(owner) || call.OpCode != OpCode.IndirectCall || !ValidTarget(target, slot)
            || owner.AppContext.InstructionSet.CallingConventionResolver?.HasRawArgumentLayout(call, owner.AppContext) != true
            || call.Operands.Count != 18 || call.Operands[2] is not LocalVariable receiver
            || klass.Type is not RuntimeClassTypeAnalysisContext { RepresentedType: { } receiverType }
            || receiverType.IsValueType || receiverType.IsInterface || receiverType.IsGenericInstance
            || receiverType.GenericParameters.Count != 0 || receiverType.Definition == null
            || slot >= receiverType.Definition.VtableCount || !DeclaresOnBase(target, receiverType)
            || owner.ControlFlowGraph is not { } graph) return false;
        var witness = new Witness(owner, graph);
        if (!witness.Ready || !witness.Location(call, out var callPlace) || !witness.Prepare(callPlace.Block)
            || !witness.Load(call.Operands[0], callPlace, out var function, out var functionPlace)
            || !witness.LoadCompanionCopies(call.Operands[3], callPlace, out var companion, out var companionPlace)
            || !witness.Load(klass, callPlace, out var classLoad, out var classPlace)
            || !ReferenceEquals(function.Base, klass) || !ReferenceEquals(companion.Base, klass)
            || function.Addend != 0x128L + 16L * slot || companion.Addend != function.Addend + 8
            || classLoad.Addend != 0 || classLoad.Base is not LocalVariable objectSource
            || !ReferenceEquals(classPlace.Block, callPlace.Block)
            || !ReferenceEquals(functionPlace.Block, callPlace.Block) || !ReferenceEquals(companionPlace.Block, callPlace.Block)
            || classPlace.Position >= functionPlace.Position || classPlace.Position >= companionPlace.Position
            || !witness.SameParameter(receiver, callPlace, objectSource, classPlace, receiverType, out var parameterRoot)) return false;
        // Moving a null fault past a field store/call is observable. The original
        // class dereference and both slot loads therefore form one local pure window.
        for (int position = classPlace.Position; position < callPlace.Position; position++)
        {
            var row = callPlace.Block.Instructions[position];
            if (position == classPlace.Position || position == functionPlace.Position || position == companionPlace.Position) continue;
            if (row.OpCode == OpCode.Nop || row.OpCode == OpCode.Move && row.Operands is [LocalVariable, LocalVariable]) continue;
            return false;
        }
        proof = new(owner, target, slot, parameterRoot);
        return true;
    }

    private static bool DeclaresOnBase(MethodAnalysisContext target, TypeAnalysisContext type)
    {
        var seen = new HashSet<TypeAnalysisContext>();
        for (int i = 0; i < 32 && seen.Add(type); i++)
        {
            if (ReferenceEquals(target.DeclaringType, type)) return true;
            if (type.BaseType is not { } parent) break;
            type = parent;
        }
        return false;
    }

    private static bool ValidTarget(MethodAnalysisContext target, int slot) =>
        slot >= 0 && target.Definition != null && target.Definition.slot == slot && !target.IsStatic && target.IsVirtual
        && target.Parameters.Count == 0 && target.GenericParameters.Count == 0 && target is not ConcreteGenericMethodAnalysisContext
        && target.DeclaringType is { IsValueType: false, IsInterface: false, IsGenericInstance: false } owner
        && owner.GenericParameters.Count == 0 && owner.Definition != null && slot < owner.Definition.VtableCount
        // The original BLR lift models its result in X0. FP/V0 and void/clobber
        // contracts need separate proof; neither is implied by virtual identity.
        && !target.IsVoid
        && (!target.ReturnType.IsValueType && target.ReturnType is not (ByRefTypeAnalysisContext or PointerTypeAnalysisContext or GenericParameterTypeAnalysisContext)
            || target.ReturnType.FullName is "System.Boolean" or "System.SByte" or "System.Byte" or "System.Int16"
                or "System.UInt16" or "System.Int32" or "System.UInt32" or "System.Int64" or "System.UInt64"
                or "System.Char");

    private readonly record struct Place(Block Block, int Position);
    private sealed class Witness
    {
        private readonly MethodAnalysisContext owner;
        private readonly ISILControlFlowGraph graph;
        private readonly Dictionary<Instruction, Place> locations = new();
        private readonly Dictionary<LocalVariable, List<Instruction>> definitions = new();
        private readonly HashSet<LocalVariable> roots = new();
        private readonly Dictionary<Block, HashSet<Block>> incoming = new();
        private readonly Dictionary<(Block, Block), bool> dominance = new();
        private HashSet<Block>? cone;
        public bool Ready { get; private set; }
        public Witness(MethodAnalysisContext owner, ISILControlFlowGraph graph)
        {
            this.owner = owner; this.graph = graph;
            if (graph.Blocks.Count is < 1 or > 4096 || graph.Blocks.Distinct().Count() != graph.Blocks.Count
                || !graph.Blocks.Contains(graph.EntryBlock)) return;
            foreach (var block in graph.Blocks) incoming.Add(block, new());
            foreach (var block in graph.Blocks)
            {
                foreach (var next in block.Successors)
                { if (!incoming.TryGetValue(next, out var previous)) return; previous.Add(block); }
                foreach (var previous in block.Predecessors)
                { if (!incoming.ContainsKey(previous)) return; incoming[block].Add(previous); }
                for (int i = 0; i < block.Instructions.Count; i++)
                {
                    var row = block.Instructions[i]; if (!locations.TryAdd(row, new(block, i)) || locations.Count > 65536) return;
                    if (row.Destination is LocalVariable local)
                    { if (!definitions.TryGetValue(local, out var defs)) definitions.Add(local, defs = new()); defs.Add(row); }
                }
            }
            Ready = true;
        }
        public bool Location(Instruction row, out Place place) => locations.TryGetValue(row, out place);
        public bool Prepare(Block call)
        {
            if (!Ready || !incoming.ContainsKey(call)) return false;
            var required = new HashSet<Block>(); var queue = new Queue<Block>(); queue.Enqueue(call);
            while (queue.Count != 0)
            {
                var block = queue.Dequeue(); if (!required.Add(block)) continue;
                foreach (var previous in incoming[block]) queue.Enqueue(previous);
            }
            if (!required.Contains(graph.EntryBlock)) return false;
            foreach (var block in required)
            {
                // Union reverse edges prevent an omitted predecessor record from
                // hiding an incoming path. Malformed edges on any path to this
                // call reject; unrelated later CFG defects are not repaired.
                if (block.Predecessors.Distinct().Count() != block.Predecessors.Count) return false;
                foreach (var previous in incoming[block])
                    if (block.Predecessors.Count(p => ReferenceEquals(p, previous)) != 1
                        || previous.Successors.Count(next => ReferenceEquals(next, block)) != 1) return false;
            }
            var reachable = new HashSet<Block>(); queue.Enqueue(graph.EntryBlock);
            while (queue.Count != 0)
            {
                var block = queue.Dequeue(); if (!reachable.Add(block)) continue;
                foreach (var next in block.Successors) if (required.Contains(next)) queue.Enqueue(next);
            }
            if (!reachable.SetEquals(required)) return false;
            cone = required; dominance.Clear(); return true;
        }
        private bool Available(Place definition, Place use)
        {
            if (cone == null || !cone.Contains(definition.Block) || !cone.Contains(use.Block)) return false;
            if (ReferenceEquals(definition.Block, use.Block)) return definition.Position < use.Position;
            var pair = (definition.Block, use.Block);
            if (dominance.TryGetValue(pair, out bool result)) return result;
            // Dominance is proved only on the fully validated cone, without
            // consulting the possibly malformed full graph's cached dominators.
            var visited = new HashSet<Block>(); var queue = new Queue<Block>(); queue.Enqueue(graph.EntryBlock);
            result = true;
            while (queue.Count != 0)
            {
                var block = queue.Dequeue(); if (ReferenceEquals(block, definition.Block) || !visited.Add(block)) continue;
                if (ReferenceEquals(block, use.Block)) { result = false; break; }
                foreach (var next in block.Successors) if (cone.Contains(next)) queue.Enqueue(next);
            }
            dominance.Add(pair, result); return result;
        }
        public bool Load(IOperand operand, Place use, out MemoryOperand memory, out Place place)
        {
            memory = default; place = default;
            if (operand is not LocalVariable local || !definitions.TryGetValue(local, out var defs) || defs.Count != 1
                || defs[0].OpCode != OpCode.Move || defs[0].Operands is not [_, MemoryOperand { Index: null, Scale: 0 } load]
                || !locations.TryGetValue(defs[0], out place) || !Available(place, use)) return false;
            roots.Add(local); memory = load; return true;
        }
        public bool LoadCompanionCopies(IOperand operand, Place use, out MemoryOperand memory, out Place place)
        {
            memory = default; place = default;
            var callBlock = use.Block;
            var visited = new HashSet<LocalVariable>();
            // Bound all defining locals, including the original paired memory
            // load. Function/class origins and receiver roots remain unchanged.
            for (int depth = 0; depth < 32; depth++)
            {
                if (operand is not LocalVariable local || !visited.Add(local)
                    || !definitions.TryGetValue(local, out var defs) || defs.Count != 1
                    || defs[0].OpCode != OpCode.Move || !locations.TryGetValue(defs[0], out var definition)
                    || !ReferenceEquals(definition.Block, callBlock) || !Available(definition, use)) return false;
                roots.Add(local);
                if (defs[0].Operands is [_, MemoryOperand { Index: null, Scale: 0 } load])
                {
                    memory = load; place = definition; return true;
                }
                if (defs[0].Operands is not [_, LocalVariable source]) return false;
                operand = source; use = definition;
            }
            return false;
        }
        private LocalVariable? Parameter(LocalVariable value, Place use, TypeAnalysisContext expected)
        {
            var active = new HashSet<LocalVariable>();
            for (int depth = 0; depth < 32 && active.Add(value); depth++)
            {
                roots.Add(value);
                if (!definitions.TryGetValue(value, out var defs))
                    return value.Register.Version == -1 && ReferenceEquals(value.Type, expected)
                        && owner.ParameterLocals.Any(p => !p.IsThis && !p.IsMethodInfo && ReferenceEquals(p.Type, expected)
                            && (ReferenceEquals(p, value) || p.Register.Version == -1 && p.Register.Name == value.Register.Name
                                && p.Register.Number == value.Register.Number)) ? value : null;
                if (defs.Count != 1 || defs[0].OpCode != OpCode.Move || defs[0].Operands is not [_, LocalVariable source]
                    || !locations.TryGetValue(defs[0], out var place) || !Available(place, use)) return null;
                value = source; use = place;
            }
            return null;
        }
        public bool SameParameter(LocalVariable left, Place leftUse, LocalVariable right, Place rightUse, TypeAnalysisContext type,
            out LocalVariable? root)
        {
            root = null;
            var a = Parameter(left, leftUse, type); var b = Parameter(right, rightUse, type);
            if (a == null || b == null || !ReferenceEquals(a, b)) return false;
            if (graph.Instructions.Any(row => row.Operands.Any(operand => Escapes(operand, 0)))) return false;
            root = a; return true;
        }
        private bool Escapes(IOperand operand, int depth) => depth > 12 || operand switch
        {
            AddressOf { Target: LocalVariable local } => roots.Contains(local),
            AddressOf address => Escapes(address.Target, depth + 1),
            MemoryOperand memory => memory.Base != null && Escapes(memory.Base, depth + 1) || memory.Index != null && Escapes(memory.Index, depth + 1),
            ArrayAccess array => Escapes(array.Index, depth + 1),
            _ => false
        };
    }
}
