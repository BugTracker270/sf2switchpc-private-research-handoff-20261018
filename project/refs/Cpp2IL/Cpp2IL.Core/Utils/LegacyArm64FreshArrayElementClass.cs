using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;

namespace Cpp2IL.Core.Utils;

/// <summary>
/// Read-only origin evidence for a reviewed native element-class input. This never
/// supplies IsInst semantics, changes operands, suppresses a call or authorizes CIL.
/// </summary>
public static class LegacyArm64FreshArrayElementClass
{
    public sealed class Proof
    {
        public MethodAnalysisContext Owner { get; }
        public Instruction Call { get; }
        public Instruction Allocation { get; }
        public LocalVariable Array { get; }
        public SzArrayTypeAnalysisContext ArrayType { get; }
        public TypeAnalysisContext ElementType => ArrayType.ElementType;
        public IReadOnlyList<Instruction> Definitions { get; }
        internal IOperand ClassInput { get; }
        internal Instruction Header { get; }
        internal MemoryOperand.NativeReadProof HeaderRead { get; }
        internal MemoryOperand.NativeReadProof ElementRead { get; }

        internal Proof(MethodAnalysisContext owner, Instruction call, Instruction allocation,
            LocalVariable array, SzArrayTypeAnalysisContext type, IOperand classInput, Instruction header,
            MemoryOperand.NativeReadProof headerRead, MemoryOperand.NativeReadProof elementRead,
            IEnumerable<Instruction> definitions)
        {
            Owner = owner; Call = call; Allocation = allocation; Array = array; ArrayType = type;
            ClassInput = classInput; Header = header; HeaderRead = headerRead; ElementRead = elementRead;
            Definitions = new ReadOnlyCollection<Instruction>(definitions.ToArray());
        }
    }

    public static bool TryProve(MethodAnalysisContext owner, Instruction call, out Proof? proof)
        => TryProve(owner, call, out proof, out _);

    public static bool TryProve(MethodAnalysisContext owner, Instruction call, out Proof? proof, out string reason)
    {
        proof = null; reason = "Unsupported owner/call/frame";
        if (owner == null || call == null || !LegacyArm64ObjectIsInstAbi.ValidForEmission(call, owner)
            || !LegacyArm64ValueThisThunks.TryGetExactPlainBodyRange(owner.AppContext, LegacyArm64ValueThisThunks.AnalysisAddress(owner), out _)
            || owner.ControlFlowGraph is not { } graph || call.Operands.Count != 4) return false;
        var witness = new Witness(owner, graph, call);
        return witness.Prove(out proof, out reason);
    }

    /// <summary>Uncached: a carrier or graph mutation cannot inherit an earlier acceptance.</summary>
    public static bool IsValid(MethodAnalysisContext owner, Instruction call, Proof? proof)
        => proof != null && ReferenceEquals(proof.Owner, owner) && ReferenceEquals(proof.Call, call)
            && TryProve(owner, call, out var current) && current != null
            && ReferenceEquals(current.Allocation, proof.Allocation) && ReferenceEquals(current.Array, proof.Array)
            && ReferenceEquals(current.ArrayType, proof.ArrayType) && ReferenceEquals(current.ClassInput, proof.ClassInput)
            && ReferenceEquals(current.Header, proof.Header) && ReferenceEquals(current.HeaderRead, proof.HeaderRead)
            && ReferenceEquals(current.ElementRead, proof.ElementRead)
            && current.Definitions.SequenceEqual(proof.Definitions);

    private readonly record struct Place(Block Block, int Position);
    private sealed class Witness(MethodAnalysisContext owner, ISILControlFlowGraph graph, Instruction call)
    {
        private readonly Dictionary<Instruction, Place> locations = new();
        private readonly Dictionary<LocalVariable, List<Instruction>> definitions = new();
        private readonly HashSet<Instruction> usedDefinitions = new();
        private readonly HashSet<Instruction> copyDefinitions = new();
        private readonly HashSet<LocalVariable> arrayAliases = new();
        private readonly HashSet<LocalVariable> pointerAliases = new();
        private readonly Dictionary<Block, HashSet<Block>> incoming = new();
        private readonly Dictionary<(Block, Block), bool> reaches = new();
        private HashSet<Block> cone = new();
        private Place callPlace;

        public bool Prove(out Proof? proof, out string reason)
        {
            proof = null; reason = "Malformed or cyclic current call cone";
            if (!Prepare()) return false;
            reason = "Unproved original eight-byte element-class read";
            if (!Load(call.Operands[3], callPlace, out var element, out var elementPlace)
                || element.Addend != 0x40 || element.Base is not LocalVariable headerLocal) return false;
            reason = "Unproved original eight-byte object-header read";
            if (!Load(headerLocal, elementPlace, out var header, out var headerPlace)
                || header.Addend != 0 || header.Base is not LocalVariable array) return false;
            reason = "Array origin is not a unique available ordinary typed NewArr";
            if (!ArrayRoot(array, headerPlace, out var allocation, out var root, out var arrayType)) return false;
            reason = "Array/header/class reference escapes or has an unsupported use";
            if (!UsesAreClosed()) return false;
            reason = "Effectful or unsupported allocation-to-call window";
            var allocationPlace = locations[allocation];
            foreach (var block in cone)
            {
                if (!Reach(allocationPlace.Block, block)) continue;
                for (int i = 0; i < block.Instructions.Count; i++)
                {
                    if (ReferenceEquals(block, allocationPlace.Block) && i <= allocationPlace.Position
                        || ReferenceEquals(block, callPlace.Block) && i >= callPlace.Position) continue;
                    var row = block.Instructions[i];
                    if (!Pure(row)) return false;
                }
            }
            proof = new(owner, call, allocation, root, arrayType, call.Operands[3],
                graph.Blocks.SelectMany(b => b.Instructions).Single(row => locations[row].Equals(headerPlace)),
                header.NativeRead!, element.NativeRead!,
                graph.Blocks.SelectMany(b => b.Instructions).Where(usedDefinitions.Contains));
            reason = "Proven origin only; native helper effects and return remain unresolved";
            return true;
        }

        private bool Prepare()
        {
            if (graph.Blocks.Count is < 1 or > 4096 || graph.Blocks.Distinct().Count() != graph.Blocks.Count
                || !graph.Blocks.Contains(graph.EntryBlock)) return false;
            foreach (var block in graph.Blocks) incoming.Add(block, new());
            foreach (var block in graph.Blocks)
            {
                if (block.Successors.Distinct().Count() != block.Successors.Count
                    || block.Predecessors.Distinct().Count() != block.Predecessors.Count) return false;
                foreach (var next in block.Successors)
                {
                    if (!incoming.ContainsKey(next) || next.Predecessors.Count(p => ReferenceEquals(p, block)) != 1) return false;
                    incoming[next].Add(block);
                }
                foreach (var previous in block.Predecessors)
                    if (!incoming.ContainsKey(previous) || previous.Successors.Count(n => ReferenceEquals(n, block)) != 1) return false;
                for (int i = 0; i < block.Instructions.Count; i++)
                {
                    var row = block.Instructions[i];
                    if (row == null || !ValidShape(row) || !locations.TryAdd(row, new(block, i)) || locations.Count > 65536) return false;
                    // NewArr currently has no generic Instruction.Destination case.
                    var destination = row.OpCode == OpCode.NewArr && row.Operands.Count > 0 ? row.Operands[0] : row.Destination;
                    if (destination is LocalVariable local)
                    {
                        if (!definitions.TryGetValue(local, out var rows)) definitions.Add(local, rows = new());
                        rows.Add(row);
                    }
                }
            }
            if (!locations.TryGetValue(call, out callPlace)) return false;
            var queue = new Queue<Block>(); queue.Enqueue(callPlace.Block);
            while (queue.Count != 0)
            {
                var block = queue.Dequeue(); if (!cone.Add(block)) continue;
                foreach (var previous in incoming[block]) queue.Enqueue(previous);
            }
            if (!cone.Contains(graph.EntryBlock) || cone.Any(b => !Reach(graph.EntryBlock, b))) return false;
            var remaining = cone.ToDictionary(b => b, b => incoming[b].Count(cone.Contains));
            foreach (var block in cone.Where(b => remaining[b] == 0)) queue.Enqueue(block);
            int visited = 0;
            while (queue.Count != 0)
            {
                var block = queue.Dequeue(); visited++;
                foreach (var next in block.Successors.Where(cone.Contains)) if (--remaining[next] == 0) queue.Enqueue(next);
            }
            return visited == cone.Count;
        }

        private bool Reach(Block from, Block to)
        {
            if (ReferenceEquals(from, to)) return true;
            var pair = (from, to); if (reaches.TryGetValue(pair, out bool result)) return result;
            var seen = new HashSet<Block>(); var queue = new Queue<Block>(); queue.Enqueue(from);
            while (queue.Count != 0)
            {
                var block = queue.Dequeue(); if (!seen.Add(block)) continue;
                foreach (var next in block.Successors)
                {
                    if (ReferenceEquals(next, to)) { reaches[pair] = true; return true; }
                    queue.Enqueue(next);
                }
            }
            reaches[pair] = false; return false;
        }

        private bool Available(Place definition, Place use)
        {
            if (!cone.Contains(definition.Block) || !cone.Contains(use.Block)) return false;
            if (ReferenceEquals(definition.Block, use.Block)) return definition.Position < use.Position;
            var seen = new HashSet<Block>(); var queue = new Queue<Block>(); queue.Enqueue(graph.EntryBlock);
            while (queue.Count != 0)
            {
                var block = queue.Dequeue();
                if (ReferenceEquals(block, definition.Block) || !seen.Add(block)) continue;
                if (ReferenceEquals(block, use.Block)) return false;
                foreach (var next in block.Successors.Where(cone.Contains)) queue.Enqueue(next);
            }
            return true;
        }

        private bool Definition(LocalVariable local, Place use, out Instruction row, out Place place)
        {
            row = null!; place = default;
            if (!definitions.TryGetValue(local, out var rows) || rows.Count != 1
                || !locations.TryGetValue(rows[0], out place) || !Available(place, use)) return false;
            row = rows[0]; usedDefinitions.Add(row); return usedDefinitions.Count <= 64;
        }

        private bool Load(IOperand input, Place use, out MemoryOperand memory, out Place place)
        {
            memory = default; place = use; var seen = new HashSet<LocalVariable>();
            for (int depth = 0; depth < 32; depth++)
            {
                if (input is MemoryOperand load)
                {
                    if (load.NativeRead is not { } read || !read.ValidFor(owner, load)
                        || load.Index != null || load.Scale != 0 || load.ScalarFloatingSize != 0) return false;
                    memory = load; return true;
                }
                if (input is not LocalVariable local || !seen.Add(local)
                    || !Definition(local, use, out var row, out place)
                    || row.OpCode != OpCode.Move || row.Operands.Count != 2) return false;
                if (row.Operands[1] is LocalVariable && copyDefinitions.Add(row) && copyDefinitions.Count > 32) return false;
                pointerAliases.Add(local); input = row.Operands[1]; use = place;
            }
            return false;
        }

        private bool ArrayRoot(LocalVariable input, Place use, out Instruction allocation,
            out LocalVariable root, out SzArrayTypeAnalysisContext type)
        {
            allocation = null!; root = null!; type = null!; var seen = new HashSet<LocalVariable>();
            for (int depth = 0; depth < 32 && seen.Add(input); depth++)
            {
                arrayAliases.Add(input);
                if (!Definition(input, use, out var row, out var place)) return false;
                if (row.OpCode == OpCode.NewArr && row.Operands is [LocalVariable result, SzArrayTypeAnalysisContext array, _]
                    && ReferenceEquals(result, input) && ReferenceEquals(input.Type, array)
                    && OrdinaryElement(array.ElementType) && ReferenceEquals(array.ElementType.AppContext, owner.AppContext)
                    && array.ElementType is { } element
                    && owner.AppContext.AllTypes.Any(t => ReferenceEquals(t, element)))
                { allocation = row; root = result; type = array; return true; }
                if (row.OpCode != OpCode.Move || row.Operands is not [_, LocalVariable source]
                    || copyDefinitions.Add(row) && copyDefinitions.Count > 32) return false;
                input = source; use = place;
            }
            return false;
        }

        private bool BeforeCall(Place place) => ReferenceEquals(place.Block, callPlace.Block)
            ? place.Position < callPlace.Position : Reach(place.Block, callPlace.Block);

        private bool UsesAreClosed()
        {
            if (ContainsAlias(call.Operands[2], 0)) return false;
            // Include every available pre-call alias, not only the chain chosen above.
            for (int iteration = 0; iteration < 32; iteration++)
            {
                bool changed = false;
                foreach (var (row, place) in locations)
                {
                    if (!BeforeCall(place) || row.OpCode != OpCode.Move || row.Operands is not [LocalVariable target, LocalVariable source]) continue;
                    var set = arrayAliases.Contains(source) ? arrayAliases : pointerAliases.Contains(source) ? pointerAliases : null;
                    if (set == null || set.Contains(target)) continue;
                    if (!Definition(target, callPlace, out var definition, out _) || !ReferenceEquals(row, definition)) return false;
                    if (copyDefinitions.Add(row) && copyDefinitions.Count > 32) return false;
                    set.Add(target); changed = true;
                    if (arrayAliases.Count + pointerAliases.Count > 64) return false;
                }
                if (!changed) break;
                if (iteration == 31) return false;
            }
            foreach (var (row, place) in locations)
            {
                if (!BeforeCall(place)) continue; // Cannot precede this call on any current path.
                if (row.OpCode == OpCode.Move && row.Operands is [LocalVariable, LocalVariable copied])
                {
                    if ((arrayAliases.Contains(copied) || pointerAliases.Contains(copied))
                        && !Definition(copied, place, out _, out _)) return false;
                    continue;
                }
                for (int i = 0; i < row.Operands.Count; i++)
                {
                    var operand = row.Operands[i];
                    if (i == 0 && row.Destination is LocalVariable || row.OpCode == OpCode.NewArr && i == 0) continue;
                    if (operand is MemoryOperand memory && row.OpCode == OpCode.Move && i == 1
                        && memory.Index == null && memory.Scale == 0 && memory.NativeRead is { } native && native.ValidFor(owner, memory)
                        && memory.Base is LocalVariable source
                        && (arrayAliases.Contains(source) && memory.Addend == 0
                            || pointerAliases.Contains(source) && memory.Addend == 0x40)
                        && Definition(source, place, out _, out _)) continue;
                    if (ContainsAlias(operand, 0)) return false;
                }
            }
            return true;
        }

        private bool ContainsAlias(IOperand operand, int depth) => depth > 12 || operand switch
        {
            LocalVariable local => arrayAliases.Contains(local) || pointerAliases.Contains(local),
            AddressOf address => ContainsAlias(address.Target, depth + 1),
            MemoryOperand memory => memory.Base != null && ContainsAlias(memory.Base, depth + 1)
                || memory.Index != null && ContainsAlias(memory.Index, depth + 1),
            ArrayAccess access => arrayAliases.Contains(access.Array) || ContainsAlias(access.Index, depth + 1),
            ArrayLength length => arrayAliases.Contains(length.Array),
            FieldReference field => arrayAliases.Contains(field.Local) || pointerAliases.Contains(field.Local),
            _ => false
        };

        private bool Pure(Instruction row)
        {
            if (row.OpCode == OpCode.Nop || row.OpCode == OpCode.Jump) return true;
            if (usedDefinitions.Contains(row) && row.OpCode == OpCode.Move) return true;
            if (row.OpCode == OpCode.Move && row.Operands is [LocalVariable, LocalVariable or Immediate or StringLiteral or TypeAnalysisContext]) return true;
            if (row.OpCode is OpCode.CheckEqual or OpCode.CheckNotEqual or OpCode.CheckGreater or OpCode.CheckLess
                or OpCode.CheckGreaterOrEqual or OpCode.CheckLessOrEqual or OpCode.ConditionalJump)
                return row.Operands.All(o => o is LocalVariable or Immediate or StringLiteral or Block);
            return false;
        }

        private static bool OrdinaryElement(TypeAnalysisContext element)
        {
            if (element.IsValueType || element.IsInterface || element.IsGenericInstance
                || element.Definition is not { IsValueType: false, IsInterface: false, IsImportOrWindowsRuntime: false }) return false;
            var seen = new HashSet<TypeAnalysisContext>();
            for (TypeAnalysisContext? type = element; type != null; type = type.DeclaringType)
                if (!seen.Add(type) || seen.Count > 16 || type is WrappedTypeAnalysisContext
                    || type.IsGenericInstance || type.GenericParameters.Count != 0
                    || type.Definition == null || !type.Definition.GenericContainerIndex.IsNull) return false;
            return true;
        }

        private static bool ValidShape(Instruction row) => row.OpCode switch
        {
            OpCode.Nop or OpCode.Interrupt => row.Operands.Count == 0,
            OpCode.Return => row.Operands.Count <= 1,
            OpCode.Move or OpCode.ConditionalJump => row.Operands.Count == 2,
            OpCode.Newobj => row.Operands.Count >= 2,
            OpCode.NewArr or OpCode.Box or OpCode.Add or OpCode.Subtract or OpCode.Multiply or OpCode.Divide
                or OpCode.Modulo or OpCode.ShiftLeft or OpCode.ShiftRight or OpCode.And or OpCode.Or or OpCode.Xor
                or OpCode.CheckEqual or OpCode.CheckNotEqual or OpCode.CheckGreater or OpCode.CheckLess
                or OpCode.CheckGreaterOrEqual or OpCode.CheckLessOrEqual => row.Operands.Count == 3,
            OpCode.Not or OpCode.Negate => row.Operands.Count == 2,
            OpCode.Phi or OpCode.Call or OpCode.IndirectCall => row.Operands.Count >= 2,
            OpCode.CallVoid => row.Operands.Count >= 1,
            OpCode.Jump or OpCode.IndirectJump or OpCode.ShiftStack or OpCode.Throw => row.Operands.Count == 1,
            OpCode.Invalid or OpCode.NotImplemented => row.Operands.Count == 1,
            _ => false
        };
    }
}
