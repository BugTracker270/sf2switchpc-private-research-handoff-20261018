using System;
using System.Collections.Generic;
using System.Linq;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.Il2CppApiFunctions;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;

namespace Cpp2IL.Core.Analysis;

/// <summary>
/// Maps calls to KeyFunctionAddresses to their underlying IL opcodes. E.g. il2cpp_codegen_object_new => newobj.
/// Eventually will include box/unbox/throw/etc
/// </summary>
public static class KeyFunctionRecovery
{
    //All of these have the same params in the same order so we treat them as equal.
    private static readonly HashSet<string> ObjectNewFunctions =
    [
        "il2cpp_object_new",
        "il2cpp_vm_object_new",
        "il2cpp_codegen_object_new",
    ];

    //These all take the exception to throw as their only real argument.
    private static readonly HashSet<string> RaiseExceptionFunctions =
    [
        nameof(BaseKeyFunctionAddresses.il2cpp_raise_exception),
        nameof(BaseKeyFunctionAddresses.il2cpp_vm_exception_raise),
        nameof(BaseKeyFunctionAddresses.il2cpp_codegen_raise_exception),
    ];

    //Both take the class to box as and a pointer to the value.
    private static readonly HashSet<string> BoxFunctions =
    [
        nameof(BaseKeyFunctionAddresses.il2cpp_value_box),
        nameof(BaseKeyFunctionAddresses.il2cpp_vm_object_box),
    ];

    public static void Run(MethodAnalysisContext method)
    {
        foreach (var instruction in method.ControlFlowGraph!.Blocks.SelectMany(block => block.Instructions))
        {
            if (TryRewriteLegacyClassInitializer(method, instruction))
                continue;
            if (LegacyArm64ScalarBoxing.TryRewrite(method, instruction))
                continue;
            if (instruction.Operands is not [StringLiteral { Value: var keyFunction }, ..])
                continue;

            if (ObjectNewFunctions.Contains(keyFunction))
                RewriteObjectNew(instruction);
            else if (keyFunction == nameof(BaseKeyFunctionAddresses.il2cpp_codegen_write_barrier))
                RemoveWriteBarrier(instruction);
            else if (RaiseExceptionFunctions.Contains(keyFunction))
                RewriteRaiseException(instruction);
            else if (BoxFunctions.Contains(keyFunction))
                RewriteBox(instruction);
            else if (keyFunction == nameof(BaseKeyFunctionAddresses.il2cpp_vm_reflection_get_type_object))
                RewriteTypeObject(instruction);
            else if (keyFunction == nameof(BaseKeyFunctionAddresses.InternalCalls_Resolve))
                RewriteInternalCallResolve(instruction, method);
        }
    }

    /// <summary>
    /// Preserve the legacy runtime's explicit .cctor operation as a CLR class
    /// initialization request. Unknown native class pointers remain diagnostic
    /// calls; they never become no-ops or default-initialized managed values.
    /// </summary>
    public static bool RewriteLegacyClassInitializers(MethodAnalysisContext method)
    {
        var changed = false;
        foreach (var instruction in method.ControlFlowGraph!.Instructions)
            changed |= TryRewriteLegacyClassInitializer(method, instruction);
        return changed;
    }

    private static bool TryRewriteLegacyClassInitializer(MethodAnalysisContext method, Instruction instruction)
    {
        if (!instruction.IsCall || instruction.Operands[0] is not Immediate target
            || !LegacyArm64ScalarBoxing.Enabled(method.AppContext))
            return false;

        var app = method.AppContext;
        var initializer = app.GetOrCreateKeyFunctionAddresses().il2cpp_codegen_runtime_class_init;
        if (initializer == 0 || target.UnsignedValue != initializer)
            return false;

        IOperand argument;
        if (instruction.OpCode == OpCode.CallVoid && instruction.Operands is [_, var exactClass])
            argument = exactClass;
        else if (instruction.OpCode == OpCode.Call && instruction.Operands.Count == 18
                 && instruction.Operands[1] is LocalVariable { Register.Name: "X0" } result
                 && app.InstructionSet.CallingConventionResolver?.HasRawArgumentLayout(instruction, app) == true
                 && HasUnusedUniqueResult(method, instruction, result))
            // Unknown-callee lowering captures X0-X7,V0-V7 and an X0 result.
            // The known native helper is void and takes only the class in X0.
            // Discard only that verified physical-register capture and unused
            // result; a partial list or extra semantic argument stays unresolved.
            argument = instruction.Operands[2];
        else
            return false;

        if (argument is not LocalVariable { Type: RuntimeClassTypeAnalysisContext runtimeClass } classLocal
            || runtimeClass.RepresentedType is not { Definition: not null } represented
            || represented.HasAnyGenericParameters()
            || represented is not GenericInstanceTypeAnalysisContext && represented.GenericParameters.Count != 0
            || !HasExactClassMetadataOrigin(method, instruction, classLocal, represented))
            return false;

        var corlib = app.GetAssemblyByName("mscorlib");
        var helpers = corlib?.Types.Where(t => t.FullName == "System.Runtime.CompilerServices.RuntimeHelpers").ToArray();
        if (helpers is not [{ } helper])
            return false;
        var candidates = helper.Methods.Where(m => m.Name == "RunClassConstructor" && m.IsStatic && m.IsVoid
            && m.GenericParameters.Count == 0 && m.Parameters.Count == 1
            && m.Parameters[0].ParameterType.FullName == "System.RuntimeTypeHandle"
            && ReferenceEquals(m.Parameters[0].ParameterType.DeclaringAssembly, corlib)).ToArray();
        if (candidates is not [{ } runClassConstructor])
            return false;

        // The existing call emitter sees RuntimeTypeHandle as the expected
        // argument type and emits ldtoken directly, without GetTypeFromHandle.
        instruction.OpCode = OpCode.CallVoid;
        instruction.SetOperands(runClassConstructor, represented);
        return true;
    }

    private static bool HasUnusedUniqueResult(MethodAnalysisContext method, Instruction call, LocalVariable result)
    {
        var instructions = method.ControlFlowGraph!.Blocks.SelectMany(b => b.Instructions).ToArray();
        var definitions = instructions.Where(i => ReferenceEquals(i.Destination, result)).Take(2).ToArray();
        if (definitions.Length != 1 || !ReferenceEquals(definitions[0], call))
            return false;
        foreach (var other in instructions)
        {
            foreach (var operand in other.Operands)
            {
                // A plain destination is a write, but destination addresses,
                // array constituents, indirect targets and throw operands read
                // locals even where Instruction.Sources does not enumerate them.
                if (operand is LocalVariable && ReferenceEquals(operand, other.Destination))
                    continue;
                if (ReferencesLocal(operand, result))
                    return false;
            }
        }
        return true;
    }

    private static bool ReferencesLocal(IOperand operand, LocalVariable local) => operand switch
    {
        LocalVariable candidate => ReferenceEquals(candidate, local),
        MemoryOperand memory => memory.Base != null && ReferencesLocal(memory.Base, local)
            || memory.Index != null && ReferencesLocal(memory.Index, local),
        FieldReference field => ReferenceEquals(field.Local, local),
        AddressOf address => ReferencesLocal(address.Target, local),
        ArrayAccess access => ReferenceEquals(access.Array, local) || ReferencesLocal(access.Index, local),
        ArrayLength length => ReferenceEquals(length.Array, local),
        _ => false,
    };

    private static bool HasExactClassMetadataOrigin(MethodAnalysisContext method, Instruction use, LocalVariable local,
        TypeAnalysisContext represented)
    {
        var graph = method.ControlFlowGraph!;
        var blocks = new HashSet<Block>(graph.Blocks);
        if (blocks.Count != graph.Blocks.Count || !blocks.Contains(graph.EntryBlock))
            return false;
        var reachable = new HashSet<Block>();
        var pending = new Stack<Block>();
        pending.Push(graph.EntryBlock);
        while (pending.Count != 0)
        {
            var block = pending.Pop();
            if (!blocks.Contains(block))
                return false;
            if (reachable.Add(block))
                foreach (var successor in block.Successors)
                    pending.Push(successor);
        }
        // Validate topology before computing dominance: a malformed or dangling
        // edge must not manufacture availability or enter the dominator fixpoint.
        foreach (var block in graph.Blocks)
        {
            if (!reachable.Contains(block) && !ReferenceEquals(block, graph.ExitBlock)
                || block.Predecessors.Distinct().Count() != block.Predecessors.Count
                || block.Successors.Distinct().Count() != block.Successors.Count
                || block.Predecessors.Any(p => !blocks.Contains(p) || !p.Successors.Contains(block))
                || block.Successors.Any(s => !blocks.Contains(s) || !s.Predecessors.Contains(block))
                || reachable.Contains(block) && block.Predecessors.Any(p => !reachable.Contains(p)))
                return false;
        }
        // A proof is local to this CFG/type-fixpoint pass. Do not cache failures
        // while RuntimeClass types are still being seeded or propagated.
        return new ClassMetadataOriginProof(graph, represented, reachable).Prove(local, use);
    }

    private sealed class ClassMetadataOriginProof
    {
        private readonly ISILControlFlowGraph _graph;
        private readonly TypeAnalysisContext _represented;
        private readonly HashSet<Block> _reachable;
        private DominatorInfo? _dominance;
        private readonly HashSet<LocalVariable> _active = [];
        private readonly HashSet<LocalVariable> _distinct = [];
        private int _visits;
        private readonly Dictionary<LocalVariable, List<(Block Block, Instruction Instruction, int Position)>> _definitions = new();
        private readonly HashSet<LocalVariable> _escaped = [];

        public ClassMetadataOriginProof(ISILControlFlowGraph graph, TypeAnalysisContext represented, HashSet<Block> reachable)
        {
            _graph = graph;
            _represented = represented;
            _reachable = reachable;
            foreach (var block in graph.Blocks)
                for (var position = 0; position < block.Instructions.Count; position++)
                {
                    var instruction = block.Instructions[position];
                    if (instruction.Destination is LocalVariable destination)
                    {
                        if (!_definitions.TryGetValue(destination, out var definitions))
                            _definitions[destination] = definitions = [];
                        definitions.Add((block, instruction, position));
                    }
                    foreach (var operand in instruction.Operands)
                        CollectEscapes(operand);
                }
        }

        public bool Prove(LocalVariable local, Instruction use)
        {
            var owners = _graph.Blocks.Where(b => b.Instructions.Contains(use)).Take(2).ToArray();
            return owners.Length == 1 && ProveAt(local, owners[0], owners[0].Instructions.IndexOf(use));
        }

        private bool ProveAt(LocalVariable local, Block useBlock, int usePosition)
        {
            // A small shared Phi DAG can have exponentially many recursive
            // paths despite few distinct locals. Bound total work separately.
            if (++_visits > 256)
                return false;
            // Propagated RuntimeClass<T> alone is insufficient: T may only name
            // an instance's static base type. Every origin must reach this exact
            // original metadata Type object through the existing Move forms.
            if (local.Type is not RuntimeClassTypeAnalysisContext klass || !ReferenceEquals(klass.RepresentedType, _represented)
                || _active.Contains(local) || _escaped.Contains(local))
                return false;
            _distinct.Add(local);
            if (_distinct.Count > 32 || !_definitions.TryGetValue(local, out var definitions) || definitions.Count != 1)
                return false;
            var definition = definitions[0];
            if (!_reachable.Contains(definition.Block) || !_reachable.Contains(useBlock)
                || (ReferenceEquals(definition.Block, useBlock)
                    ? definition.Position >= usePosition
                    : !(_dominance ??= new DominatorInfo(_graph)).Dominates(definition.Block, useBlock)))
                return false;
            _active.Add(local);
            try
            {
                if (definition.Instruction is { OpCode: OpCode.Move, Operands: [_, var source] })
                    return source switch
                    {
                        TypeAnalysisContext type => ReferenceEquals(type, _represented),
                        LocalVariable copy => ProveAt(copy, definition.Block, definition.Position),
                        _ => false,
                    };
                if (definition.Instruction.OpCode != OpCode.Phi
                    || definition.Block.Predecessors.Count < 2
                    || definition.Instruction.Operands.Count != definition.Block.Predecessors.Count + 1
                    || definition.Block.Instructions.Take(definition.Position).Any(i => i.OpCode is not (OpCode.Phi or OpCode.Nop)))
                    return false;
                // SsaForm aligns source i+1 with Predecessors[i]. Conditional
                // source definitions need to dominate that edge's predecessor,
                // not the merge block. Checking at its end also rejects a
                // swapped/uninitialized incoming value without changing the CFG.
                for (var index = 0; index < definition.Block.Predecessors.Count; index++)
                {
                    var predecessor = definition.Block.Predecessors[index];
                    if (definition.Instruction.Operands[index + 1] is not LocalVariable incoming
                        || !ProveAt(incoming, predecessor, predecessor.Instructions.Count))
                        return false;
                }
                return true;
            }
            finally
            {
                // Shared identical roots on separate incoming paths are valid;
                // only an active origin dependency cycle is rejected.
                _active.Remove(local);
            }
        }

        private void CollectEscapes(IOperand operand)
        {
            switch (operand)
            {
                case AddressOf { Target: LocalVariable local }:
                    _escaped.Add(local);
                    break;
                case AddressOf address:
                    CollectEscapes(address.Target);
                    break;
                case MemoryOperand memory:
                    if (memory.Base != null) CollectEscapes(memory.Base);
                    if (memory.Index != null) CollectEscapes(memory.Index);
                    break;
                case ArrayAccess access:
                    CollectEscapes(access.Index);
                    break;
            }
        }
    }

    private static void RemoveWriteBarrier(Instruction instruction)
    {
        instruction.OpCode = OpCode.Nop;
        instruction.SetOperands();
    }
    
    private static void RewriteRaiseException(Instruction instruction)
    {
        // A void call has no return value operand, so the exception is one slot earlier
        var exceptionIndex = instruction.OpCode == OpCode.CallVoid ? 1 : 2;

        if (!instruction.IsCall || instruction.Operands.Count <= exceptionIndex)
            return;

        var exception = instruction.Operands[exceptionIndex];

        instruction.OpCode = OpCode.Throw;
        instruction.SetOperands(exception);
    }

    private static void RewriteBox(Instruction instruction)
    {
        // function name, result, class, address of value.
        if (instruction.OpCode != OpCode.Call || instruction.Operands is not [_, var result, TypeAnalysisContext boxedType, var value, ..])
            return;

        instruction.OpCode = OpCode.Box;
        instruction.SetOperands(result, boxedType, value);
    }

    private static void RewriteTypeObject(Instruction instruction)
    {
        if (instruction.OpCode != OpCode.Call || instruction.Operands is not [_, var result, TypeAnalysisContext type, ..])
            return;

        instruction.OpCode = OpCode.Move;
        instruction.SetOperands(result, type);
    }

    private static void RewriteInternalCallResolve(Instruction instruction, MethodAnalysisContext method)
    {
        if (instruction.OpCode != OpCode.Call || instruction.Operands is not [_, var result, Immediate nameAddress, ..])
            return;

        if (ThrowHelperRecovery.ReadCStringAtVirtualAddress(method.AppContext, nameAddress.UnsignedValue, 256) is not { } name)
            return;

        if (ResolveInternalCallName(method.AppContext, name) is not { DeclaringType.DeclaringAssembly: { } assembly } resolved)
            return;

        var pointer = new RuntimeMethodInfoAnalysisContext(resolved, assembly);

        instruction.OpCode = OpCode.Move;
        instruction.SetOperands(result, pointer);

        RewriteCachedPointerLoads(method, result, pointer);
    }

    private static void RewriteCachedPointerLoads(MethodAnalysisContext method, IOperand result, RuntimeMethodInfoAnalysisContext pointer)
    {
        var cache = method.ControlFlowGraph!.Instructions
            .Where(i => i is { OpCode: OpCode.Move, Operands: [MemoryOperand { IsConstant: true }, _] })
            .Where(i => ReferenceEquals(i.Operands[1], result))
            .Select(i => ((MemoryOperand)i.Operands[0]).Addend)
            .Distinct()
            .ToList();

        if (cache.Count != 1)
            return;

        foreach (var instruction in method.ControlFlowGraph.Instructions)
        {
            if (instruction is { OpCode: OpCode.Move, Operands: [LocalVariable destination, MemoryOperand { IsConstant: true } load] }
                && load.Addend == cache[0])
                instruction.SetOperands(destination, pointer);
        }
    }

    internal static MethodAnalysisContext? ResolveInternalCallName(ApplicationAnalysisContext appContext, string name)
    {
        var separator = name.IndexOf("::", StringComparison.Ordinal);

        if (separator < 0)
            return null;

        var typeName = name[..separator];
        var signature = name[(separator + 2)..];
        var parenthesis = signature.IndexOf('(');
        var methodName = parenthesis < 0 ? signature : signature[..parenthesis];

        if (appContext.LibCpp2IlContext.ReflectionCache.GetTypeByFullName(typeName) is not { } typeDefinition
            || appContext.ResolveContextForType(typeDefinition) is not { } type)
            return null;

        var candidates = type.Methods.Where(m => m.Name == methodName).ToList();

        if (candidates.Count <= 1)
            return candidates.FirstOrDefault();

        // Overloaded, so fall back on the parameter list in the name
        var parameters = parenthesis < 0 ? "" : signature[(parenthesis + 1)..].TrimEnd(')');
        var count = parameters.Length == 0 ? 0 : parameters.Split(',').Length;

        var byParameterCount = candidates.Where(m => m.Parameters.Count == count).ToList();

        return byParameterCount.Count == 1 ? byParameterCount[0] : null;
    }

    private static void RewriteObjectNew(Instruction instruction)
    {
        // Needs the function name, the result, and the class argument.
        if (instruction.OpCode != OpCode.Call || instruction.Operands.Count < 3)
            return;

        var result = instruction.Operands[1];
        var klass = instruction.Operands[2];

        instruction.OpCode = OpCode.Newobj;
        instruction.SetOperands(result, klass);
    }
}
