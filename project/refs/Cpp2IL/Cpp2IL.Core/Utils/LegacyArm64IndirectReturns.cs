using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using LibCpp2IL;

namespace Cpp2IL.Core.Utils;

/// <summary>
/// One reviewed legacy NSO caller's indirect reference-enumerator return.
/// This is not a generic structure-size classifier or the general ARM64 aggregate ABI.
/// </summary>
public static class LegacyArm64IndirectReturns
{
    private const ulong Caller = 0xC9F3F0, Target = 0x1585F60, Constructor = 0x11DD130;
    private const ulong CallSite = 0xC9F4DC;
    private sealed record NativeDescriptor(ConcreteGenericMethodAnalysisContext Method, int ConcreteAliases);
    private sealed class State
    {
        public readonly object Gate = new();
        public bool Initialized;
        public NativeDescriptor? Descriptor;
    }
    private static readonly ConditionalWeakTable<ApplicationAnalysisContext, State> States = new();

    /// <summary>
    /// Run on completed conversion, after branch Instruction targets resolve and before stack/SSA.
    /// Only a successful call destination is changed. Native addresses must parallel the ISIL list.
    /// </summary>
    public static int Apply(MethodAnalysisContext caller, List<Instruction> instructions, IReadOnlyList<ulong> nativeAddresses)
    {
        try { return ApplyProved(caller, instructions, nativeAddresses); }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or IndexOutOfRangeException
            or OverflowException or KeyNotFoundException or NullReferenceException or System.IO.IOException
            or NotSupportedException or BadImageFormatException)
        {
            // Unsupported/malformed metadata or symbolic operands never justify a recovery.
            // All checks precede the single destination mutation, so rejection is atomic.
            return 0;
        }
    }

    private static int ApplyProved(MethodAnalysisContext caller, List<Instruction> instructions, IReadOnlyList<ulong> nativeAddresses)
    {
        if (!LegacyArm64Hfa.Enabled(caller) || caller.UnderlyingPointer != Caller
            || caller.DeclaringType?.DefaultFullName != "Nekki.SF2.Core.Fights.Fight" || caller.DefaultName != "SetStage"
            || caller.IsStatic || !caller.IsVoid || instructions.Count != nativeAddresses.Count)
            return 0;
        var state = States.GetValue(caller.AppContext, _ => new State());
        NativeDescriptor? descriptor;
        lock (state.Gate)
        {
            if (!state.Initialized)
            {
                state.Descriptor = DescribeNative(caller);
                state.Initialized = true;
            }
            descriptor = state.Descriptor;
        }
        if (descriptor == null) return 0;

        int callIndex = -1;
        for (int i = 0; i < nativeAddresses.Count; i++)
        {
            if (instructions[i].Index != i) return 0;
            if (nativeAddresses[i] == CallSite)
            {
                if (callIndex >= 0) return 0;
                callIndex = i;
            }
        }
        if (callIndex < 1) return 0;
        var call = instructions[callIndex];
        if (call.OpCode != OpCode.Call || call.Operands.Count != 4
            || call.Operands[0] is not Immediate target || target.UnsignedValue != Target
            || call.Destination is not Register { Name: "X0", Version: -1 }
            || call.Operands[2] is not Register { Name: "X0", Version: -1 }
            || call.Operands[3] is not Register { Name: "X1", Version: -1 }) return 0;
        var address = instructions[callIndex - 1];
        if (nativeAddresses[callIndex - 1] != 0xC9F4D8 || address.OpCode != OpCode.Move
            || address.Operands.Count != 2 || address.Operands[0] is not Register { Name: "X8", Version: -1 }
            || address.Operands[1] is not AddressOf { Target: StackOffset { Offset: 8 } buffer }) return 0;
        if (!ReviewedStorageUses(instructions, nativeAddresses)) return 0;

        // A temporary CFG rewrites branch operands, so build it from fresh instructions and
        // remap every Instruction target. The source list must stay untouched on rejection.
        var clones = new Dictionary<Instruction, Instruction>();
        foreach (var row in instructions)
        {
            if (clones.ContainsKey(row)) return 0;
            clones.Add(row, new Instruction(row.Index, row.OpCode, row.Operands.ToList())
                { ImplicitDefinition = row.ImplicitDefinition, NativeVirtualDispatch = row.NativeVirtualDispatch,
                    NativeClassLayoutAbi = row.NativeClassLayoutAbi, NativeOverflowExceptionAbi = row.NativeOverflowExceptionAbi,
                    NativeObjectIsInstAbi = row.NativeObjectIsInstAbi });
        }
        foreach (var row in clones.Values)
            for (int i = 0; i < row.Operands.Count; i++)
            {
                if (row.Operands[i] is Block) return 0; // Already-normalized or unsupported graph.
                if (row.Operands[i] is Instruction oldTarget)
                {
                    if (!clones.TryGetValue(oldTarget, out var cloneTarget)) return 0;
                    row.SetOperand(i, cloneTarget);
                }
            }
        var graph = new ISILControlFlowGraph(instructions.Select(i => clones[i]).ToList());
        if (!DeadBeforeOverwrite(graph, clones[call], "X0") || !DeadBeforeOverwrite(graph, clones[call], "X8")) return 0;

        // The original native X0 returns a buffer pointer, whose uses were proven dead above.
        // X1 still carries MethodInfo for the ordinary later concrete managed-call resolver.
        call.Destination = buffer;
        return 1;
    }

    private static NativeDescriptor? DescribeNative(MethodAnalysisContext caller)
    {
        var app = caller.AppContext;
        if (!ExactBody(caller, 552, "a1752250eaef0b5c3c2714f7dd5995a15560d9f83f7ad057b5078a62eb93efe9")
            || !app.MethodsByAddress.TryGetValue(Target, out var aliases) || aliases.Count != 279
            || !LegacyArm64ValueThisThunks.TryGetExactBodyRange(app, Constructor, out int constructorSize) || constructorSize != 16
            || !BodyHash(app, Constructor, 16, "93f97aee4056e153eb26e662e2518b5597090fb7491333fa0a160c01ed376afe")) return null;
        var selected = aliases.OrderByDescending(m => m.Parameters.Count + (m.IsStatic ? 0 : 1)).First();
        if (selected.UnderlyingPointer != Target || !ExactBody(selected, 36,
                "43694a140756dab00d417fb317762c8d7e917bea857ba9368f482b6e80c7235a")) return null;
        var usage = app.LibCpp2IlContext.GetMethodGlobalByAddress(0x3B4CE60);
        if (app.Binary.ReadPointerAtVirtualAddress(0x39D61A0) != 0x3B4CE60 || usage?.Type != MetadataUsageType.MethodRef
            || app.ResolveContextForMethod(usage) is not ConcreteGenericMethodAnalysisContext concrete
            || concrete.UnderlyingPointer is not (0 or Target) || concrete.TypeGenericParameters.Count != 1
            || concrete.TypeGenericParameters[0].DefaultFullName != "Nekki.SF2.Core.Fights.Model.Model"
            || concrete.ReturnType is not GenericInstanceTypeAnalysisContext returned
            || returned.GenericType.DefaultFullName != "System.Collections.Generic.List`1+Enumerator"
            || concrete.BaseMethodContext.DeclaringType?.DefaultFullName != "System.Collections.Generic.List`1"
            || !ReferenceEquals(returned.GenericType.DeclaringType, concrete.BaseMethodContext.DeclaringType)) return null;

        int closedCount = 0, openCount = 0, registeredMatches = 0;
        foreach (var alias in aliases)
        {
            if (alias.DefaultName != "GetEnumerator" || alias.IsStatic || alias.Parameters.Count != 0 || alias.GenericParameters.Count != 0)
                return null;
            if (alias is not ConcreteGenericMethodAnalysisContext closed)
            {
                if (!ReferenceEquals(alias, concrete.BaseMethodContext)) return null;
                openCount++; continue; // An open signature supplies no ABI/layout proof.
            }
            if (!ReferenceEquals(closed.BaseMethodContext, concrete.BaseMethodContext)
                || closed.TypeGenericParameters.Count != 1 || closed.MethodGenericParameters.Count != 0
                || !KnownReference(closed.TypeGenericParameters[0])
                || closed.ReturnType is not GenericInstanceTypeAnalysisContext resultType
                || !ReferenceEquals(resultType.GenericType, returned.GenericType) || resultType.GenericArguments.Count != 1
                || !ReferenceEquals(resultType.GenericArguments[0], closed.TypeGenericParameters[0])
                || !ReferenceEnumeratorLayout(resultType, closed.TypeGenericParameters[0], concrete.BaseMethodContext.DeclaringType!)) return null;
            if (closed.UnderlyingPointer == Target && closed.TypeGenericParameters.SequenceEqual(concrete.TypeGenericParameters)
                && closed.MethodGenericParameters.SequenceEqual(concrete.MethodGenericParameters)) registeredMatches++;
            closedCount++;
        }
        // MetadataUsage.AsGenericMethodRef may have pointer zero: it creates a fresh metadata-only
        // reference. A registered alias must independently agree on the base and concrete arguments.
        return closedCount == 278 && openCount == 1 && registeredMatches == 1
            ? new NativeDescriptor(concrete, closedCount) : null;
    }

    private static bool ReferenceEnumeratorLayout(GenericInstanceTypeAnalysisContext type, TypeAnalysisContext element, TypeAnalysisContext listDefinition)
    {
        var definition = type.GenericType;
        if (!type.IsValueType || definition.Definition == null || definition.Definition.PackingSize != 0
            || (definition.DefaultAttributes & TypeAttributes.LayoutMask) != TypeAttributes.SequentialLayout)
            return false;
        var fields = definition.Fields.Where(f => (f.DefaultAttributes & (FieldAttributes.Static | FieldAttributes.Literal)) == 0)
            .Select(f => new ConcreteGenericFieldAnalysisContext(f, type)).ToArray();
        // Raw generic offsets are zero in this build. The sequential ref/int/int/ref declaration
        // gives offsets0/8/12/16 and size24, corroborated by the complete native writes/constructor.
        // No other field mixture, packing, explicit layout, value T or unresolved substitution enters.
        return fields.Length == 4 && fields.All(f => f.DefaultOffset == 0)
            && fields[0].DefaultName == "l" && fields[0].FieldType is GenericInstanceTypeAnalysisContext list
            && ReferenceEquals(list.GenericType, listDefinition) && list.GenericArguments.Count == 1
            && ReferenceEquals(list.GenericArguments[0], element) && KnownReference(list)
            && fields[1].DefaultName == "next" && fields[1].FieldType.DefaultFullName == "System.Int32"
            && fields[2].DefaultName == "ver" && fields[2].FieldType.DefaultFullName == "System.Int32"
            && fields[3].DefaultName == "current" && ReferenceEquals(fields[3].FieldType, element) && KnownReference(element);
    }

    private static bool KnownReference(TypeAnalysisContext type) => !type.IsValueType
        && type is not PointerTypeAnalysisContext and not ByRefTypeAnalysisContext
        && (type is GenericInstanceTypeAnalysisContext || type.GenericParameters.Count == 0)
        && !GenericInstantiation.HasAnyGenericParameters(type);

    private static bool ExactBody(MethodAnalysisContext method, int size, string hash) =>
        LegacyArm64ValueThisThunks.TryGetExactBodyRange(method, out int actual) && actual == size
        && BodyHash(method.AppContext, method.UnderlyingPointer, size, hash);

    private static bool BodyHash(ApplicationAnalysisContext app, ulong address, int size, string hash)
    {
        if (!app.Binary.TryMapVirtualAddressToRaw(address, out var raw)) return false;
        var content = app.Binary.GetRawBinaryContent();
        if (raw < 0 || raw + size > content.Length) return false;
        using var algorithm = SHA256.Create();
        var actual = BitConverter.ToString(algorithm.ComputeHash(content.Slice((int)raw, size).ToArray())).Replace("-", "").ToLowerInvariant();
        return actual == hash;
    }

    private static bool ReviewedStorageUses(List<Instruction> instructions, IReadOnlyList<ulong> addresses)
    {
        int takes = 0, zeros = 0;
        for (int i = 0; i < instructions.Count; i++)
        {
            var row = instructions[i];
            foreach (var operand in row.Operands)
            {
                if (operand is AddressOf { Target: StackOffset slot } && slot.Offset >= 0 && slot.Offset < 32)
                {
                    if (slot.Offset != 8 || row.OpCode != OpCode.Move || row.Operands.Count != 2
                        || row.Operands[0] is not Register register || register.Version != -1) return false;
                    string expectedRegister = addresses[i] == 0xC9F4D8 ? "X8"
                        : addresses[i] is 0xC9F4FC or 0xC9F50C or 0xC9F594 or 0xC9F5DC ? "X0" : "";
                    if (register.Name != expectedRegister) return false;
                    if (expectedRegister == "X0")
                    {
                        ulong expectedTarget = addresses[i] == 0xC9F4FC ? 0x11DD3E0UL
                            : addresses[i] == 0xC9F50C ? 0x11DD540UL : 0x11DD3B0UL;
                        if (i + 1 >= instructions.Count || addresses[i + 1] != addresses[i] + 4) return false;
                        var consumer = instructions[i + 1];
                        int firstArgument = consumer.OpCode == OpCode.Call ? 2 : 1;
                        if (!consumer.IsCall || consumer.Operands.Count <= firstArgument
                            || consumer.Operands[0] is not Immediate callee || callee.UnsignedValue != expectedTarget
                            || consumer.Operands[firstArgument] is not Register { Name: "X0", Version: -1 }) return false;
                    }
                    takes++;
                }
                else if (operand is StackOffset direct && direct.Offset >= 0 && direct.Offset < 32)
                {
                    if (row.OpCode != OpCode.Move || row.Operands.Count != 2 || row.Operands[0] is not StackOffset destination
                        || destination.Offset != direct.Offset || row.Operands[1] is not Immediate literal || literal.UnsignedValue != 0
                        || (direct.Offset == 8 ? addresses[i] != 0xC9F444
                            : direct.Offset is 16 or 24 ? addresses[i] != 0xC9F440 : true)) return false;
                    zeros++;
                }
                else if (operand is MemoryOperand memory && (UnsupportedStackAddress(memory.Base) || UnsupportedStackAddress(memory.Index))) return false;
            }
        }
        // Exact whole-caller hash/FDE above anchors native memory widths and the absence of
        // unreviewed overlapping/escaping accesses. Unsupported symbolic slot uses reject too.
        // Fifth address-take is the exact same-buffer Dispose at0xC9F5DC/5E0 in the
        // native exception cleanup tail. Recognizing its storage does not recover EH flow.
        return takes == 5 && zeros == 3;
    }

    private static bool UnsupportedStackAddress(IOperand? operand) => operand is StackOffset or AddressOf;

    private static bool DeadBeforeOverwrite(ISILControlFlowGraph graph, Instruction call, string name)
    {
        var owners = graph.Blocks.Where(b => b.Instructions.Contains(call)).ToArray();
        if (owners.Length != 1) return false;
        var queue = new Queue<(Block Block, int Start)>();
        queue.Enqueue((owners[0], owners[0].Instructions.IndexOf(call) + 1));
        var visited = new HashSet<(Block, int)>();
        while (queue.Count > 0)
        {
            var (block, start) = queue.Dequeue();
            if (!visited.Add((block, start))) continue;
            bool overwritten = false;
            foreach (var row in block.Instructions.Skip(start))
            {
                if (row.SourcesAndConstants.Any(o => Uses(o, name))) return false;
                if (row.Destination is Register defined && defined.Name == name
                    || row.ImplicitDefinition is Register killed && killed.Name == name)
                { overwritten = true; break; }
            }
            if (!overwritten) foreach (var next in block.Successors) queue.Enqueue((next, 0));
        }
        return true;
    }

    private static bool Uses(IOperand operand, string name) => operand switch
    {
        Register register => register.Name == name,
        MemoryOperand memory => memory.Base is Register b && b.Name == name || memory.Index is Register i && i.Name == name,
        AddressOf { Target: Register addressed } => addressed.Name == name,
        _ => false
    };
}
