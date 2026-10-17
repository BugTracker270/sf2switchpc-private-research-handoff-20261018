using System;
using System.Collections.Generic;
using Cpp2IL.Core.ISIL;

namespace Cpp2IL.Core.Analysis;

/// <summary>Keep the address of a metadata load distinct from a GOT pointer load.</summary>
public static class MetadataAddressResolver
{
    public static ulong? LoadAddress(MemoryOperand memory, Dictionary<LocalVariable, Instruction> definitions,
        Func<ulong, ulong?> readKnownPointer)
        => LoadAddress(memory, definitions, readKnownPointer, new HashSet<LocalVariable>(), 0);

    private static ulong? LoadAddress(MemoryOperand memory, Dictionary<LocalVariable, Instruction> definitions,
        Func<ulong, ulong?> readKnownPointer, HashSet<LocalVariable> visiting, int depth)
    {
        if (depth > 32 || memory.Index != null || memory.Scale != 0)
            return null;
        if (memory.Base == null)
            return unchecked((ulong)memory.Addend);
        var value = Value(memory.Base, definitions, readKnownPointer, visiting, depth + 1);
        return value.HasValue ? unchecked(value.Value + (ulong)memory.Addend) : null;
    }

    private static ulong? Value(IOperand operand, Dictionary<LocalVariable, Instruction> definitions,
        Func<ulong, ulong?> readKnownPointer, HashSet<LocalVariable> visiting, int depth)
    {
        if (depth > 32)
            return null;
        if (operand is Immediate immediate)
            return immediate.UnsignedValue;
        if (operand is LocalVariable local && visiting.Add(local))
        {
            try
            {
                if (definitions.TryGetValue(local, out var definition)
                    && definition is { OpCode: OpCode.Move, Operands: [_, var source] })
                    return Value(source, definitions, readKnownPointer, visiting, depth + 1);
            }
            finally { visiting.Remove(local); }
        }
        if (operand is MemoryOperand memory
            && LoadAddress(memory, definitions, readKnownPointer, visiting, depth + 1) is { } address)
            return readKnownPointer(address);
        return null;
    }
}
