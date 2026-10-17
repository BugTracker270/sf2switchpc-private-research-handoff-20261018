using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.Il2CppApiFunctions;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using LibCpp2IL.NintendoSwitch;

namespace Cpp2IL.Core.Utils;

/// <summary>The reviewed legacy boxing helper, narrowed to proven scalar storage.</summary>
public static class LegacyArm64ScalarBoxing
{
    public static bool Enabled(ApplicationAnalysisContext app) => app.Binary is NsoFile && app.MetadataVersion == 24f
        && Environment.GetEnvironmentVariable("CPP2IL_LEGACY_HFA") == "1";

    private static byte[] ReadCode(ApplicationAnalysisContext app, ulong address, int size)
    {
        var binary = app.Binary;
        var start = binary.GetVirtualAddressOfPrimaryExecutableSection();
        var end = start + (ulong)binary.GetEntirePrimaryExecutableSection().Length;
        return address >= start && address + (ulong)size <= end && binary.TryMapVirtualAddressToRaw(address, out var raw)
            ? binary.GetRawBinaryContent().Slice((int)raw, size).ToArray() : [];
    }

    private static bool Reviewed(ApplicationAnalysisContext app, ulong address, int size, string hash)
    {
        var bytes = ReadCode(app, address, size);
        return bytes.Length == size && Convert.ToHexString(SHA256.HashData(bytes)).Equals(hash, StringComparison.OrdinalIgnoreCase);
    }

    private static ulong Branch(uint word, ulong address, uint operation)
        => (word & 0xfc000000) == operation ? unchecked((ulong)((long)address + (((int)(word << 6)) >> 4))) : 0;

    private static ulong Call(ApplicationAnalysisContext app, ulong start, int offset)
    {
        var bytes = ReadCode(app, start + (ulong)offset, 4);
        return bytes.Length == 4 ? Branch(BinaryPrimitives.ReadUInt32LittleEndian(bytes), start + (ulong)offset, 0x94000000) : 0;
    }

    public static ulong FindCandidate(ApplicationAnalysisContext app, ulong knownAllocator)
    {
        if (!Enabled(app) || knownAllocator == 0) return 0;
        var anchors = new[] {
            (app.SystemTypes.SystemBooleanType, 172, "1ea2f4b548e85ca3e0fc255808000fbc0912d24145179acb4d82319ed9e085c9"),
            (app.SystemTypes.SystemInt32Type, 164, "c7e0898130034e89a8de15c5cbefadcd2b4ff969a4ff410e2697f95a97703aec"),
            (app.SystemTypes.SystemDoubleType, 164, "6372f10a0c4d160212bbe43818a169a3a9236eb4c1be059f53e7a01a3559be4e")
        };
        ulong agreed = 0;
        foreach (var (type, callOffset, hash) in anchors)
        {
            var methods = type.Methods.Where(m => m.Name == "System.IConvertible.ToType" && m.Parameters.Count == 2).ToArray();
            if (methods.Length != 1 || !LegacyArm64ValueThisThunks.TryGetBody(methods[0], out var body, out var size)
                || size != 252 || !Reviewed(app, body, size, hash)) return 0;
            var candidate = Call(app, body, callOffset);
            if (candidate == 0 || agreed != 0 && candidate != agreed) return 0;
            agreed = candidate;
        }
        if (!Reviewed(app, agreed, 156, "827735a47ad60dc6eb33046526701fa86647e543ab655c6ecc1ff4b766c74aa2")
            || !Reviewed(app, Call(app, agreed, 24), 112, "16314f8396501200adcba482521357b30cf07bc7e95f3c26ae6c206873088b81")
            || !Reviewed(app, Call(app, agreed, 48), 48, "a61cfe7955c2fcb9224cc24df52d426b8574d4485afd70a249d8b932e5a53d13")
            || !Reviewed(app, Call(app, agreed, 92), 56, "13099b82b75073da5d08b01043d321cb250786d439936676711d891f3f19f369")) return 0;
        var allocator = Call(app, agreed, 104);
        if (allocator != knownAllocator)
        {
            var thunk = ReadCode(app, knownAllocator, 4);
            if (thunk.Length != 4 || Branch(BinaryPrimitives.ReadUInt32LittleEndian(thunk), knownAllocator, 0x14000000) != allocator) return 0;
        }
        return agreed;
    }

    public static int PrimitiveWidth(ApplicationAnalysisContext app, TypeAnalysisContext type)
    {
        var sys = app.SystemTypes;
        var width = ReferenceEquals(type, sys.SystemSByteType) || ReferenceEquals(type, sys.SystemByteType) ? 1
            : ReferenceEquals(type, sys.SystemInt16Type) || ReferenceEquals(type, sys.SystemUInt16Type) ? 2
            : ReferenceEquals(type, sys.SystemInt32Type) || ReferenceEquals(type, sys.SystemUInt32Type) || ReferenceEquals(type, sys.SystemSingleType) ? 4
            : ReferenceEquals(type, sys.SystemInt64Type) || ReferenceEquals(type, sys.SystemUInt64Type) || ReferenceEquals(type, sys.SystemDoubleType) ? 8 : 0;
        return width != 0 && type.IsValueType && type.Definition != null
            && (long)type.Definition.RawSizes.instance_size == 16 + width && !type.Methods.Any(m => m.Name == ".cctor") ? width : 0;
    }

    public static bool TryRewrite(MethodAnalysisContext method, Instruction instruction)
    {
        var app = method.AppContext;
        if (!Enabled(app) || app.GetOrCreateKeyFunctionAddresses() is not NewArm64KeyFunctionAddresses { LegacyScalarBoxingCandidate: > 0 } keys
            || instruction.OpCode != OpCode.Call || instruction.Operands is not [Immediate target, LocalVariable result, TypeAnalysisContext type, AddressOf { Target: LocalVariable value }, ..]
            || target.UnsignedValue != keys.LegacyScalarBoxingCandidate || PrimitiveWidth(app, type) == 0 || !ReferenceEquals(value.Type, type)
            || !HasDefinedStorage(method, instruction, value, type, [])) return false;
        instruction.OpCode = OpCode.Box;
        instruction.SetOperands(result, type, new AddressOf(value));
        return true;
    }

    // Unknown calls/addresses must not acquire a fabricated initialized local.
    // At this SSA stage, keep only a genuine argument or a unique dominating
    // same-type copy chain rooted in an argument/typed field/scalar literal.
    private static bool HasDefinedStorage(MethodAnalysisContext method, Instruction use, LocalVariable local, TypeAnalysisContext type, HashSet<LocalVariable> seen)
    {
        if (!seen.Add(local) || seen.Count > 32) return false;
        if (method.ParameterLocals.Any(p => ReferenceEquals(p, local))) return true;
        var graph = method.ControlFlowGraph!;
        var definitions = graph.Blocks.SelectMany(b => b.Instructions.Select(i => (block:b, instruction:i)))
            .Where(row => ReferenceEquals(row.instruction.Destination, local)).ToArray();
        if (definitions.Length != 1 || definitions[0].instruction is not { OpCode: OpCode.Move, Operands: [_, var source] } definition) return false;
        var useBlock = graph.Blocks.SingleOrDefault(b => b.Instructions.Contains(use));
        var owner = definitions[0].block;
        if (useBlock == null || owner == useBlock && owner.Instructions.IndexOf(definition) >= owner.Instructions.IndexOf(use)
            || owner != useBlock && !new DominatorInfo(graph).Dominates(owner, useBlock)) return false;
        return source switch {
            LocalVariable other when ReferenceEquals(other.Type, type) => HasDefinedStorage(method, definition, other, type, seen),
            FieldReference field when ReferenceEquals(field.Field.FieldType, type) => true,
            FloatLiteral when ReferenceEquals(type, method.AppContext.SystemTypes.SystemSingleType) => true,
            DoubleLiteral when ReferenceEquals(type, method.AppContext.SystemTypes.SystemDoubleType) => true,
            Immediate when type != method.AppContext.SystemTypes.SystemSingleType && type != method.AppContext.SystemTypes.SystemDoubleType => true,
            _ => false
        };
    }
}
