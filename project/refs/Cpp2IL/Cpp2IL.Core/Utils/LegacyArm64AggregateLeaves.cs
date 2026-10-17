using System;
using System.Buffers.Binary;
using System.Linq;
using System.Reflection;
using Cpp2IL.Core.Model.Contexts;

namespace Cpp2IL.Core.Utils;

/// <summary>
/// Exact native leaf copies of a metadata-validated 16-byte integer value field.
/// This deliberately does not implement the general ARM64 integer aggregate ABI.
/// </summary>
public static class LegacyArm64AggregateLeaves
{
    public sealed record Match(FieldAnalysisContext Field, bool IsSetter);

    /// <summary>Validate a straight-line entry ending in RET before the next function boundary.</summary>
    public static Match? Describe(MethodAnalysisContext method)
    {
        if (!LegacyArm64Hfa.Enabled(method) || method.IsStatic || method.DeclaringType?.IsValueType != false)
            return null;
        var binary = method.AppContext.Binary;
        if (!binary.TryMapVirtualAddressToRaw(method.UnderlyingPointer, out var raw)) return null;
        var content = binary.GetRawBinaryContent();
        if (raw < 0 || raw + 12 > content.Length) return null;
        var first = BinaryPrimitives.ReadUInt32LittleEndian(content.Slice((int)raw, 4));
        // The only accepted entry sequences end unconditionally in RET. No branch/call can
        // reach a later instruction; alignment bytes after that RET are not executable body.
        if ((first & 0xFFC07FFF) is not (0xA9000801 or 0xA9400408)) return null;
        var length = (first & 0xFFC07FFF) == 0xA9000801 ? 8 : 12;
        var next = method.AppContext.GetAddressOfNextFunctionStart(method.UnderlyingPointer);
        if (next < method.UnderlyingPointer + (ulong)length) return null;
        return Describe(method, content.Slice((int)raw, length));
    }

    /// <param name="body">The complete decoded native body, including its RET;
    /// do not pass a truncated prefix of a longer function.</param>
    public static Match? Describe(MethodAnalysisContext method, ReadOnlySpan<byte> body)
    {
        if (!LegacyArm64Hfa.Enabled(method) || method.IsStatic || method.IsAbstract
            || method.GenericParameters.Count != 0
            || method.DeclaringType is not { } owner || owner.IsValueType
            || owner is GenericInstanceTypeAnalysisContext || owner.GenericParameters.Count != 0
            || owner.Definition == null || owner.Definition.PackingSize != 0
            || (owner.Attributes & TypeAttributes.LayoutMask) == TypeAttributes.ExplicitLayout)
            return null;

        bool setter;
        uint pair;
        if (body.Length == 8 && method.IsVoid && method.Parameters.Count == 1
            && BinaryPrimitives.ReadUInt32LittleEndian(body[4..]) == 0xD65F03C0)
        {
            // STP X1,X2,[X0,#imm7*8]; RET. Offset mode only; no writeback.
            pair = BinaryPrimitives.ReadUInt32LittleEndian(body);
            if ((pair & 0xFFC07FFF) != 0xA9000801) return null;
            setter = true;
        }
        else if (body.Length == 12 && !method.IsVoid && method.Parameters.Count == 0
            && BinaryPrimitives.ReadUInt32LittleEndian(body[4..]) == 0xAA0803E0
            && BinaryPrimitives.ReadUInt32LittleEndian(body[8..]) == 0xD65F03C0)
        {
            // LDP X8,X1,[X0,#imm7*8]; MOV X0,X8; RET.
            pair = BinaryPrimitives.ReadUInt32LittleEndian(body);
            if ((pair & 0xFFC07FFF) != 0xA9400408) return null;
            setter = false;
        }
        else return null;

        var immediate = (int)((pair >> 15) & 0x7F);
        if ((immediate & 0x40) != 0) immediate -= 0x80;
        var offset = immediate * 8;
        if (offset < 16 || owner.Definition.RawSizes.instance_size < offset + 16) return null;
        var fields = owner.Fields.Where(field => !field.IsStatic
            && (field.Attributes & FieldAttributes.Literal) == 0 && field.Offset == offset).ToArray();
        if (fields.Length != 1) return null;
        var field = fields[0];
        var signatureType = setter ? method.Parameters[0].ParameterType : method.ReturnType;
        if (!ReferenceEquals(signatureType, field.FieldType)
            || (setter && (field.Attributes & FieldAttributes.InitOnly) != 0)
            || !IsKnownIntegerValue(field.FieldType)) return null;
        return new Match(field, setter);
    }

    private static bool IsKnownIntegerValue(TypeAnalysisContext type)
    {
        if (!type.IsValueType || type.IsEnumType || type is WrappedTypeAnalysisContext
            || type is GenericInstanceTypeAnalysisContext || type.GenericParameters.Count != 0
            || type.Definition == null || type.Definition.PackingSize != 0
            || (type.Attributes & TypeAttributes.LayoutMask) != TypeAttributes.SequentialLayout
            || TypeSizes.UnboxedSize(type, 8) != 16) return false;
        var fields = type.Fields.Where(field => !field.IsStatic
            && (field.Attributes & FieldAttributes.Literal) == 0).OrderBy(field => field.Offset).ToArray();
        if (fields.Length == 0) return false;
        long end = 0, alignment = 1;
        foreach (var field in fields)
        {
            // No references, nested structs, open generics or unknown widths.
            var size = field.FieldType.FullName switch
            {
                "System.Boolean" or "System.Byte" or "System.SByte" => 1,
                "System.Int16" or "System.UInt16" or "System.Char" => 2,
                "System.Int32" or "System.UInt32" => 4,
                "System.Int64" or "System.UInt64" => 8,
                _ => 0
            };
            if (size == 0 || field.Offset < end || field.Offset % size != 0
                || field.Offset + size > 16) return false;
            // Validate ordinary sequential placement, including only required padding.
            var expected = (end + size - 1) & -size;
            if (field.Offset != expected) return false;
            end = field.Offset + size;
            alignment = Math.Max(alignment, size);
        }
        // Tail padding is not a managed field; field-copy semantics preserve all fields.
        return ((end + alignment - 1) & -alignment) == 16;
    }
}
