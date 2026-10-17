using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;

namespace Cpp2IL.Core.Analysis;

/// <summary>Conservative closed-generic and nested scalar-FP field paths.</summary>
public static class LegacyArm64FieldPaths
{
    private sealed record Entry(FieldAnalysisContext Field, long Offset, long Size);
    private sealed record Layout(long End, long Alignment, Entry[] Entries);

    public static FieldAnalysisContext[]? Find(TypeAnalysisContext owner, long offset, int scalarSize)
    {
        if (offset < 0 || scalarSize is not (4 or 8)) return null;
        return Find(owner, offset, scalarSize, new HashSet<TypeAnalysisContext>(), 0);
    }

    private static FieldAnalysisContext[]? Find(TypeAnalysisContext owner, long offset, int scalarSize,
        HashSet<TypeAnalysisContext> active, int depth)
    {
        if (depth > 12 || !active.Add(owner)) return null;
        try
        {
            var layout = Describe(owner, new HashSet<TypeAnalysisContext>(), 0);
            if (layout == null) return null;
            foreach (var entry in layout.Entries)
            {
                var delta = offset - entry.Offset;
                if (delta < 0 || delta + scalarSize > entry.Size) continue;
                var type = entry.Field.FieldType;
                if (delta == 0 && type.FullName == (scalarSize == 4 ? "System.Single" : "System.Double"))
                    return [entry.Field];
                if (!type.IsValueType || type.IsEnumType) return null;
                var inner = Find(type, delta, scalarSize, active, depth + 1);
                return inner == null ? null : new[] { entry.Field }.Concat(inner).ToArray();
            }
            return null;
        }
        finally { active.Remove(owner); }
    }

    private static long Align(long value, long alignment) => (value + alignment - 1) & -alignment;

    private static (long Size, long Alignment)? Storage(TypeAnalysisContext type,
        HashSet<TypeAnalysisContext> active, int depth)
    {
        var pointerSize = type.AppContext.Binary.PointerSizeBytes;
        if (type.HasAnyGenericParameters() || type is ByRefTypeAnalysisContext) return null;
        if (type is PointerTypeAnalysisContext || !type.IsValueType) return (pointerSize, pointerSize);
        if (type.IsEnumType) return type.EnumUnderlyingType is { } underlying ? Storage(underlying, active, depth + 1) : null;
        var primitive = type.FullName switch
        {
            "System.Boolean" or "System.Byte" or "System.SByte" => 1,
            "System.Int16" or "System.UInt16" or "System.Char" => 2,
            "System.Int32" or "System.UInt32" or "System.Single" => 4,
            "System.Int64" or "System.UInt64" or "System.Double" => 8,
            "System.IntPtr" or "System.UIntPtr" => pointerSize,
            _ => 0
        };
        if (primitive != 0) return (primitive, primitive);
        var layout = Describe(type, active, depth + 1);
        var size = TypeSizes.UnboxedSize(type, pointerSize);
        return layout != null && size >= layout.End && size == Align(layout.End, layout.Alignment)
            ? (size, layout.Alignment) : null;
    }

    private static Layout? Describe(TypeAnalysisContext type, HashSet<TypeAnalysisContext> active, int depth)
    {
        if (depth > 20 || !active.Add(type) || type.HasAnyGenericParameters()) return null;
        try
        {
            var generic = type as GenericInstanceTypeAnalysisContext;
            var definition = generic?.GenericType ?? type;
            if (definition.Definition == null || definition.Definition.PackingSize != 0
                || (definition.Attributes & TypeAttributes.LayoutMask) == TypeAttributes.ExplicitLayout
                || (generic != null && type.IsValueType)) return null;
            long end = type.IsValueType ? 0 : 2 * type.AppContext.Binary.PointerSizeBytes;
            long alignment = type.IsValueType ? 1 : type.AppContext.Binary.PointerSizeBytes;
            var entries = new List<Entry>();
            if (!type.IsValueType && definition.BaseType is { } parent)
            {
                if (generic != null) parent = GenericInstantiation.Instantiate(parent, generic.GenericArguments, []);
                var inherited = Describe(parent, active, depth + 1);
                if (inherited == null) return null;
                // Inherited fields retain their actual offsets. The next class's fields can
                // occupy the base's tail padding: instance_size is the rounded allocation size.
                end = inherited.End;
                alignment = inherited.Alignment;
                entries.AddRange(inherited.Entries);
            }
            foreach (var raw in definition.Fields.Where(f => !f.IsStatic && (f.Attributes & FieldAttributes.Literal) == 0))
            {
                FieldAnalysisContext field = generic == null ? raw : new ConcreteGenericFieldAnalysisContext(raw, generic);
                var storage = Storage(field.FieldType, active, depth + 1);
                if (storage == null) return null;
                var (size, fieldAlignment) = storage.Value;
                var offset = generic == null ? raw.Offset : Align(end, fieldAlignment);
                if ((generic != null && raw.Offset != 0) || offset < end || offset % fieldAlignment != 0) return null;
                entries.Add(new Entry(field, offset, size));
                end = offset + size;
                alignment = Math.Max(alignment, fieldAlignment);
            }
            if (generic == null)
            {
                var size = type.IsValueType ? TypeSizes.UnboxedSize(type, type.AppContext.Binary.PointerSizeBytes)
                    : definition.Definition.RawSizes.instance_size;
                if (size <= 0 || size != Align(end, alignment)) return null;
            }
            return new Layout(end, alignment, entries.ToArray());
        }
        finally { active.Remove(type); }
    }
}
