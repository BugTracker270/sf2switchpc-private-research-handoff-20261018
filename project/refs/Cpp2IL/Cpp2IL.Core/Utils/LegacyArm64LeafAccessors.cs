using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using Cpp2IL.Core.Model.Contexts;
using LibCpp2IL.NintendoSwitch;

namespace Cpp2IL.Core.Utils;

/// <summary>
/// Finds an existing public property accessor only when its complete reachable
/// native body is one exact scalar field access followed by RET. This does not
/// change field visibility, manufacture accessors, or recognize effectful getters.
/// Caller accessibility and recursion checks remain the emitter's responsibility.
/// </summary>
public static class LegacyArm64LeafAccessors
{
    private sealed record Accessors(MethodAnalysisContext? Getter, MethodAnalysisContext? Setter);
    private static readonly ConditionalWeakTable<ApplicationAnalysisContext,
        ConcurrentDictionary<FieldAnalysisContext, Accessors>> Cache = new();
    private sealed record StaticGetter(MethodAnalysisContext? Getter);
    private static readonly ConditionalWeakTable<ApplicationAnalysisContext,
        ConcurrentDictionary<FieldAnalysisContext, StaticGetter>> StaticCache = new();
    private sealed record AssemblyGetter(MethodAnalysisContext? Getter);
    private static readonly ConditionalWeakTable<ApplicationAnalysisContext,
        ConcurrentDictionary<FieldAnalysisContext, AssemblyGetter>> AssemblyCache = new();

    /// <summary>
    /// Native-only selection. Caller accessibility is checked separately at every
    /// emission site; a field-only cache never grants access to another assembly.
    /// </summary>
    public static MethodAnalysisContext? FindAssemblyGetter(FieldAnalysisContext field)
    {
        return AssemblyCache.GetValue(field.AppContext, _ => new()).GetOrAdd(field, f =>
        {
            var candidates = f.DeclaringType.Properties.Select(p => p.Getter)
                .Where(m => m != null && IsExactAssemblyGetter(f, m)).Distinct().ToArray();
            return new AssemblyGetter(candidates.Length == 1 ? candidates[0] : null);
        }).Getter;
    }

    /// <summary>Exact instance Assembly getter, with no owner initialization or nested-type access contract.</summary>
    public static bool IsExactAssemblyGetter(FieldAnalysisContext field, MethodAnalysisContext method)
    {
        var owner = field.DeclaringType;
        return owner.DeclaringType == null
            && (owner.Attributes & TypeAttributes.VisibilityMask) is TypeAttributes.Public or TypeAttributes.NotPublic
            && !owner.Methods.Any(m => m.Name == ".cctor")
            && IsExactLeafCore(field, method, false, MethodAttributes.Assembly);
    }

    /// <summary>
    /// An internal accessor is callable only inside the actual attached output
    /// assembly. Names, friend assemblies, family rules and detached metadata do
    /// not establish this capability. The decision is deliberately uncached.
    /// </summary>
    public static bool CanCallAssemblyGetter(FieldAnalysisContext? field, MethodAnalysisContext? getter, MethodDefinition? caller)
    {
        if (field == null || getter == null || caller?.DeclaringType == null
            || !IsExactAssemblyGetter(field, getter)
            || !ReferenceEquals(FindAssemblyGetter(field), getter)) return false;
        var owner = field.DeclaringType;
        var assembly = owner.DeclaringAssembly.GetExtraData<AssemblyDefinition>("AsmResolverAssembly");
        var type = owner.GetExtraData<TypeDefinition>("AsmResolverType");
        var method = getter.GetExtraData<MethodDefinition>("AsmResolverMethod");
        var outputField = field.GetExtraData<FieldDefinition>("AsmResolverField");
        return assembly != null && type != null && method != null && outputField != null
            && ReferenceEquals(caller.DeclaringModule?.Assembly, assembly)
            && ReferenceEquals(type.DeclaringModule?.Assembly, assembly)
            && ReferenceEquals(method.DeclaringType, type)
            && ReferenceEquals(method.DeclaringModule?.Assembly, assembly)
            && ReferenceEquals(outputField.DeclaringType, type)
            && !ReferenceEquals(caller.DeclaringType, type)
            && type.DeclaringType == null
            && !type.Methods.Any(m => m.Name == ".cctor")
            && ((uint)type.Attributes & (uint)TypeAttributes.VisibilityMask) == (uint)(owner.Attributes & TypeAttributes.VisibilityMask)
            && method.IsAssembly && !method.IsStatic && !method.IsVirtual && !method.IsAbstract
            && outputField.IsPrivate && !outputField.IsStatic
            && method.Signature is { HasThis: true, ParameterTypes.Count: 0 } signature
            && outputField.Signature is { } fieldSignature
            && SignatureComparer.Default.Equals(signature.ReturnType, fieldSignature.FieldType);
    }

    public static MethodAnalysisContext? FindStaticGetter(FieldAnalysisContext field)
    {
        if (!LegacyArm64ScalarBoxing.Enabled(field.AppContext)) return null;
        return StaticCache.GetValue(field.AppContext, _ => new()).GetOrAdd(field, f =>
        {
            var candidates = f.DeclaringType.Properties.Select(p => p.Getter).Where(m => m != null
                && IsExactStaticGetter(f, m)).Distinct().ToArray();
            return new StaticGetter(candidates.Length == 1 ? candidates[0] : null);
        }).Getter;
    }

    /// <summary>
    /// A static getter may contain method-metadata assurance, but no managed
    /// initializer or game effect. The exact FDE and metadata owner are proved
    /// separately from the instruction witness; field names are not evidence.
    /// </summary>
    public static bool IsExactStaticGetter(FieldAnalysisContext field, MethodAnalysisContext method)
    {
        var owner = field.DeclaringType;
        var app = field.AppContext;
        if (!LegacyArm64ScalarBoxing.Enabled(app) || !field.IsStatic || field.Offset < 0
            || (field.Attributes & FieldAttributes.Literal) != 0 || owner.Definition == null
            || owner.IsValueType || owner.IsEnumType || owner.DeclaringType != null
            || owner is GenericInstanceTypeAnalysisContext || owner.GenericParameters.Count != 0 || owner.HasAnyGenericParameters()
            || owner.Definition.PackingSize != 0 || (owner.Attributes & TypeAttributes.VisibilityMask) != TypeAttributes.Public
            || (owner.Attributes & TypeAttributes.LayoutMask) == TypeAttributes.ExplicitLayout
            || owner.DeclaringAssembly.Name is not ("Assembly-CSharp" or "Assembly-CSharp-firstpass")
            || owner.Methods.Any(m => m.Name == ".cctor") || owner.Definition.RawSizes.thread_static_fields_size != 0
            || !ReferenceEquals(method.AppContext, app) || !ReferenceEquals(method.DeclaringType, owner)
            || method.Definition == null || !method.IsStatic || method.IsVirtual || method.IsAbstract
            || method.UnderlyingPointer == 0 || method.Visibility != MethodAttributes.Public || method.GenericParameters.Count != 0
            || method.Parameters.Count != 0 || !ReferenceEquals(method.ReturnType, field.FieldType)
            || !owner.Properties.Any(p => ReferenceEquals(p.Getter, method))
            || !app.MethodsByAddress.TryGetValue(method.UnderlyingPointer, out var aliases)
            || aliases.Count != 1 || !ReferenceEquals(aliases[0], method)
            || !TryEncoding(field.FieldType, false, out var load, out var width)
            || field.Offset % width != 0 || field.Offset / width > 4095
            || owner.Definition.RawSizes.static_fields_size < field.Offset + width
            || !LegacyArm64ValueThisThunks.TryGetExactBodyRange(method, out var length) || length != 84)
            return false;

        var binary = app.Binary;
        var bytes = binary.GetRawBinaryContent();
        if (bytes.Length < 0x40 || !binary.TryMapVirtualAddressToRaw(method.UnderlyingPointer, out var raw)
            || raw < 0 || raw > bytes.Length - length)
            return false;
        var writable = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(0x34, 4));
        var writableEnd = (ulong)writable + BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(0x38, 4))
            + BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(0x3c, 4));
        if (!TryDecodeStaticGetter(bytes.Slice((int)raw, length), method.UnderlyingPointer,
            app.GetOrCreateKeyFunctionAddresses().il2cpp_codegen_initialize_method, load, width, field.Offset,
            writable, writableEnd, out var typeGot))
            return false;

        // ADRP/LDR obtains a GOT pointer to a registered legacy type-usage slot;
        // the following native LDR reads that slot's resolved Il2CppClass*.
        try
        {
            if (!binary.TryMapVirtualAddressToRaw(typeGot, out _)) return false;
            var slot = binary.ReadPointerAtVirtualAddress(typeGot);
            return app.LibCpp2IlContext.GetTypeGlobalByAddress(slot) is { } type
                && ReferenceEquals(app.ResolveIl2CppType(type), owner);
        }
        catch (Exception) { return false; }
    }

    /// <summary>Instruction-only witness; exact FDE and type-global identity are required by the caller.</summary>
    public static bool TryDecodeStaticGetter(ReadOnlySpan<byte> body, ulong start, ulong metadataInitializer,
        uint loadOpcode, int width, int fieldOffset, ulong writableStart, ulong writableEnd, out ulong typeGot)
    {
        typeGot = 0;
        if (body.Length != 84 || start % 4 != 0 || width is not (1 or 2 or 4 or 8)
            || fieldOffset < 0 || fieldOffset % width != 0 || fieldOffset / width > 4095)
            return false;
        var words = new uint[21];
        for (var i = 0; i < words.Length; i++) words[i] = BinaryPrimitives.ReadUInt32LittleEndian(body.Slice(i * 4, 4));
        if (words[0] != 0xF81E0FF3 || words[1] != 0xA9017BFD || words[2] != 0x910043FD
            || words[5] != 0x39401268 || words[6] != 0x370000E8 || words[9] != 0xB9400100
            || words[11] != 0x320003E8 || words[12] != 0x39001268 || words[15] != 0xF9400108
            || words[16] != 0xA9417BFD || words[17] != 0xF9405D08
            || words[18] != (loadOpcode | (uint)(fieldOffset / width) << 10 | 8u << 5)
            || words[19] != 0xF84207F3 || words[20] != 0xD65F03C0)
            return false;
        var guards = LegacyArm64InitializationPattern.Match(body, start, metadataInitializer, writableStart, writableEnd);
        if (guards.Count != 1 || guards[0].Branch != start + 24 || guards[0].Skip != start + 52
            || (words[13] & 0x9F00001F) != 0x90000008 || (words[14] & 0xFFC003FF) != 0xF9400108)
            return false;
        var immediate = ((words[13] >> 29) & 3) | (((words[13] >> 5) & 0x7FFFF) << 2);
        var pageOffset = ((long)((int)(immediate << 11) >> 11)) << 12;
        var page = unchecked((ulong)((long)((start + 52) & ~0xFFFUL) + pageOffset));
        typeGot = page + ((words[14] >> 10) & 0xFFF) * 8UL;
        return typeGot % 8 == 0;
    }

    public static MethodAnalysisContext? Find(FieldAnalysisContext field, bool write)
    {
        var pair = Cache.GetValue(field.AppContext, _ => new()).GetOrAdd(field, Build);
        return write ? pair.Setter : pair.Getter;
    }

    private static Accessors Build(FieldAnalysisContext field)
    {
        MethodAnalysisContext? FindOne(bool write) => field.DeclaringType.Properties
            .Select(property => write ? property.Setter : property.Getter)
            .FirstOrDefault(method => method != null && IsExactLeaf(field, method, write));
        return new Accessors(FindOne(false), FindOne(true));
    }

    /// <summary>Uncached proof predicate, also used by the independent probe.</summary>
    public static bool IsExactLeaf(FieldAnalysisContext field, MethodAnalysisContext method, bool write)
        => IsExactLeafCore(field, method, write, MethodAttributes.Public);

    private static bool IsExactLeafCore(FieldAnalysisContext field, MethodAnalysisContext method, bool write, MethodAttributes visibility)
    {
        var owner = field.DeclaringType;
        if (field.AppContext.Binary is not NsoFile || field.AppContext.MetadataVersion != 24f
            || field.IsStatic || field.Offset < 16 || owner.Definition == null
            || owner.IsValueType || owner.IsEnumType || owner is GenericInstanceTypeAnalysisContext
            || owner.GenericParameters.Count != 0 || owner.HasAnyGenericParameters()
            || owner.Definition.PackingSize != 0
            || (owner.Attributes & TypeAttributes.LayoutMask) == TypeAttributes.ExplicitLayout
            || owner.DeclaringAssembly.Name is not ("Assembly-CSharp" or "Assembly-CSharp-firstpass")
            || (owner.Methods.Any(candidate => candidate.Name == ".cctor")
                && (owner.Attributes & TypeAttributes.BeforeFieldInit) == 0)
            || !ReferenceEquals(method.AppContext, field.AppContext)
            || !ReferenceEquals(method.DeclaringType, owner) || method.Definition == null
            || method.IsStatic || method.IsVirtual || method.IsAbstract || method.UnderlyingPointer == 0
            || method.Visibility != visibility || method.GenericParameters.Count != 0
            || !owner.Properties.Any(property => ReferenceEquals(write ? property.Setter : property.Getter, method)))
            return false;

        if (write)
        {
            if ((field.Attributes & (FieldAttributes.InitOnly | FieldAttributes.Literal)) != 0
                || !method.IsVoid || method.Parameters.Count != 1
                || !ReferenceEquals(method.Parameters[0].ParameterType, field.FieldType)) return false;
        }
        else if (method.Parameters.Count != 0 || !ReferenceEquals(method.ReturnType, field.FieldType)) return false;

        if (!TryEncoding(field.FieldType, write, out var opcode, out var size)
            || field.Offset % size != 0 || field.Offset / size > 4095
            || owner.Definition.RawSizes.instance_size < field.Offset + size) return false;

        // A two-instruction prefix with an unconditional RET has no later
        // reachable instructions. Padding or aliases after RET are immaterial.
        var start = method.UnderlyingPointer;
        var next = method.AppContext.GetAddressOfNextFunctionStart(start);
        if (next != 0 && next < start + 8) return false;
        var raw = method.AppContext.Binary.MapVirtualAddressToRaw(start);
        var bytes = method.AppContext.Binary.GetRawBinaryContent();
        if (raw < 0 || raw > bytes.Length - 8) return false;
        var span = bytes.Slice((int)raw, 8);
        var expected = opcode | (uint)(field.Offset / size) << 10;
        return BinaryPrimitives.ReadUInt32LittleEndian(span) == expected
            && BinaryPrimitives.ReadUInt32LittleEndian(span[4..]) == 0xD65F03C0; // RET X30
    }

    private static bool TryEncoding(TypeAnalysisContext type, bool write, out uint opcode, out int size)
    {
        opcode = 0;
        size = 0;
        if (type is WrappedTypeAnalysisContext or GenericInstanceTypeAnalysisContext
            || type.GenericParameters.Count != 0 || type.HasAnyGenericParameters() || type.IsEnumType) return false;
        (uint load, uint store, int width) = type.FullName switch
        {
            "System.Boolean" or "System.Byte" => (0x39400000u, 0x39000001u, 1),
            "System.SByte" => (0x39C00000u, 0x39000001u, 1),
            "System.Char" or "System.UInt16" => (0x79400000u, 0x79000001u, 2),
            "System.Int16" => (0x79C00000u, 0x79000001u, 2),
            "System.Int32" or "System.UInt32" => (0xB9400000u, 0xB9000001u, 4),
            "System.Int64" or "System.UInt64" or "System.IntPtr" or "System.UIntPtr" => (0xF9400000u, 0xF9000001u, 8),
            "System.Single" => (0xBD400000u, 0xBD000000u, 4),
            "System.Double" => (0xFD400000u, 0xFD000000u, 8),
            _ when !type.IsValueType && type.Definition != null => (0xF9400000u, 0xF9000001u, 8),
            _ => (0u, 0u, 0)
        };
        opcode = write ? store : load;
        size = width;
        return size != 0;
    }
}
