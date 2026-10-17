using System;
using System.Collections.Generic;
using System.Linq;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Cpp2IL.Core.Model.Contexts;
using LibCpp2IL.NintendoSwitch;
using Cpp2IL.Core.Utils;

namespace Cpp2IL.Core.Analysis;

/// <summary>
/// Finds exception throw helper functions. These eventually look up the type they throw by name
/// (via <c>Class::FromName(corlib, "System", "NullReferenceException")</c>), so the type name appears
/// as a plain C string in the helper's body.
/// </summary>
public static class ThrowHelperRecovery
{
    private const int MaxDepth = 5;
    private const int MaxRaiserDepth = 3;
    private const int MaxStringLength = 64;

    public static TypeAnalysisContext? GetThrownException(ApplicationAnalysisContext appContext, ulong address)
    {
        // A conditional failure path is not evidence that a native routine is
        // an exception factory or unconditional thrower. In the legacy NSO,
        // the array allocator reaches OverflowException on oversized input.
        // Only the exact native factory shape is accepted here. Unknown
        // helpers remain unresolved; the exact raiser is handled separately.
        if (appContext.Binary is NsoFile && appContext.MetadataVersion == 24f)
        {
            if (!appContext.ThrowHelperNamesByAddress.TryGetValue(address, out var factoryName))
            {
                factoryName = null;
                var binary = appContext.Binary;
                var text = binary.GetVirtualAddressOfPrimaryExecutableSection();
                var textEnd = text + (ulong)binary.GetEntirePrimaryExecutableSection().Length;
                var allocator = appContext.GetOrCreateKeyFunctionAddresses().il2cpp_codegen_object_new;
                if (address >= text && address + 64 <= textEnd && binary.TryMapVirtualAddressToRaw(address, out var raw)
                    && LegacyArm64ExceptionFactoryPattern.Match(binary.GetRawBinaryContent().Slice((int)raw, 64), address, allocator) is { } witness
                    && ReadCStringAtVirtualAddress(appContext, witness.Namespace) == "System"
                    && ReadCStringAtVirtualAddress(appContext, witness.Name) is { } directName
                    && directName.EndsWith("Exception", StringComparison.Ordinal)) factoryName = directName;
                else if (MatchNoArgumentTailFactory(appContext, address) is { } tailName)
                    factoryName = tailName;
                appContext.ThrowHelperNamesByAddress[address] = factoryName;
            }
            var factoryType = factoryName == null ? null : appContext.LibCpp2IlContext.ReflectionCache.GetType(factoryName, "System");
            var resolved = factoryType == null ? null : appContext.ResolveContextForType(factoryType);
            return resolved != null && IsExceptionType(appContext, resolved) ? resolved : null;
        }

        var name = ResolveName(appContext, address, 0);

        if (name == null)
            return null;

        var type = appContext.LibCpp2IlContext.ReflectionCache.GetType(name);

        return type == null ? null : appContext.ResolveContextForType(type);
    }

    // Factory recovery must retain initialization, not merely the allocated type.
    // These fingerprints identify the independently inspected legacy runtime's
    // default-constructor dispatcher and its zero-message factory path. Other
    // runtime builds remain unresolved rather than inheriting this contract.
    public static MethodAnalysisContext? GetProvenDefaultConstructor(ApplicationAnalysisContext app, ulong address, TypeAnalysisContext type)
    {
        if (app.Binary is not NsoFile || app.MetadataVersion != 24f || type.IsValueType)
            return null;
        if (!IsExceptionType(app, type) || !ReferenceEquals(GetThrownException(app, address), type)) return null;
        var bytes = ReadCode(app, address, 64);
        var allocation = app.GetOrCreateKeyFunctionAddresses().il2cpp_codegen_object_new;
        var original = LegacyArm64ExceptionFactoryPattern.Match(bytes, address, allocation);
        if (!(original is { } witness && IsDefaultInitializer(app, witness.Initialization))
            && MatchNoArgumentTailFactory(app, address) == null)
            return null;
        return type.Methods.SingleOrDefault(m => m.Name == ".ctor" && !m.IsStatic && m.Parameters.Count == 0);
    }

    private static bool IsExceptionType(ApplicationAnalysisContext app, TypeAnalysisContext type)
    {
        var seen = new HashSet<TypeAnalysisContext>();
        for (var current = type; current != null && seen.Add(current); current = current.BaseType)
            if (ReferenceEquals(current, app.SystemTypes.SystemExceptionType)) return true;
        return false;
    }

    private static byte[] ReadCode(ApplicationAnalysisContext app, ulong address, int count)
    {
        var binary = app.Binary;
        var start = binary.GetVirtualAddressOfPrimaryExecutableSection();
        var end = start + (ulong)binary.GetEntirePrimaryExecutableSection().Length;
        if (address < start || address + (ulong)count > end || !binary.TryMapVirtualAddressToRaw(address, out var raw)) return [];
        return binary.GetRawBinaryContent().Slice((int)raw, count).ToArray();
    }

    private static bool HasReviewedCode(ApplicationAnalysisContext app, ulong address, int count, string hash)
    {
        var bytes = ReadCode(app, address, count);
        return bytes.Length == count && Convert.ToHexString(SHA256.HashData(bytes)).Equals(hash, StringComparison.OrdinalIgnoreCase);
    }

    private static ulong DirectBranch(uint word, ulong pc, uint operation)
        => (word & 0xfc000000) == operation ? unchecked((ulong)((long)pc + (((int)(word << 6)) >> 4))) : 0;

    private static ulong? CStringAddress(uint page, uint add, ulong pc, uint register)
    {
        if ((page & 0x9f00001f) != (0x90000000 | register) || (add & 0xffc003ff) != (0x91000000 | register << 5 | register)) return null;
        var imm = ((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3);
        return unchecked((ulong)((long)(pc & ~0xffful) + (((int)(imm << 11)) >> 11) * 4096L)) + ((add >> 10) & 0xfff);
    }

    private static bool IsDefaultInitializer(ApplicationAnalysisContext app, ulong address)
    {
        if (!HasReviewedCode(app, address, 8, "acac22dd522bbc3fabdece4cc419be8580df7b7a4e73b1be82f78c292348d587")) return false;
        var wrapper = ReadCode(app, address, 8);
        var body = DirectBranch(BinaryPrimitives.ReadUInt32LittleEndian(wrapper.AsSpan(4)), address + 4, 0x14000000);
        if (!HasReviewedCode(app, body, 160, "c6256a0890b092660369cf49c667d9dd5b76134232ab68cd61c2acf0655542bc")) return false;
        var code = ReadCode(app, body, 160);
        var name = CStringAddress(BinaryPrimitives.ReadUInt32LittleEndian(code.AsSpan(28)), BinaryPrimitives.ReadUInt32LittleEndian(code.AsSpan(32)), body + 28, 1);
        return name != null && ReadCStringAtVirtualAddress(app, name.Value) == ".ctor";
    }

    private static string? MatchNoArgumentTailFactory(ApplicationAnalysisContext app, ulong address)
    {
        var bytes = ReadCode(app, address, 40);
        if (bytes.Length != 40) return null;
        var words = new uint[10];
        for (var i = 0; i < words.Length; i++) words[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i * 4));
        if (words[0] != 0xa9bf7bfd || words[1] != 0x910003fd || words[7] != 0xaa1f03e3 || words[8] != 0xa8c17bfd) return null;
        var corlib = DirectBranch(words[2], address + 8, 0x94000000);
        var factory = DirectBranch(words[9], address + 36, 0x14000000);
        if (corlib == 0 || factory == 0
            || !HasReviewedCode(app, corlib, 16, "963ae7b0935b32a1dee79fb9b805e3e6b0c088e405a85003c97f7dcaa2641500")
            || !HasReviewedCode(app, factory, 276, "9e3411197d487cd2b54a9f187d7c4fc2a56319c1cc0f7277e563af9fe58acc49")) return null;
        var body = ReadCode(app, factory, 276);
        var allocator = DirectBranch(BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(200)), factory + 200, 0x94000000);
        var initializer = DirectBranch(BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(212)), factory + 212, 0x94000000);
        if (allocator != app.GetOrCreateKeyFunctionAddresses().il2cpp_codegen_object_new || !IsDefaultInitializer(app, initializer)) return null;
        var ns = CStringAddress(words[3], words[4], address + 12, 1);
        var name = CStringAddress(words[5], words[6], address + 20, 2);
        if (ns == null || name == null || ReadCStringAtVirtualAddress(app, ns.Value) != "System") return null;
        return ReadCStringAtVirtualAddress(app, name.Value);
    }

    // Whether the provided method raises whatever exception it is handed
    // e.g. il2cpp_codegen_raise_exception, il2cpp_codegen_rethrow_exception, vm::Exception::Raise
    public static bool IsExceptionRaiser(ApplicationAnalysisContext appContext, ulong address)
    {
        if (address == 0)
            return false;

        if (appContext.ExceptionRaisersByAddress.TryGetValue(address, out var cached))
            return cached;

        var raise = appContext.GetOrCreateKeyFunctionAddresses().il2cpp_vm_exception_raise;

        if (raise == 0)
            return false;

        if (address == raise)
        {
            appContext.ExceptionRaisersByAddress[address] = true;
            return true;
        }

        // A transitive call to a raiser does not prove that this function
        // unconditionally raises its incoming argument. Legacy NSO collection
        // verifiers, for example, return normally unless their state is invalid.
        // Their short linear inspection window may also stop before the real
        // C++ throw tail. Require the independently witnessed exact target here.
        if (appContext.Binary is NsoFile && appContext.MetadataVersion == 24f)
        {
            appContext.ExceptionRaisersByAddress[address] = false;
            return false;
        }

        // grab the c++ exception raise method from the end of il2cpp::vm::Exception::Raise
        var nativeThrow = appContext.InstructionSet.InspectPotentialThrowHelper(appContext, raise).CallTargets.LastOrDefault();

        // and then check if we're calling it
        var result = nativeThrow != 0 && ReachesCall(appContext, address, nativeThrow, 0, []);

        appContext.ExceptionRaisersByAddress[address] = result;
        return result;
    }

    private static bool ReachesCall(ApplicationAnalysisContext appContext, ulong address, ulong wanted, int depth, HashSet<ulong> visited)
    {
        if (address == wanted)
            return true;

        if (depth >= MaxRaiserDepth || !visited.Add(address))
            return false;

        var (_, callTargets) = appContext.InstructionSet.InspectPotentialThrowHelper(appContext, address);

        return callTargets.Any(target => ReachesCall(appContext, target, wanted, depth + 1, visited));
    }

    private static string? ResolveName(ApplicationAnalysisContext appContext, ulong address, int depth)
    {
        if (appContext.ThrowHelperNamesByAddress.TryGetValue(address, out var cached))
            return cached;

        if (address == 0 || depth >= MaxDepth)
            return null;

        // Insert before recursing so a cycle terminates
        appContext.ThrowHelperNamesByAddress[address] = null;

        var (dataReferences, callTargets) = appContext.InstructionSet.InspectPotentialThrowHelper(appContext, address);

        var name = FindExceptionName(appContext, dataReferences);

        if (name == null)
        {
            foreach (var target in callTargets)
            {
                name = ResolveName(appContext, target, depth + 1);

                if (name != null)
                    break;
            }
        }

        appContext.ThrowHelperNamesByAddress[address] = name;
        return name;
    }

    private static string? FindExceptionName(ApplicationAnalysisContext appContext, IReadOnlyList<ulong> dataReferences)
    {
        foreach (var address in dataReferences)
            if (ReadCStringAtVirtualAddress(appContext, address) is { } text && text.EndsWith("Exception", StringComparison.Ordinal))
                return text;

        return null;
    }

    //TODO didn't we have a helper for this somewhere? Can't find it. Maybe got deleted. Maybe it's just too late
    internal static string? ReadCStringAtVirtualAddress(ApplicationAnalysisContext appContext, ulong address, int maxLength = MaxStringLength)
    {
        long offset;

        try
        {
            offset = appContext.Binary.MapVirtualAddressToRaw(address, false);
        }
        catch
        {
            return null;
        }

        if (offset <= 0)
            return null;

        var content = appContext.Binary.GetRawBinaryContent();
        var end = offset;

        while (end < content.Length && end - offset < maxLength && content[(int)end] != 0)
        {
            var c = content[(int)end];

            if (c < 32 || c >= 127)
                return null;

            end++;
        }

        if (end == offset || end >= content.Length || content[(int)end] != 0)
            return null;

        var characters = new char[end - offset];

        for (var i = 0; i < characters.Length; i++)
            characters[i] = (char)content[(int)offset + i];

        return new string(characters);
    }
}
