using System;
using System.Buffers.Binary;

namespace Cpp2IL.Core.Utils;

/// <summary>Bounded native cache-generator/string-wrapper witnesses; no property name is inferred.</summary>
public static class LegacyArm64DefaultMemberPattern
{
    public readonly record struct Witness(ulong CString, ulong Utf8Wrapper);

    public static Witness? Match(ReadOnlySpan<byte> bytes, ulong start, ulong constructor)
    {
        if (bytes.Length < 56 || constructor == 0) return null;
        var w = Words(bytes, 14);
        if (w[0] != 0xf81e0ff3 || w[1] != 0xa9017bfd || w[2] != 0x910043fd
            || w[3] != 0xf9400408 || w[6] != 0xf9400113 || w[8] != 0xa9417bfd
            || w[9] != 0xaa0003e1 || w[10] != 0xaa1303e0 || w[11] != 0xaa1f03e2
            || w[12] != 0xf84207f3 || Branch(w[13], start + 52, false) != constructor) return null;
        if ((w[4] & 0x9f00001f) != 0x90000000 || (w[5] & 0xffc003ff) != 0x91000000) return null;
        var immediate = ((w[4] >> 5) & 0x7ffff) << 2 | ((w[4] >> 29) & 3);
        long delta = (((int)(immediate << 11)) >> 11) * 4096L;
        var literal = unchecked((ulong)((long)((start + 16) & ~0xffful) + delta)) + ((w[5] >> 10) & 0xfff);
        var helper = Branch(w[7], start + 28, true);
        return helper == 0 ? null : new(literal, helper);
    }

    public static bool IsStringWrapper(ReadOnlySpan<byte> bytes, ulong start)
    {
        if (bytes.Length < 40) return false;
        var w = Words(bytes, 10);
        return w[0] == 0xf81e0ff3 && w[1] == 0xa9017bfd && w[2] == 0x910043fd
            && w[3] == 0xaa0003f3 && Branch(w[4], start + 16, true) != 0
            && w[5] == 0xa9417bfd && w[6] == 0xaa0003e1 && w[7] == 0xaa1303e0
            && w[8] == 0xf84207f3 && Branch(w[9], start + 36, false) != 0;
    }

    private static uint[] Words(ReadOnlySpan<byte> bytes, int count)
    {
        var output = new uint[count];
        for (var i = 0; i < count; i++) output[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i * 4, 4));
        return output;
    }

    private static ulong Branch(uint word, ulong pc, bool call) => (word & 0xfc000000) == (call ? 0x94000000u : 0x14000000u)
        ? unchecked((ulong)((long)pc + (((int)(word << 6)) >> 4))) : 0;
}
