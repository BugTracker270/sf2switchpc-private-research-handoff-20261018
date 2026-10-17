using System;
using System.Buffers.Binary;

namespace Cpp2IL.Core.Utils;

/// <summary>One proven no-argument factory shape; never follows conditional error callees.</summary>
public static class LegacyArm64ExceptionFactoryPattern
{
    public readonly record struct Witness(ulong Namespace, ulong Name, ulong Corlib, ulong ClassLookup, ulong Initialization);

    public static Witness? Match(ReadOnlySpan<byte> bytes, ulong start, ulong allocation)
    {
        if (bytes.Length < 64 || allocation == 0) return null;
        var words = new uint[16];
        for (var i = 0; i < 16; i++) words[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i * 4, 4));
        if (words[0] != 0xf81e0ff3 || words[1] != 0xa9017bfd || words[2] != 0x910043fd
            || words[10] != 0xaa0003f3 || words[12] != 0xa9417bfd || words[13] != 0xaa1303e0
            || words[14] != 0xf84207f3 || words[15] != 0xd65f03c0) return null;
        if (Call(words[9], start + 36) != allocation) return null;
        var corlib = Call(words[3], start + 12);
        var lookup = Call(words[8], start + 32);
        var initialization = Call(words[11], start + 44);
        var ns = CStringAddress(words[4], words[5], start + 16, 1);
        var name = CStringAddress(words[6], words[7], start + 24, 2);
        if (corlib == 0 || lookup == 0 || initialization == 0 || ns == null || name == null
            || corlib == lookup || initialization == allocation) return null;
        return new(ns.Value, name.Value, corlib, lookup, initialization);
    }

    private static ulong? CStringAddress(uint page, uint add, ulong pc, uint register)
    {
        if ((page & 0x9f00001f) != (0x90000000 | register)
            || (add & 0xffc003ff) != (0x91000000 | register << 5 | register)) return null;
        var imm = ((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3);
        long delta = (((int)(imm << 11)) >> 11) * 4096L;
        return unchecked((ulong)((long)(pc & ~0xffful) + delta)) + ((add >> 10) & 0xfff);
    }

    private static ulong Call(uint word, ulong pc) => (word & 0xfc000000) == 0x94000000
        ? unchecked((ulong)((long)pc + (((int)(word << 6)) >> 4))) : 0;
}
