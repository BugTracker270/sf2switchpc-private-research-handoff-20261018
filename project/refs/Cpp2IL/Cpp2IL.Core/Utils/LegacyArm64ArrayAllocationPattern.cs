using System;
using System.Buffers.Binary;

namespace Cpp2IL.Core.Utils;

/// <summary>Strict witness for the legacy NSO single-dimensional array allocator.</summary>
public static class LegacyArm64ArrayAllocationPattern
{
    public readonly record struct Witness(ulong ClassLayout, ulong ElementSize, ulong AtomicAllocation, ulong TypedAllocation, ulong GeneralAllocation, ulong ClearMemory);

    public static Witness? Match(ReadOnlySpan<byte> bytes, ulong start, ulong raise)
    {
        if (raise == 0 || bytes.Length < 244 || bytes.Length % 4 != 0) return null;
        var words = new uint[244 / 4];
        for (var i = 0; i < words.Length; i++) words[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i * 4, 4));
        uint Word(int offset) => words[offset / 4];
        // The two arguments survive helper calls in callee-saved registers.
        if (Word(0x10) != 0xaa0103f4 || Word(0x14) != 0xaa0003f3) return null;
        // Array class rank, initialized-size flag, and its element class flag.
        if (Word(0x1c) != 0x39447a68 || Word(0x24) != 0x39448668
            || Word(0x2c) != 0xf9402268 || Word(0x30) != 0x39448508) return null;
        // Invalid lengths call the independently witnessed exception raiser;
        // the normal path bypasses that branch and computes elementSize*length.
        if (Word(0x38) != 0xd35ffe88 || Word(0x3c) != 0xb4000128
            || Call(Word(0x54), start + 0x54) != raise
            || Word(0x60) != 0xaa1303e0 || Word(0x64) != 0x91048675
            || Word(0x6c) != 0x2a0003e8 || Word(0x70) != 0x9b147d16
            || Word(0x78) != 0x910082c0) return null;
        // Bounds are null; payload starts after the 32-byte array header.
        if (Word(0x88) != 0xaa0003f5 || Word(0x8c) != 0x910042c2
            || Word(0x90) != 0x2a1f03e1 || Word(0x94) != 0xf8010c1f
            || Word(0xc0) != 0xf9000eb4 || Word(0xe4) != 0xaa1503e0
            || Word(0xf0) != 0xd65f03c0) return null;
        var layout = Call(Word(0x18), start + 0x18);
        var element = Call(Word(0x68), start + 0x68);
        var atomic = Call(Word(0x84), start + 0x84);
        var typed = Call(Word(0xac), start + 0xac);
        var general = Call(Word(0xb8), start + 0xb8);
        var clear = Call(Word(0x98), start + 0x98);
        if (layout == 0 || element == 0 || atomic == 0 || typed == 0 || general == 0 || clear == 0) return null;
        if (layout == element || atomic == typed || typed == general || atomic == general) return null;
        return new(layout, element, atomic, typed, general, clear);
    }

    private static ulong Call(uint word, ulong pc) => (word & 0xfc000000) == 0x94000000
        ? unchecked((ulong)((long)pc + (((int)(word << 6)) >> 4))) : 0;
}
