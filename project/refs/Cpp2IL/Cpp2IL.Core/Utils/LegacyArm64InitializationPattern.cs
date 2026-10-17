using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Cpp2IL.Core.Utils;

/// <summary>Strict native witness for an old codegen method-metadata guard.</summary>
public static class LegacyArm64InitializationPattern
{
    public readonly record struct Guard(ulong Branch, ulong Skip, ulong Flag);

    public static List<Guard> Match(ReadOnlySpan<byte> bytes, ulong start, ulong initializer, ulong writableStart, ulong writableEnd)
    {
        var result = new List<Guard>();
        if (initializer == 0 || writableEnd <= writableStart || bytes.Length % 4 != 0 || bytes.Length > 512) return result;
        var words = new uint[bytes.Length / 4];
        for (var n = 0; n < words.Length; n++) words[n] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(n * 4, 4));
        for (var i = 0; i + 7 < words.Length; i++)
        {
            var branch = words[i];
            // Never walk through an entry thunk/return into a neighboring body.
            if ((branch & 0xfc000000) == 0x14000000 || (branch & 0xfffffc1f) is 0xd65f0000 or 0xd61f0000) break;
            if (i < 2) continue;
            // TBNZ Wflag,#0,skip; exactly six metadata-init instructions follow.
            if ((branch & 0xfff80000) != 0x37000000 || ((branch >> 5) & 0x3fff) != 7) continue;
            var flagRegister = branch & 31;
            var page = words[i + 1]; var load = words[i + 2]; var handle = words[i + 3];
            var call = words[i + 4]; var one = words[i + 5]; var store = words[i + 6];
            var scratch = page & 31;
            if (scratch > 17 || (page & 0x9f000000) != 0x90000000
                || (load & 0xffc003ff) != (0xf9400000u | (scratch << 5) | scratch)
                || handle != (0xb9400000u | (scratch << 5))
                || (call & 0xfc000000) != 0x94000000
                || BranchTarget(start + (ulong)(i + 4) * 4, call) != initializer
                || ((one & 0xffffffe0) != 0x320003e0 && (one & 0xffffffe0) != 0x52800020)
                || (one & 31) != flagRegister
                || (store & 0xffc0001f) != (0x39000000u | flagRegister)) continue;
            var baseRegister = (store >> 5) & 31;
            if (baseRegister is < 19 or > 28 || flagRegister > 17) continue;
            var loadIndex = i - 1;
            for (; loadIndex >= Math.Max(0, i - 8); loadIndex--)
            {
                var word = words[loadIndex];
                if (word == (0x39400000u | (store & 0x003fffff))) break; // same byte address/register
                // Only unrelated register copies and plain SP stores may lie
                // between the flag load and its test. No calls or clobbers.
                var move = (word & 0xffe0ffe0) is 0xaa0003e0 or 0x2a0003e0;
                var stackStore = (word & 0xffc003e0) is 0xf90003e0 or 0xb90003e0;
                if (!(move && (word & 31) != flagRegister && (word & 31) != baseRegister) && !stackStore) break;
            }
            if (loadIndex < Math.Max(0, i - 8) || words[loadIndex] != (0x39400000u | (store & 0x003fffff))) continue;
            var before = loadIndex - 1;
            ulong extra = 0;
            if (before >= 0 && (words[before] & 0xffc003ff) == (0x91000000u | (baseRegister << 5) | baseRegister))
            {
                extra = (words[before] >> 10) & 0xfff; before--;
            }
            if (before < 0 || (words[before] & 0x9f00001f) != (0x90000000u | baseRegister)) continue;
            var flag = unchecked((ulong)((long)((start + (ulong)before * 4) & ~0xffful) + PageDelta(words[before])))
                + extra + ((store >> 10) & 0xfff);
            if (flag < writableStart || flag >= writableEnd) continue;
            result.Add(new Guard(start + (ulong)i * 4, start + (ulong)(i + 7) * 4, flag));
        }
        return result;
    }

    private static ulong BranchTarget(ulong pc, uint word)
        => unchecked((ulong)((long)pc + (((int)(word << 6)) >> 6) * 4L));
    private static long PageDelta(uint word)
    {
        var immediate = (((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 3);
        return (((int)(immediate << 11)) >> 11) * 4096L;
    }
}
