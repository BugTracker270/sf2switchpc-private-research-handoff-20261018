using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Cpp2IL.Core.Utils;

/// <summary>Bounded-width ARM64 B/BL indexing without retaining a full decoded text section.</summary>
public static class LegacyArm64ThunkScanner
{
    private static ulong Target(uint word, ulong address)
        => unchecked((ulong)((long)address + (((int)(word << 6)) >> 4)));

    private static bool Terminates(uint word)
        => word == 0 || (word & 0xfc000000) == 0x14000000 ||
           (word & 0xfffffc1f) is 0xd65f0000 or 0xd61f0000 || (word & 0xffe0001f) == 0xd4200000;

    public static List<ulong> Find(ReadOnlySpan<byte> code, ulong address, ulong target, uint maxBytesBack,
        ISet<ulong> ignored, bool preserveExceptionX0 = false)
    {
        var calls = new HashSet<ulong>();
        for (var offset = 0; offset + 4 <= code.Length; offset += 4)
        {
            var word = BinaryPrimitives.ReadUInt32LittleEndian(code[offset..]);
            if ((word & 0xfc000000) == 0x94000000)
                calls.Add(Target(word, address + (ulong)offset));
        }
        var result = new List<ulong>();
        for (var offset = 0; offset + 4 <= code.Length; offset += 4)
        {
            var word = BinaryPrimitives.ReadUInt32LittleEndian(code[offset..]);
            var branch = address + (ulong)offset;
            if ((word & 0xfc000000) != 0x14000000 || Target(word, branch) != target || ignored.Contains(branch))
                continue;
            for (var back = 0; back <= maxBytesBack / 4 && back * 4 <= offset; back++)
            {
                var start = offset - back * 4;
                if (start != 0 && !calls.Contains(address + (ulong)start) &&
                    !Terminates(BinaryPrimitives.ReadUInt32LittleEndian(code[(start - 4)..])))
                    continue;
                var candidate = address + (ulong)start;
                if (!ignored.Contains(candidate))
                {
                    // A legacy raiser thunk may clear auxiliary arguments,
                    // but must hand the same incoming exception X0 onward.
                    var safe = true;
                    if (preserveExceptionX0)
                        for (var at = start; at < offset; at += 4)
                        {
                            var setup = BinaryPrimitives.ReadUInt32LittleEndian(code[at..]);
                            if (setup is not (0xaa1f03e1 or 0xaa1f03e2)) { safe = false; break; }
                        }
                    if (safe) result.Add(candidate);
                }
                break;
            }
        }
        return result;
    }
}
