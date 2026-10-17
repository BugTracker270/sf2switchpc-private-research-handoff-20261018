using System;
using System.Buffers.Binary;

namespace Cpp2IL.Core.Utils;

/// <summary>A narrow legacy ARM64 exception-wrapper witness, not a generic throw recognizer.</summary>
public static class LegacyArm64ExceptionRaiserPattern
{
    public readonly record struct Witness(ulong AllocateException, ulong NativeThrow, int BodyBytes);

    private static ulong Branch(uint word, ulong address)
        => unchecked((ulong)((long)address + (((int)(word << 6)) >> 4)));

    public static Witness? Match(ReadOnlySpan<byte> bytes, ulong address)
    {
        static uint Tail(ReadOnlySpan<byte> data, int i) => BinaryPrimitives.ReadUInt32LittleEndian(data[(i * 4)..]);
        var length = Math.Min(bytes.Length & ~3, 512);
        for (var copy = 0; copy + 12 <= Math.Min(length, 64); copy += 4)
        {
            var word = BinaryPrimitives.ReadUInt32LittleEndian(bytes[copy..]);
            if ((word & 0xfc000000) is 0x14000000 or 0x94000000 || (word & 0xfffffc1f) is 0xd65f0000 or 0xd61f0000)
                break;
            var exception = (int)(word & 31);
            if ((word & 0xffffffe0) != 0xaa0003e0 || exception is < 19 or > 28)
                continue; // preserve incoming exception X0 in a callee-saved register
            var load = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(copy + 4)..]);
            if ((load & 0xfffffc00) != 0xf9400800 || ((load >> 5) & 31) != exception)
                continue; // Il2CppException.trace_ips at object + 0x10
            var trace = load & 31;
            if (trace == 31)
                continue;
            for (var test = copy + 8; test <= copy + 16 && test + 4 <= length; test += 4)
            {
                var condition = BinaryPrimitives.ReadUInt32LittleEndian(bytes[test..]);
                if ((condition & 0xff00001f) != (0xb5000000 | trace))
                {
                    var destination = condition & 31;
                    if ((condition & 0xffe0ffe0) != 0xaa0003e0 || destination == exception || destination == trace || destination is < 19 or > 28)
                        break;
                    continue;
                }
                long displacement = (condition >> 5) & 0x7ffff;
                if ((displacement & (1 << 18)) != 0)
                    displacement -= 1 << 19;
                var tail = (long)test + displacement * 4;
                if (tail <= test || tail + 32 > length)
                    break;
                var span = bytes[(int)tail..];
                if (Tail(span, 0) is not (0x321d03e0 or 0x52800100) || (Tail(span, 1) & 0xfc000000) != 0x94000000 ||
                    Tail(span, 2) != (0xf9000000 | (uint)exception) || (Tail(span, 3) & 0x9f00001f) != 0x90000001 ||
                    (Tail(span, 4) & 0xffc003ff) != 0xf9400021 || Tail(span, 5) != 0xaa1f03e2 ||
                    (Tail(span, 6) & 0xfc000000) != 0x94000000 || Tail(span, 7) != 0)
                    break;
                var allocate = Branch(Tail(span, 1), address + (ulong)tail + 4);
                var nativeThrow = Branch(Tail(span, 6), address + (ulong)tail + 24);
                if (allocate == 0 || nativeThrow == 0 || allocate == nativeThrow)
                    break;
                return new Witness(allocate, nativeThrow, (int)tail + 32);
            }
        }
        return null;
    }
}
