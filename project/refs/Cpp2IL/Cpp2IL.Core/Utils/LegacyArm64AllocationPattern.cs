using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Cpp2IL.Core.Utils;

/// <summary>Conservative witness for stripped legacy ARM64 singleton allocation.</summary>
public static class LegacyArm64AllocationPattern
{
    public static bool IsImmediateReturn(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(bytes[..4]) == 0xD65F03C0;

    public readonly record struct ClassGuard(ulong Branch, ulong Skip, ulong Target)
    {
        public ulong Start => Branch - 4;
    }

    public static List<ulong> ClassInitTargets(ReadOnlySpan<byte> bytes, ulong start)
    {
        var result = new List<ulong>();
        foreach (var guard in ClassInitSites(bytes, start)) result.Add(guard.Target);
        return result;
    }

    public static List<ClassGuard> ClassInitSites(ReadOnlySpan<byte> bytes, ulong start)
    {
        var targets = new List<ClassGuard>();
        if (bytes.Length % 4 != 0 || bytes.Length > 65536) return targets;
        for (var i = 4; i + 20 <= bytes.Length; i += 4)
        {
            if (!FindClassLoad(bytes, i, out var loadClass)) continue;
            var flag = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i, 4));
            var testFlag = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i + 4, 4));
            var finished = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i + 8, 4));
            var testFinished = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i + 12, 4));
            var call = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i + 16, 4));
            // klass->has_cctor bit followed by klass->cctor_finished. X0 stays
            // unchanged and is the initializer's class argument.
            if ((flag & 0xffc003e0) != 0x39400000 || ((flag >> 10) & 0xfff) != 0x122 || (flag & 31) == 0
                || (testFlag & 0xfff80000) != 0x36000000 || (testFlag & 31) != (flag & 31)
                || (finished & 0xffc003e0) != 0xb9400000 || ((finished >> 10) & 0xfff) * 4 != 0xd4 || (finished & 31) == 0
                || (testFinished & 0xff000000) != 0x35000000 || (testFinished & 31) != (finished & 31)
                || (call & 0xfc000000) != 0x94000000) continue;
            var skip = Target(start + (ulong)i + 4, (testFlag >> 5) & 0x3fff, 14);
            if (skip != Target(start + (ulong)i + 12, (testFinished >> 5) & 0x7ffff, 19)) continue;
            if (skip > start + (ulong)bytes.Length) continue;
            if (skip != start + (ulong)i + 20 && skip != start + (ulong)i + 24) continue;
            // Some instances reload the class after the runtime call, which
            // clobbers X0. Never skip an arbitrary intervening instruction.
            if (skip == start + (ulong)i + 24
                && BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i + 20, 4)) != loadClass) continue;
            targets.Add(new ClassGuard(start + (ulong)i + 4, skip, Target(start + (ulong)i + 16, call & 0x3ffffff, 26)));
        }
        return targets;
    }

    private static bool FindClassLoad(ReadOnlySpan<byte> bytes, int flagOffset, out uint classLoad)
    {
        classLoad = 0;
        // Scheduling can place ordinary loads and stack-zero stores between
        // the class load and its flag test. Preserve those instructions; only
        // accept this small, explicit set which cannot change X0 or branch.
        for (var offset = flagOffset - 4; offset >= Math.Max(0, flagOffset - 16); offset -= 4)
        {
            var word = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(offset, 4));
            if (Load(word, out var destination, out _, out var addend))
            {
                if (destination != 0) continue;
                if (addend != 0) return false;
                classLoad = word;
                return true;
            }
            // STR XZR,[SP,#imm], no writeback; ADRP to a register other than X0.
            if ((word & 0xffc003ff) == 0xf90003ff
                // A scheduled unsigned-offset 32-bit load writes only Wn/Xn.
                // Preserve it before the guard; W0 would replace the class
                // pointer and cannot establish the initializer's X0 receiver.
                || ((word & 0xffc00000) == 0xb9400000 && (word & 31) != 0)
                // Scalar FP unsigned-offset loads use the separate V register
                // bank and cannot change the class pointer in X0. Preserve
                // them before the macro; do not accept writeback forms.
                || (word & 0xffc00000) is 0xbd400000 or 0xfd400000
                || ((word & 0x9f000000) == 0x90000000 && (word & 31) != 0)) continue;
            return false;
        }
        return false;
    }

    private static ulong Target(ulong pc, uint immediate, int bits)
    {
        var signed = ((int)(immediate << (32 - bits))) >> (32 - bits);
        return unchecked((ulong)((long)pc + signed * 4L));
    }

    public static ulong? Match(ReadOnlySpan<byte> bytes, ulong start, ulong initializeMetadata, ulong objectConstructor)
    {
        if (bytes.Length % 4 != 0 || bytes.Length < 40 || bytes.Length > 512 || initializeMetadata == 0 || objectConstructor == 0)
            return null;
        var words = new uint[bytes.Length / 4];
        var calls = new List<(int Index, ulong Target)>();
        for (var i = 0; i < words.Length; i++)
        {
            var word = words[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i * 4, 4));
            if ((word & 0xfc000000) != 0x94000000) continue;
            var immediate = (int)(word & 0x03ffffff);
            if ((immediate & 0x02000000) != 0) immediate |= unchecked((int)0xfc000000);
            calls.Add((i, unchecked((ulong)((long)start + i * 4L + immediate * 4L))));
        }
        if (calls.Count != 3 || calls[0].Target != initializeMetadata || calls[2].Target != objectConstructor)
            return null;
        var allocation = calls[1]; var ctor = calls[2];
        if (allocation.Target == initializeMetadata || allocation.Target == objectConstructor || allocation.Index < 1 || ctor.Index + 3 >= words.Length || ctor.Index != allocation.Index + 3)
            return null;
        // Class pointer is the sole real input; return value survives the empty
        // Object constructor and is stored in this class's singleton static.
        var classLoad = words[allocation.Index - 1];
        if (!Load(classLoad, out var register, out var classSlotRegister, out var offset) || register != 0 || offset != 0)
            return null;
        if (words[allocation.Index + 1] != 0xaa1f03e1) return null; // mov x1,xzr
        var save = words[allocation.Index + 2];
        if ((save & 0xffffffe0) != 0xaa0003e0) return null; // mov saved,x0
        var saved = save & 31;
        if (saved is < 19 or > 28) return null;
        if (!Load(words[ctor.Index + 1], out var klass, out var slot, out offset) || slot != classSlotRegister || offset != 0)
            return null;
        if (!Load(words[ctor.Index + 2], out var statics, out var klassSource, out offset) || klassSource != klass || offset != 0xb8)
            return null;
        var store = words[ctor.Index + 3];
        if ((store & 0xffc00000) != 0xf9000000 || (store & 31) != saved || ((store >> 5) & 31) != statics || ((store >> 10) & 0xfff) != 0)
            return null;
        return allocation.Target;
    }

    private static bool Load(uint instruction, out uint destination, out uint source, out uint offset)
    {
        destination = instruction & 31; source = (instruction >> 5) & 31; offset = ((instruction >> 10) & 0xfff) * 8;
        return (instruction & 0xffc00000) == 0xf9400000;
    }
}
