using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;

namespace Cpp2IL.Core.Utils;

/// <summary>
/// Exact legacy initialization witnesses inside an independently FDE-bounded ARM64 body.
/// This is not a general class-layout recognizer. Callers must provide verified initializer
/// identities and apply this only to selected legacy NSO metadata-24 bodies. Metadata flags
/// represent the compiler's method-metadata assurance, never game state. Class initialization
/// must become a semantic managed class-constructor call, not disappear.
/// </summary>
public static class LegacyArm64CfgInitializationPattern
{
    public readonly record struct MetadataGuard(ulong Load, ulong Branch, ulong Skip, ulong Flag, uint FlagRegister);
    public readonly record struct ClassGuard(ulong Start, ulong Skip, ulong Target, ulong ClassLoad, uint ClassRegister);
    public sealed record Result(List<MetadataGuard> MetadataGuards, List<ClassGuard> ClassGuards);

    public static Result Match(ReadOnlySpan<byte> exactFdeBody, ulong start, ulong metadataInitializer,
        ulong classInitializer, ulong writableStart, ulong writableEnd)
    {
        var result = new Result([], []);
        if (start % 4 != 0 || exactFdeBody.Length is < 4 or > 65536 || exactFdeBody.Length % 4 != 0
            || metadataInitializer == 0 || classInitializer == 0 || metadataInitializer == classInitializer
            || writableEnd <= writableStart || start > ulong.MaxValue - (ulong)exactFdeBody.Length) return result;
        return new Matcher(exactFdeBody, start, metadataInitializer, classInitializer, writableStart, writableEnd).Run();
    }

    private sealed class Matcher
    {
        private readonly uint[] _words;
        private readonly ulong _start, _metadata, _class, _writableStart, _writableEnd;
        private readonly List<int>[] _next, _previous;
        private readonly ulong?[][] _before;
        private readonly List<MetadataGuard> _metadataGuards = [];
        private readonly List<ClassGuard> _classGuards = [];
        private readonly Dictionary<int, int> _metadataRedirects = [];

        internal Matcher(ReadOnlySpan<byte> body, ulong start, ulong metadata, ulong klass, ulong writableStart, ulong writableEnd)
        {
            _start = start; _metadata = metadata; _class = klass; _writableStart = writableStart; _writableEnd = writableEnd;
            _words = new uint[body.Length / 4];
            _next = new List<int>[_words.Length]; _previous = new List<int>[_words.Length]; _before = new ulong?[_words.Length][];
            for (var i = 0; i < _words.Length; i++)
            {
                _words[i] = BinaryPrimitives.ReadUInt32LittleEndian(body.Slice(i * 4, 4));
                _next[i] = []; _previous[i] = [];
            }
            for (var i = 0; i < _words.Length; i++)
            {
                var w = _words[i];
                if ((w & 0xfc000000) == 0x14000000) AddEdge(i, Branch(i, w & 0x3ffffff, 26));
                else if ((w & 0xff000010) == 0x54000000) { AddEdge(i, Branch(i, (w >> 5) & 0x7ffff, 19)); AddEdge(i, i + 1); }
                else if ((w & 0x7e000000) == 0x34000000) { AddEdge(i, Branch(i, (w >> 5) & 0x7ffff, 19)); AddEdge(i, i + 1); }
                else if ((w & 0x7e000000) == 0x36000000) { AddEdge(i, Branch(i, (w >> 5) & 0x3fff, 14)); AddEdge(i, i + 1); }
                else if ((w & 0xfffffc1f) is not (0xd65f0000 or 0xd61f0000)) AddEdge(i, i + 1);
            }
        }

        internal Result Run()
        {
            Propagate();
            for (var i = 0; i < _words.Length; i++) MatchMetadata(i);
            foreach (var guard in _metadataGuards)
                if (Index(guard.Branch) == Index(guard.Load) + 1) _metadataRedirects[Index(guard.Load)] = Index(guard.Skip);
            for (var i = 0; i < _words.Length; i++) MatchClass(i);
            return new Result(_metadataGuards, _classGuards);
        }

        private void AddEdge(int source, int target)
        {
            if (target < 0 || target >= _words.Length || _next[source].Contains(target)) return;
            _next[source].Add(target); _previous[target].Add(source);
        }
        private int Branch(int i, uint immediate, int bits) => i + Sign(immediate, bits);
        private ulong Address(int i) => _start + (ulong)i * 4;
        private int Index(ulong address) => checked((int)((address - _start) / 4));
        private static int Sign(uint value, int bits) => ((int)(value << (32 - bits))) >> (32 - bits);
        private bool In(int i) => i >= 0 && i < _words.Length;
        private ulong CallTarget(int i) => unchecked((ulong)((long)Address(i) + Sign(_words[i] & 0x3ffffff, 26) * 4L));

        private void Propagate()
        {
            _before[0] = new ulong?[31];
            var queue = new Queue<int>(); queue.Enqueue(0);
            var queued = new bool[_words.Length]; queued[0] = true;
            while (queue.Count > 0)
            {
                var i = queue.Dequeue(); queued[i] = false;
                var after = (ulong?[])_before[i].Clone(); var w = _words[i];
                Effects(w, out _, out uint writes, out bool known);
                if (!known) Array.Clear(after);
                else for (var r = 0; r < 31; r++) if ((writes & (1u << r)) != 0) after[r] = null;
                int rd = (int)(w & 31), rn = (int)((w >> 5) & 31);
                if ((w & 0xfc000000) == 0x94000000)
                {
                    // Only the two independently identified runtime helpers are trusted here.
                    bool knownCall = CallTarget(i) == _metadata || CallTarget(i) == _class;
                    for (var r = 0; r < 31; r++) if (!knownCall || r < 19 || r == 30) after[r] = null;
                }
                else if (rd < 31 && (w & 0x9f000000) == 0x90000000)
                {
                    uint imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3);
                    after[rd] = unchecked((ulong)((long)(Address(i) & ~0xffful) + Sign(imm, 21) * 4096L));
                }
                else if (rd < 31 && (w & 0x9f000000) == 0x10000000)
                {
                    uint imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3);
                    after[rd] = unchecked((ulong)((long)Address(i) + Sign(imm, 21)));
                }
                else if (rd < 31 && (w & 0x1f000000) == 0x11000000 && rn < 31 && _before[i][rn] is ulong value)
                {
                    ulong imm = ((w >> 10) & 0xfff) << (((w >> 22) & 1) == 0 ? 0 : 12);
                    var v = (w & 0x40000000) == 0 ? unchecked(value + imm) : unchecked(value - imm);
                    after[rd] = (w & 0x80000000) == 0 ? (uint)v : v;
                }
                else if (rd < 31 && IsMove(w))
                {
                    int rm = (int)((w >> 16) & 31);
                    var v = rm == 31 ? 0ul : _before[i][rm];
                    after[rd] = (w & 0x80000000) == 0 && v.HasValue ? (uint)v.Value : v;
                }
                foreach (var target in _next[i])
                {
                    bool changed = false;
                    if (_before[target] == null) { _before[target] = (ulong?[])after.Clone(); changed = true; }
                    else for (var r = 0; r < 31; r++)
                        if (_before[target][r].HasValue && _before[target][r] != after[r]) { _before[target][r] = null; changed = true; }
                    if (changed && !queued[target]) { queue.Enqueue(target); queued[target] = true; }
                }
            }
        }

        private void MatchMetadata(int test)
        {
            var branch = _words[test];
            if (_before[test] == null || (branch & 0xfff80000) is not (0x36000000 or 0x37000000)) return;
            uint flagRegister = branch & 31;
            if (flagRegister > 17) return;
            bool nonzero = (branch & 0x01000000) != 0;
            int branchTarget = Branch(test, (branch >> 5) & 0x3fff, 14);
            int block = nonzero ? test + 1 : branchTarget, skip = nonzero ? branchTarget : test + 1;
            if (!In(block) || !In(skip) || !In(block + 5)) return;
            uint page = _words[block], load = _words[block + 1], handle = _words[block + 2], call = _words[block + 3], one = _words[block + 4], store = _words[block + 5];
            uint scratch = page & 31, baseRegister = (store >> 5) & 31;
            if (scratch > 17 || (page & 0x9f000000) != 0x90000000
                || (load & 0xffc003ff) != (0xf9400000u | (scratch << 5) | scratch)
                || handle != (0xb9400000u | (scratch << 5))
                || (call & 0xfc000000) != 0x94000000 || CallTarget(block + 3) != _metadata
                || ((one & 0xffffffe0) != 0x320003e0 && (one & 0xffffffe0) != 0x52800020)
                || (one & 31) != flagRegister || (store & 0xffc0001f) != (0x39000000u | flagRegister)
                || baseRegister is < 19 or > 28 || !OnlySequentialInterior(block, block + 5)
                || _before[block + 5] == null || _before[block + 5][baseRegister] is not ulong baseValue) return;
            ulong flag = unchecked(baseValue + ((store >> 10) & 0xfff));
            if (flag < _writableStart || flag >= _writableEnd || !Equivalent(block + 6, skip, false)) return;
            for (int loadIndex = test - 1; loadIndex >= Math.Max(0, test - 8); loadIndex--)
            {
                var w = _words[loadIndex];
                if (w == (0x39400000u | (store & 0x003fffff)))
                {
                    if (_before[loadIndex] == null || _before[loadIndex][baseRegister] != baseValue
                        || !OnlySequentialInterior(loadIndex, test) || !DeadAfter(skip, flagRegister)) return;
                    _metadataGuards.Add(new MetadataGuard(Address(loadIndex), Address(test), Address(skip), flag, flagRegister));
                    return;
                }
                // Keep scheduled arithmetic in place. Only unrelated copies and the exact plain
                // 32-bit register EOR form are allowed between a flag load and its bit test.
                if (!(IsMove(w) || (w & 0xffe0fc00) == 0x4a000000)) return;
                Effects(w, out uint reads, out uint writes, out bool known);
                if (!known || ((reads | writes) & (1u << (int)flagRegister)) != 0 || (writes & (1u << (int)baseRegister)) != 0) return;
            }
        }

        private void MatchClass(int i)
        {
            if (!In(i + 3) || _before[i] == null) return;
            uint flag = _words[i], testFlag = _words[i + 1], finished = _words[i + 2], testFinished = _words[i + 3];
            if ((flag & 0xffc003e0) != 0x39400000 || ((flag >> 10) & 0xfff) != 0x122
                || (flag & 31) is 0 or > 17 || (testFlag & 0xfff80000) != 0x36000000 || (testFlag & 31) != (flag & 31)
                || (finished & 0xffc003e0) != 0xb9400000 || ((finished >> 10) & 0xfff) * 4 != 0xd4
                || (finished & 31) is 0 or > 17 || (testFinished & 0x7e000000) != 0x34000000 || (testFinished & 31) != (finished & 31)
                || !OnlySequentialInterior(i, i + 3) || !FindClassLoad(i, out int classLoad)) return;
            int skip = Branch(i + 1, (testFlag >> 5) & 0x3fff, 14);
            int finishTarget = Branch(i + 3, (testFinished >> 5) & 0x7ffff, 19);
            bool cbnz = (testFinished & 0x01000000) != 0;
            int call = cbnz ? i + 4 : finishTarget;
            int initialized = cbnz ? finishTarget : i + 4;
            int afterCall = call + 1;
            // This reload is exactly the same immutable metadata class-slot load. A semantic
            // void class-constructor call preserves its typed managed receiver; native X0 needs
            // reloading only because the runtime ABI clobbers caller-saved registers.
            if (In(afterCall) && _words[afterCall] == _words[classLoad] && OnlySequentialInterior(call, afterCall)) afterCall++;
            if (!In(call) || !In(skip) || !Equivalent(initialized, skip, true)
                || (_words[call] & 0xfc000000) != 0x94000000 || CallTarget(call) != _class
                || !Equivalent(afterCall, skip, true) || !DeadAfter(skip, flag & 31) || !DeadAfter(skip, finished & 31)) return;
            // No unrelated path may enter a cold helper expecting a different class receiver.
            if (_previous[call].Count != 1 || _previous[call][0] != i + 3) return;
            _classGuards.Add(new ClassGuard(Address(i), Address(skip), _class, Address(classLoad), 0));
        }

        private bool FindClassLoad(int flag, out int load)
        {
            load = -1;
            for (int i = flag - 1; i >= Math.Max(0, flag - 4); i--)
            {
                uint w = _words[i];
                if ((w & 0xffc00000) == 0xf9400000 && (w & 31) == 0)
                {
                    if (((w >> 10) & 0xfff) != 0 || ((w >> 5) & 31) is < 19 or > 28 || !OnlySequentialInterior(i, flag)) return false;
                    load = i; return true;
                }
                if ((w & 0x3b000000) == 0x39000000 && (w & 0x00400000) != 0 && (w & 31) != 0) continue;
                if ((w & 0xffc003ff) == 0xf90003ff || ((w & 0x9f000000) == 0x90000000 && (w & 31) != 0)) continue;
                return false;
            }
            return false;
        }

        private bool OnlySequentialInterior(int first, int last)
        {
            for (int i = first + 1; i <= last; i++) if (_previous[i].Count != 1 || _previous[i][0] != i - 1) return false;
            return true;
        }
        private int Normalize(int i, bool metadata)
        {
            var seen = new HashSet<int>();
            while (In(i) && seen.Add(i))
            {
                if (metadata && _metadataRedirects.TryGetValue(i, out int skip)) { i = skip; continue; }
                if ((_words[i] & 0xfc000000) == 0x14000000) { i = Branch(i, _words[i] & 0x3ffffff, 26); continue; }
                break;
            }
            return i;
        }
        private bool Equivalent(int left, int right, bool metadata)
        {
            left = Normalize(left, metadata); right = Normalize(right, metadata);
            if (!In(left) || !In(right)) return false;
            if (left == right) return true;
            uint a = _words[left], b = _words[right];
            // Explicitly compare the zero and nonzero successors. This preserves the key
            // selection CBZ/CBNZ that is duplicated around the native cold metadata path.
            if ((a & 0x7e000000) != 0x34000000 || (b & 0x7e000000) != 0x34000000 || (a & 0x8000001f) != (b & 0x8000001f)) return false;
            int at = Branch(left, (a >> 5) & 0x7ffff, 19), bt = Branch(right, (b >> 5) & 0x7ffff, 19);
            int az = (a & 0x01000000) == 0 ? at : left + 1, an = (a & 0x01000000) == 0 ? left + 1 : at;
            int bz = (b & 0x01000000) == 0 ? bt : right + 1, bn = (b & 0x01000000) == 0 ? right + 1 : bt;
            return Normalize(az, metadata) == Normalize(bz, metadata) && Normalize(an, metadata) == Normalize(bn, metadata);
        }
        private bool DeadAfter(int start, uint register)
        {
            var seen = new HashSet<int>(); var todo = new Stack<int>(); todo.Push(start);
            uint bit = 1u << (int)register;
            while (todo.Count > 0)
            {
                int i = todo.Pop(); if (!In(i) || !seen.Add(i)) continue;
                uint word = _words[i];
                // An out-of-FDE successor cannot prove a caller-saved flag dead. In particular,
                // an unconditional branch can be an ABI tail call whose arguments remain live.
                if ((word & 0xfc000000) == 0x14000000 && !In(Branch(i, word & 0x3ffffff, 26))) return false;
                if ((word & 0x7e000000) == 0x34000000 && !In(Branch(i, (word >> 5) & 0x7ffff, 19))) return false;
                if ((word & 0x7e000000) == 0x36000000 && !In(Branch(i, (word >> 5) & 0x3fff, 14))) return false;
                if ((word & 0xff000010) == 0x54000000 && !In(Branch(i, (word >> 5) & 0x7ffff, 19))) return false;
                Effects(_words[i], out uint reads, out uint writes, out bool known);
                if (!known || (reads & bit) != 0) return false;
                if ((writes & bit) != 0) continue;
                foreach (int target in _next[i]) todo.Push(target);
            }
            return true;
        }

        private static bool IsMove(uint w) => (w & 0x7fe0ffe0) == 0x2a0003e0;
        private static uint Bit(uint register) => register == 31 ? 0 : 1u << (int)register;
        private static void Effects(uint w, out uint reads, out uint writes, out bool known)
        {
            uint rd = w & 31, rn = (w >> 5) & 31, rm = (w >> 16) & 31;
            reads = writes = 0; known = true;
            if ((w & 0x9f000000) is 0x90000000 or 0x10000000) { writes = Bit(rd); return; }
            if ((w & 0x1f800000) == 0x12800000)
            {
                writes = Bit(rd);
                if (((w >> 29) & 3) == 3) reads = Bit(rd); // MOVK preserves the other destination bits.
                return;
            }
            if ((w & 0x1f000000) == 0x11000000) { reads = Bit(rn); writes = Bit(rd); return; }
            if ((w & 0x1f800000) == 0x12000000) { reads = Bit(rn); writes = Bit(rd); return; } // Logical immediate, including MOV #1.
            if ((w & 0x1f000000) is 0x0a000000 or 0x0b000000) { reads = Bit(rn) | Bit(rm); writes = Bit(rd); return; }
            if ((w & 0x3b000000) == 0x39000000 || (w & 0x3b200000) == 0x38000000)
            {
                reads = Bit(rn);
                bool vector = (w & 0x04000000) != 0, load = ((w >> 22) & 3) != 0;
                if (!vector) { if (load) writes = Bit(rd); else reads |= Bit(rd); }
                if ((w & 0x3b200000) == 0x38000000 && ((w >> 10) & 3) is 1 or 3) writes |= Bit(rn);
                return;
            }
            if ((w & 0x3a000000) == 0x28000000)
            {
                reads = Bit(rn); bool vector = (w & 0x04000000) != 0, load = (w & 0x00400000) != 0;
                uint pair = Bit(rd) | Bit((w >> 10) & 31);
                if (!vector) { if (load) writes = pair; else reads |= pair; }
                if (((w >> 23) & 3) is 1 or 3) writes |= Bit(rn);
                return;
            }
            if ((w & 0x7e000000) is 0x34000000 or 0x36000000) { reads = Bit(rd); return; }
            if ((w & 0xfc000000) == 0x94000000 || (w & 0xfffffc1f) == 0xd63f0000)
            {
                reads = 0x7ffff; writes = 0x4007ffff; return;
            }
            if ((w & 0xfc000000) == 0x14000000 || (w & 0xff000010) == 0x54000000 || w == 0xd503201f) return;
            if ((w & 0xfffffc1f) == 0xd65f0000) { reads = Bit(rn) | 3u; return; } // Include integer return registers.
            if ((w & 0xfffffc1f) == 0xd61f0000) { reads = Bit(rn) | 0x7ffffu; return; } // Tail call arguments.
            // Unknown effects lose all constant information and cannot establish flag death.
            known = false;
        }
    }
}
