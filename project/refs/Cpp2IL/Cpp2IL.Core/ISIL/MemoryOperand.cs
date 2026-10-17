using System;
using System.Text;
using System.Buffers.Binary;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;

namespace Cpp2IL.Core.ISIL;

/// <summary>
/// Memory operand in the format of [base+addend+index*scale]
/// </summary>
public struct MemoryOperand(IOperand? baseRegister = null, IOperand? indexRegister = null, long addend = 0, int scale = 0) : IOperand
{
    public IOperand? Base = baseRegister;
    public IOperand? Index = indexRegister;
    public long Addend = addend;
    public int Scale = scale;

    // Retain scalar FP access width before ARM64 S/D registers are normalized to V.
    // Zero means the access was not independently identified as scalar floating point.
    public int ScalarFloatingSize;

    // Evidence about one original native read, not a type or managed-memory
    // interpretation. Copying/inlining this struct retains the immutable witness.
    public NativeReadProof? NativeRead;

    /// <summary>
    /// An exact unsigned-offset LDR X read in the reviewed legacy image. Width is
    /// checked against original bytes, never inferred from a normalized register
    /// or a propagated managed type. This does not prove SSA base-value identity.
    /// </summary>
    public sealed class NativeReadProof
    {
        public MethodAnalysisContext Owner { get; }
        public ulong Address { get; }
        public uint Word { get; }
        public int WidthBytes => 8;
        public string NativeBaseRegister { get; }
        public string NativeDestinationRegister { get; }
        public long Addend { get; }
        public IOperand BoundBase { get; }

        private NativeReadProof(MethodAnalysisContext owner, ulong address, uint word, IOperand boundBase)
        {
            Owner = owner; Address = address; Word = word;
            NativeBaseRegister = "X" + ((word >> 5) & 31);
            NativeDestinationRegister = "X" + (word & 31);
            Addend = ((word >> 10) & 0xFFF) * 8L;
            BoundBase = boundBase;
        }

        /// <summary>Creates evidence only from actual owned native bytes; no claimed-width callback.</summary>
        public static NativeReadProof? TryCreate(MethodAnalysisContext owner, ulong address, MemoryOperand source)
        {
            if (!TryRead(owner, address, out uint word) || !IsUnsignedPointerRead(word)) return null;
            // Only the decoder's original unversioned native register can seed
            // a proof. Later SSA/local identities require checked derivation.
            if (source.Base is not Register { Version: -1 } register
                || register.Name != "X" + ((word >> 5) & 31)) return null;
            var proof = new NativeReadProof(owner, address, word, register);
            return proof.MatchesShape(source) ? proof : null;
        }

        /// <summary>
        /// Rechecks the exact owner, image gate, body range, instruction word and
        /// live memory shape and currently bound base. SSA value/root identity
        /// must additionally be proved by the consuming dataflow witness; the
        /// original native register name is evidence, not the final SSA name.
        /// </summary>
        public bool ValidFor(MethodAnalysisContext owner, MemoryOperand source) =>
            ReferenceEquals(Owner, owner) && ReferenceEquals(source.NativeRead, this)
            && TryRead(owner, Address, out uint word) && word == Word && IsUnsignedPointerRead(word)
            && MatchesShape(source);

        private bool MatchesShape(MemoryOperand source)
        {
            return SameBase(source.Base, BoundBase) && source.Addend == Addend
                && source.Index == null && source.Scale == 0 && source.ScalarFloatingSize == 0;
        }

        private static bool SameBase(IOperand? left, IOperand right) =>
            left is Register a && right is Register b ? a == b : ReferenceEquals(left, right);

        // Called only at existing SSA-renaming or proved copy-replacement sites.
        // A stale/untracked mutation loses its proof; it cannot be blessed later.
        internal NativeReadProof? RebindBaseForProvenCopy(MemoryOperand source, IOperand replacement) =>
            replacement is Register or LocalVariable && ValidFor(Owner, source)
                ? SameBase(replacement, BoundBase) ? this : new NativeReadProof(Owner, Address, Word, replacement)
                : null;

        private static bool IsUnsignedPointerRead(uint word) =>
            (word & 0xFFC00000u) == 0xF9400000u // unsigned immediate, 64-bit LDR
            && (word & 31) != 31 && ((word >> 5) & 31) != 31; // no ZR destination / SP base

        private static bool TryRead(MethodAnalysisContext owner, ulong address, out uint word)
        {
            word = 0;
            if (!LegacyArm64Hfa.Enabled(owner) || owner.AppContext.Binary.PointerSizeBytes != 8
                || !LegacyArm64ClassLayoutAbi.IsKnownTarget(owner.AppContext, LegacyArm64ClassLayoutAbi.Target)
                || address % 4 != 0) return false;
            try
            {
                ulong start = LegacyArm64ValueThisThunks.AnalysisAddress(owner);
                if (!LegacyArm64ValueThisThunks.TryGetExactBodyRange(owner.AppContext, start, out int size)
                    || size < 4 || address < start || address - start > (ulong)(size - 4)
                    || !owner.AppContext.Binary.TryMapVirtualAddressToRaw(address, out var raw)) return false;
                var bytes = owner.AppContext.Binary.GetRawBinaryContent();
                if (raw < 0 || raw > bytes.Length - 4) return false;
                word = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice((int)raw, 4));
                return true;
            }
            catch (Exception error) when (error is ArgumentException or InvalidOperationException or IndexOutOfRangeException
                or OverflowException or System.IO.IOException or NotSupportedException or BadImageFormatException)
            { return false; }
        }
    }

    /// <summary>Retains evidence only through an existing compiler-proved base replacement.</summary>
    internal void RebindBaseForProvenCopy(IOperand replacement)
    {
        NativeRead = NativeRead?.RebindBaseForProvenCopy(this, replacement);
        Base = replacement;
    }

    public bool IsConstant => Base == null && Index == null && Scale == 0;

    public override string ToString()
    {
        var sb = new StringBuilder("[");
        var needsPlus = false;

        if (Base != null)
        {
            sb.Append(Base);
            needsPlus = true;
        }

        if (Addend != 0)
        {
            if (needsPlus || Addend < 0)
                sb.Append(Addend > 0 ? '+' : '-');
            sb.Append($"{Math.Abs(Addend):X}");
            needsPlus = true;
        }

        if (Index != null)
        {
            if (needsPlus)
                sb.Append('+');
            sb.Append(Index);

            if (Scale > 1)
            {
                sb.Append('*');
                sb.Append(Scale);
            }
        }

        sb.Append(']');
        return sb.ToString();
    }
}
