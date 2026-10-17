using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using LibCpp2IL.NintendoSwitch;

namespace Cpp2IL.Core.Utils;

/// <summary>
/// Signature only for one reviewed native bool Class::Init(Il2CppClass*) helper.
/// It remains an unresolved, effectful numeric call. This is not Runtime::ClassInit,
/// managed .cctor execution, or a host implementation of metadata/layout initialization.
/// </summary>
public static class LegacyArm64ClassLayoutAbi
{
    public const ulong Target = 0xB04F60;
    public const int NativeBodySize = 140;
    // NsoFile has applied relocations and retains its decompression buffer's capacity.
    // This is the derived in-memory image, not the original uncompressed input file.
    public const int DerivedLoadedImageSize = 74363922;
    public const string DerivedLoadedImageSha256 = "b84d5b3eb4a3a12d3260b06840414445fb2d2deff54d1ba84876e8fa28549449";
    public const string NativeBodySha256 = "496575374643a8ca7a9f1181d685de0fa4ac68574a3cc50c315d52d74a4d7dd3";
    private sealed class State
    {
        public readonly object Gate = new();
        public bool Initialized;
        public bool Accepted;
    }
    private static readonly ConditionalWeakTable<ApplicationAnalysisContext, State> States = new();

    /// <summary>Pure image/range/body guard, also usable with independent immutable fixture copies.</summary>
    public static bool MatchesReviewedImage(ReadOnlySpan<byte> derivedLoadedImage, long helperRaw, int helperFrameSize)
    {
        if (derivedLoadedImage.Length != DerivedLoadedImageSize || helperFrameSize != NativeBodySize
            || helperRaw < 0 || helperRaw > derivedLoadedImage.Length - NativeBodySize) return false;
        return Hash(derivedLoadedImage.Slice((int)helperRaw, NativeBodySize)) == NativeBodySha256
            && MatchesDerivedLoadedImage(derivedLoadedImage);
    }

    /// <summary>Exact derived relocated image identity; no original-input or helper semantics claim.</summary>
    public static bool MatchesDerivedLoadedImage(ReadOnlySpan<byte> derivedLoadedImage) =>
        derivedLoadedImage.Length == DerivedLoadedImageSize && Hash(derivedLoadedImage) == DerivedLoadedImageSha256;

    private static string Hash(ReadOnlySpan<byte> bytes)
    {
        using var algorithm = SHA256.Create();
        return BitConverter.ToString(algorithm.ComputeHash(bytes.ToArray())).Replace("-", "").ToLowerInvariant();
    }

    public static bool IsKnownTarget(ApplicationAnalysisContext app, ulong target)
    {
        if (target != Target || Environment.GetEnvironmentVariable("CPP2IL_LEGACY_HFA") != "1"
            || app.Binary is not NsoFile || app.MetadataVersion != 24f || app.Binary.PointerSizeBytes != 8) return false;
        var state = States.GetValue(app, _ => new State());
        lock (state.Gate)
        {
            if (!state.Initialized)
            {
                try
                {
                    state.Accepted = LegacyArm64ValueThisThunks.TryGetExactBodyRange(app, target, out int size)
                        && app.Binary.TryMapVirtualAddressToRaw(target, out var raw)
                        && MatchesReviewedImage(app.Binary.GetRawBinaryContent(), raw, size);
                }
                catch (Exception error) when (error is ArgumentException or InvalidOperationException or IndexOutOfRangeException
                    or OverflowException or System.IO.IOException or NotSupportedException or BadImageFormatException)
                { state.Accepted = false; }
                state.Initialized = true;
            }
            return state.Accepted;
        }
    }

    /// <summary>Before alias selection and SSA: keep only the proven native X0 input and X0 result.</summary>
    public static Instruction? CreateCall(MethodAnalysisContext owner, int index, ulong target)
    {
        if (!IsKnownTarget(owner.AppContext, target)) return null;
        return new Instruction(index, OpCode.Call, new Immediate(unchecked((long)target)), new Register(null, "X0"), new Register(null, "X0"))
        { NativeClassLayoutAbi = new(owner, target) };
    }

    /// <summary>Does not require a typed class argument: this establishes ABI, not input validity or semantics.</summary>
    public static bool IsProvenCall(MethodAnalysisContext owner, Instruction call) =>
        call.NativeClassLayoutAbi is { } proof && ReferenceEquals(proof.Owner, owner) && proof.Target == Target
        && IsKnownTarget(owner.AppContext, proof.Target) && call.OpCode == OpCode.Call
        && call.Operands is [Immediate target, _, _] && target.UnsignedValue == proof.Target;

    /// <summary>Run immediately after CreateAll, before any type inference or managed-alias resolution.</summary>
    public static int SeedResults(MethodAnalysisContext owner)
    {
        int seeded = 0;
        foreach (var call in owner.ControlFlowGraph!.Instructions)
        {
            if (call.NativeClassLayoutAbi == null) continue;
            if (!IsProvenCall(owner, call)
                || call.Operands[1] is not LocalVariable { Register.Name: "X0" } result
                || call.Operands[2] is not LocalVariable { Register.Name: "X0" }
                || result.Type != null && !ReferenceEquals(result.Type, owner.AppContext.SystemTypes.SystemBooleanType))
                throw new InvalidOperationException("Stale or conflicting reviewed native class-layout ABI at SSA seeding");
            result.Type = owner.AppContext.SystemTypes.SystemBooleanType;
            seeded++;
        }
        return seeded;
    }

    public static bool ValidForEmission(Instruction call, MethodAnalysisContext owner) =>
        IsProvenCall(owner, call) && call.Operands[1] is LocalVariable result
        && ReferenceEquals(result.Type, owner.AppContext.SystemTypes.SystemBooleanType);
}
