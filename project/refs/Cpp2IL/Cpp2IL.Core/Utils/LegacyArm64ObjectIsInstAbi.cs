using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using LibCpp2IL.NintendoSwitch;

namespace Cpp2IL.Core.Utils;

/// <summary>
/// ABI only for one reviewed Object* Object::IsInst(Object*, Class*) helper.
/// X1 remains its original native class pointer. Assignability, metadata setup,
/// COM/WinRT queries, release and error effects remain unresolved numeric calls.
/// This does not introduce CIL isinst, array-store fusion or a default result.
/// </summary>
public static class LegacyArm64ObjectIsInstAbi
{
    public const ulong Target = 0xB5B390;
    public const int NativeBodySize = 244;
    public const string NativeBodySha256 = "1b265abeee0dfb0991ffe2b237b6cf3f817a9a5071eb8787a2dc28b87d9cbec6";
    private sealed class State
    {
        public readonly object Gate = new();
        public bool Initialized;
        public bool Accepted;
    }
    private static readonly ConditionalWeakTable<ApplicationAnalysisContext, State> States = new();

    public static bool MatchesReviewedImage(ReadOnlySpan<byte> derivedLoadedImage, long helperRaw, int helperFrameSize)
    {
        if (helperFrameSize != NativeBodySize || helperRaw < 0 || helperRaw > derivedLoadedImage.Length - NativeBodySize)
            return false;
        using var algorithm = SHA256.Create();
        var bodyHash = BitConverter.ToString(algorithm.ComputeHash(derivedLoadedImage.Slice((int)helperRaw, NativeBodySize).ToArray()))
            .Replace("-", "").ToLowerInvariant();
        return bodyHash == NativeBodySha256 && LegacyArm64ClassLayoutAbi.MatchesDerivedLoadedImage(derivedLoadedImage);
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

    /// <summary>Before aliases and SSA, capture exactly original X0/X1 sources and the distinct X0 result definition.</summary>
    public static Instruction? CreateCall(MethodAnalysisContext owner, int index, ulong target)
    {
        if (!IsKnownTarget(owner.AppContext, target)) return null;
        return new Instruction(index, OpCode.Call, new Immediate(unchecked((long)target)),
            new Register(null, "X0"), new Register(null, "X0"), new Register(null, "X1"))
        { NativeObjectIsInstAbi = new(owner, target) };
    }

    /// <summary>Establishes native ABI and owner/shape only, not input class validity or managed semantics.</summary>
    public static bool IsProvenCall(MethodAnalysisContext owner, Instruction call) =>
        call.NativeObjectIsInstAbi is { } proof && ReferenceEquals(proof.Owner, owner) && proof.Target == Target
        && IsKnownTarget(owner.AppContext, proof.Target) && call.OpCode == OpCode.Call
        && call.Operands is [Immediate target, _, _, _] && target.UnsignedValue == proof.Target;

    public static int SeedResults(MethodAnalysisContext owner)
    {
        int seeded = 0;
        foreach (var call in owner.ControlFlowGraph!.Instructions)
        {
            if (call.NativeObjectIsInstAbi == null) continue;
            if (!IsProvenCall(owner, call)
                || call.Operands[1] is not LocalVariable { Register.Name: "X0" } result
                || call.Operands[2] is not LocalVariable { Register.Name: "X0" } originalObject
                || call.Operands[3] is not LocalVariable { Register.Name: "X1" }
                || ReferenceEquals(result, originalObject)
                || result.Type != null && !ReferenceEquals(result.Type, owner.AppContext.SystemTypes.SystemObjectType))
                throw new InvalidOperationException("Stale or conflicting reviewed native Object::IsInst ABI at SSA seeding");
            // Original nominal Il2CppObject* return only. No narrower subtype or
            // target-class interpretation follows from this signature witness.
            result.Type = owner.AppContext.SystemTypes.SystemObjectType;
            seeded++;
        }
        return seeded;
    }

    public static bool ValidForEmission(Instruction call, MethodAnalysisContext owner) =>
        IsProvenCall(owner, call) && call.Operands[1] is LocalVariable result
        && ReferenceEquals(result.Type, owner.AppContext.SystemTypes.SystemObjectType);
}
