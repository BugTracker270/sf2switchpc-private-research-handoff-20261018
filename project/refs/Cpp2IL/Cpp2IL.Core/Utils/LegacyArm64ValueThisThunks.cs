using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using Cpp2IL.Core.Model.Contexts;
using LibCpp2IL.NintendoSwitch;

namespace Cpp2IL.Core.Utils;

/// <summary>Opt-in exact boxed-value receiver adjustors; registered metadata pointers remain unchanged.</summary>
public static class LegacyArm64ValueThisThunks
{
    public sealed record Mapping(MethodAnalysisContext Method, ulong RegisteredAddress, ulong Address, int Size);
    public sealed record Rejection(ulong RegisteredAddress, ulong Target, string Reason);
    private sealed class State
    {
        public readonly Dictionary<MethodAnalysisContext, Mapping> Mappings = new();
        public readonly List<Rejection> Rejections = new();
        public FrameTable? Frames;
        public string? FrameError;
    }
    private static readonly ConditionalWeakTable<ApplicationAnalysisContext, State> States = new();

    public static ulong AnalysisAddress(MethodAnalysisContext method) => TryGetBody(method, out var address, out _) ? address : method.UnderlyingPointer;

    public static bool TryGetBody(MethodAnalysisContext method, out ulong address, out int size)
    {
        address = method.UnderlyingPointer; size = 0;
        if (!LegacyArm64Hfa.Enabled(method) || !States.TryGetValue(method.AppContext, out var state)
            || !state.Mappings.TryGetValue(method, out var match)) return false;
        address = match.Address; size = match.Size; return true;
    }

    /// <summary>
    /// Proves only the FDE extent at the original registered native pointer. It does not
    /// select a replacement body, establish a managed identity, or register an alias.
    /// </summary>
    public static bool TryGetExactBodyRange(MethodAnalysisContext method, out int size)
        => TryGetExactBodyRange(method.AppContext, method.UnderlyingPointer, out size);

    /// <summary>Bounds-only lookup for a reviewed native address, including unregistered constructors.</summary>
    public static bool TryGetExactBodyRange(ApplicationAnalysisContext app, ulong originalAddress, out int size)
    {
        size = 0;
        if (Environment.GetEnvironmentVariable("CPP2IL_LEGACY_HFA") != "1" || app.Binary is not NsoFile || app.MetadataVersion != 24f
            || !States.TryGetValue(app, out var state)
            || state.Frames is not { } frames) return false;
        // Frame/CIE caches are populated lazily. Preparation is single-threaded and publishes
        // only the completed state; ordinary-method queries can subsequently run in parallel.
        lock (frames) return frames.TryRange(originalAddress, out size);
    }

    /// <summary>
    /// Proves an exact registered-address extent with a plain zR CIE and empty FDE
    /// augmentation. This is a conservative eligibility gate, not exception analysis.
    /// Use the address overload explicitly for a selected unboxed analysis body.
    /// </summary>
    public static bool TryGetExactPlainBodyRange(MethodAnalysisContext method, out int size)
        => TryGetExactPlainBodyRange(method.AppContext, method.UnderlyingPointer, out size);

    /// <summary>Plain-frame eligibility at the exact supplied native address; never selects an identity or alias.</summary>
    public static bool TryGetExactPlainBodyRange(ApplicationAnalysisContext app, ulong nativeAddress, out int size)
    {
        size = 0;
        if (Environment.GetEnvironmentVariable("CPP2IL_LEGACY_HFA") != "1" || app.Binary is not NsoFile || app.MetadataVersion != 24f
            || !States.TryGetValue(app, out var state) || state.Frames is not { } frames) return false;
        lock (frames) return frames.TryPlainRange(nativeAddress, out size);
    }

    public static IReadOnlyList<Mapping> AcceptedMappings(ApplicationAnalysisContext app) => States.TryGetValue(app, out var state) ? state.Mappings.Values.ToArray() : [];
    public static IReadOnlyList<Rejection> Rejections(ApplicationAnalysisContext app) => States.TryGetValue(app, out var state) ? state.Rejections.ToArray() : [];
    public static string? FrameError(ApplicationAnalysisContext app) => States.TryGetValue(app, out var state) ? state.FrameError : null;
    public static IEnumerable<ulong> AcceptedAnalysisAddresses(ApplicationAnalysisContext app) => AcceptedMappings(app).Select(match => match.Address);

    // Exposed for instruction-boundary negative fixtures; acceptance also requires metadata and exact FDEs.
    public static bool TryDecodeWords(uint first, uint second, ulong registeredAddress, out ulong target)
    {
        target = 0;
        if (first != 0x91004000 || (second & 0xFC000000) != 0x14000000 || registeredAddress % 4 != 0) return false;
        long immediate = second & 0x3FFFFFF;
        if ((immediate & 0x2000000) != 0) immediate -= 0x4000000;
        long result;
        try { result = checked((long)registeredAddress + 4 + immediate * 4); }
        catch (OverflowException) { return false; }
        if (result < 0 || (ulong)result == registeredAddress) return false;
        target = (ulong)result; return true;
    }

    private static bool HasOrdinaryValueReceiver(MethodAnalysisContext method) => method.Definition != null
        && !method.IsStatic && !method.IsAbstract && method.GenericParameters.Count == 0
        && method.DeclaringType is { IsValueType: true, IsEnumType: false } owner
        && owner.Definition != null && owner is not (GenericInstanceTypeAnalysisContext or WrappedTypeAnalysisContext)
        && owner.GenericParameters.Count == 0 && owner.Definition.RawSizes.instance_size > 16
        && !method.ReturnType.HasAnyGenericParameters() && method.Parameters.All(parameter => !parameter.ParameterType.HasAnyGenericParameters());

    /// <summary>Run after assemblies/SystemTypes exist and before raw-byte or key-function analysis.</summary>
    public static void Prepare(ApplicationAnalysisContext app, IReadOnlyList<MethodAnalysisContext> methods)
    {
        var state = new State();
        if (States.TryGetValue(app, out _)) throw new InvalidOperationException("Value-this preparation must run once per application");
        if (Environment.GetEnvironmentVariable("CPP2IL_LEGACY_HFA") != "1" || app.Binary is not NsoFile binary || app.MetadataVersion != 24f)
        { States.Add(app, state); return; }
        FrameTable frames;
        try { frames = new FrameTable(binary); }
        catch (Exception error) when (error is InvalidDataException or OverflowException or ArgumentException)
        { state.FrameError = error.Message; States.Add(app, state); return; }
        state.Frames = frames;
        var registered = methods.Select(method => method.UnderlyingPointer)
            .Concat(binary.ConcreteGenericImplementationsByAddress.Keys).Concat(binary.AllCustomAttributeGenerators).ToHashSet();
        var registeredCounts = methods.GroupBy(method => method.UnderlyingPointer).ToDictionary(group => group.Key, group => group.Count());
        var candidates = new List<Mapping>();
        foreach (var method in methods)
        {
            if (!HasOrdinaryValueReceiver(method)) continue;
            ulong pointer = method.UnderlyingPointer;
            if (!frames.IsText(pointer, 8)) continue;
            var bytes = frames.Read(pointer, 8);
            if (!TryDecodeWords(BinaryPrimitives.ReadUInt32LittleEndian(bytes), BinaryPrimitives.ReadUInt32LittleEndian(bytes[4..]), pointer, out var target)) continue;
            if (!frames.TryRange(pointer, out int wrapperSize) || wrapperSize != 8 || !frames.TryRange(target, out int bodySize))
            { state.Rejections.Add(new(pointer, target, "Missing or conflicting exact wrapper/body FDE range")); continue; }
            if (registeredCounts[pointer] != 1 || binary.ConcreteGenericImplementationsByAddress.ContainsKey(pointer)
                || binary.AllCustomAttributeGenerators.Contains(pointer))
            { state.Rejections.Add(new(pointer, target, "Registered wrapper has ambiguous metadata/generic/attribute identities")); continue; }
            if (registered.Contains(target))
            { state.Rejections.Add(new(pointer, target, "Target already has a registered method/generic/attribute identity")); continue; }
            candidates.Add(new(method, pointer, target, bodySize));
        }
        foreach (var group in candidates.GroupBy(candidate => candidate.Address))
        {
            if (group.Count() != 1)
            {
                foreach (var candidate in group) state.Rejections.Add(new(candidate.RegisteredAddress, candidate.Address, "Shared native body has ambiguous managed identity/signature"));
                continue;
            }
            var match = group.Single(); state.Mappings.Add(match.Method, match);
        }
        States.Add(app, state); // Publish only a complete immutable preparation result.
    }

    /// <summary>Run after ordinary and generic registrations, before method analysis starts.</summary>
    public static void RegisterAliases(ApplicationAnalysisContext app)
    {
        if (!States.TryGetValue(app, out var state)) return;
        foreach (var match in state.Mappings.Values.ToArray())
        {
            if (app.MethodsByAddress.TryGetValue(match.Address, out var previous) && previous.Count != 0)
            {
                if (previous.Count == 1 && ReferenceEquals(previous[0], match.Method)) continue;
                state.Mappings.Remove(match.Method);
                state.Rejections.Add(new(match.RegisteredAddress, match.Address, "Late alias conflicts with an existing managed target"));
                // Constructor preparation only: no method analysis has happened yet.
                match.Method.RawBytes = BinarySlice.Empty;
                match.Method.EnsureRawBytes();
                continue;
            }
            app.MethodsByAddress[match.Address] = [match.Method];
        }
    }

    // Bounded NSO64/MOD0 eh_frame_hdr lookup. Validates table/FDE/CIE agreement;
    // it does not interpret CFI, LSDA actions, personalities, or exception semantics.
    private sealed class FrameTable
    {
        private readonly NsoFile binary;
        private readonly (ulong Raw, ulong Address, ulong Size)[] segments;
        private readonly ulong headerStart, headerEnd, frameStart, roEnd;
        private readonly Dictionary<ulong, ulong> fdes = new();
        private readonly ulong[] starts;
        private readonly record struct FrameRange(int Size, bool Plain);
        private readonly record struct CieDescription(byte Encoding, bool Plain);
        private readonly Dictionary<ulong, FrameRange> ranges = new();
        private readonly Dictionary<ulong, CieDescription> cies = new();

        public FrameTable(NsoFile binary)
        {
            this.binary = binary;
            var raw = binary.GetRawBinaryContent();
            int rawLength = raw.Length;
            if (raw.Length < 0x100 || BinaryPrimitives.ReadUInt32LittleEndian(raw) != 0x304F534E) throw new InvalidDataException("Expected NSO header");
            segments = new[] { 0x10, 0x20, 0x30 }.Select(offset =>
            {
                var content = binary.GetRawBinaryContent();
                return ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(content[offset..]),
                    (ulong)BinaryPrimitives.ReadUInt32LittleEndian(content[(offset+4)..]),
                    (ulong)BinaryPrimitives.ReadUInt32LittleEndian(content[(offset+8)..]));
            }).ToArray();
            if (segments.Any(segment => segment.Raw < 0x100 || segment.Raw + segment.Size > (ulong)rawLength || segment.Address + segment.Size > 0x100000000UL))
                throw new InvalidDataException("NSO segment bounds differ");
            ulong mod = U32(4);
            if (U32(mod) != 0x30444F4D) throw new InvalidDataException("Missing MOD0");
            headerStart = Relative(mod, I32(mod+16)); headerEnd = Relative(mod, I32(mod+20));
            roEnd = segments[1].Address + segments[1].Size;
            if (headerStart < segments[1].Address || headerEnd > roEnd || headerStart + 12 > headerEnd) throw new InvalidDataException("Invalid exception header range");
            var header = Read(headerStart, 12);
            if (header[0] != 1 || header[1] != 0x1B || header[2] != 3 || header[3] != 0x3B) throw new InvalidDataException("Unsupported exception search encodings");
            frameStart = Relative(headerStart+4, BinaryPrimitives.ReadInt32LittleEndian(header[4..]));
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);
            if (count is 0 or > 1000000 || headerStart + 12UL + count*8UL != headerEnd || frameStart < segments[1].Address || frameStart >= roEnd)
                throw new InvalidDataException("Exception table extent differs");
            ulong previous = 0;
            starts = new ulong[count];
            for (uint index = 0; index < count; index++)
            {
                ulong at = headerStart+12+index*8UL;
                ulong start = Relative(headerStart, I32(at)), fde = Relative(headerStart, I32(at+4));
                if (!IsText(start, 4) || start % 4 != 0 || (index != 0 && start <= previous) || fde < frameStart || fde >= roEnd)
                    throw new InvalidDataException("Invalid or unsorted exception table");
                previous = start; starts[index] = start; fdes.Add(start, fde);
            }
        }

        private static ulong Relative(ulong basis, long displacement) => checked((ulong)checked((long)basis + displacement));
        public bool IsText(ulong address, int size) => size > 0 && address >= segments[0].Address && address + (ulong)size <= segments[0].Address + segments[0].Size;
        public ReadOnlySpan<byte> Read(ulong address, int size)
        {
            if (size < 0) throw new InvalidDataException("Negative native read");
            foreach (var segment in segments)
                if (address >= segment.Address && address + (ulong)size <= segment.Address + segment.Size)
                    return binary.GetRawBinaryContent().Slice(checked((int)(segment.Raw + address-segment.Address)), size);
            throw new InvalidDataException("Unmapped native read");
        }
        private uint U32(ulong address) => BinaryPrimitives.ReadUInt32LittleEndian(Read(address, 4));
        private int I32(ulong address) => BinaryPrimitives.ReadInt32LittleEndian(Read(address, 4));
        private ulong RecordEnd(ulong address)
        {
            if (address < frameStart || address >= roEnd) throw new InvalidDataException("Frame record outside region");
            uint length = U32(address);
            ulong end = address + 4 + length;
            if (length is < 4 or 0xFFFFFFFF || end > roEnd || (address < headerEnd && end > headerStart)) throw new InvalidDataException("Invalid DWARF32 record extent");
            return end;
        }
        public bool TryRange(ulong address, out int size)
        {
            if (TryFrame(address, out var frame)) { size = frame.Size; return true; }
            size = 0;
            return false;
        }
        public bool TryPlainRange(ulong address, out int size)
        {
            if (TryFrame(address, out var frame) && frame.Plain) { size = frame.Size; return true; }
            size = 0;
            return false;
        }
        private bool TryFrame(ulong address, out FrameRange frame)
        {
            if (ranges.TryGetValue(address, out frame)) return true;
            frame = default;
            if (!fdes.TryGetValue(address, out ulong fde)) return false;
            try
            {
                var cursor = new Cursor(this, fde+4, RecordEnd(fde));
                uint link = cursor.U32();
                if (link == 0 || link > fde+4) return false;
                ulong cie = fde+4-link;
                if (!cies.TryGetValue(cie, out var description))
                { description = ReadCie(cie); cies.Add(cie, description); }
                if (description.Encoding != 0x1B) return false;
                ulong start = Relative(cursor.At, cursor.I32());
                int length = cursor.I32();
                if (start != address || length <= 0 || length % 4 != 0 || !IsText(start, length)) return false;
                ulong augmentationSize = cursor.Leb(); cursor.Skip(augmentationSize);
                // A range cannot consume a separately indexed subsequent function.
                int index = Array.BinarySearch(starts, address);
                ulong next = index >= 0 && index+1 < starts.Length ? starts[index+1] : segments[0].Address+segments[0].Size;
                if (address+(ulong)length > next) return false;
                frame = new FrameRange(length, description.Plain && augmentationSize == 0);
                ranges.Add(address, frame); return true;
            }
            catch (Exception error) when (error is InvalidDataException or OverflowException or ArgumentException) { return false; }
        }
        private CieDescription ReadCie(ulong address)
        {
            var cursor = new Cursor(this, address+4, RecordEnd(address));
            if (cursor.U32() != 0) throw new InvalidDataException("CIE identifier differs");
            byte version = cursor.Byte();
            if (version is not (1 or 3)) throw new InvalidDataException("Unknown CIE version");
            string augmentation = cursor.Text();
            if (augmentation is not ("zR" or "zPLR")) throw new InvalidDataException("Unsupported CIE augmentation");
            cursor.Leb(); cursor.Leb(); // signed data alignment has identical termination rules.
            if (version == 1) cursor.Byte(); else cursor.Leb();
            ulong augmentationLength = cursor.Leb();
            ulong end = checked(cursor.At + augmentationLength); byte encoding = 0;
            foreach (char letter in augmentation[1..])
                switch (letter)
                {
                    case 'R': encoding = cursor.Byte(); break;
                    case 'L': cursor.Byte(); break;
                    case 'P':
                        byte personality = cursor.Byte();
                        // Record encoding bounds only; never dereference the personality.
                        int width = (personality & 0x0F) switch { 0 or 4 or 12 => 8, 3 or 11 => 4, 2 or 10 => 2, _ => 0 };
                        if (width == 0) throw new InvalidDataException("Unknown personality encoding");
                        cursor.Skip((ulong)width); break;
                }
            if (cursor.At != end) throw new InvalidDataException("CIE augmentation length differs");
            return new CieDescription(encoding, augmentation == "zR");
        }
        private sealed class Cursor(FrameTable image, ulong start, ulong end)
        {
            public ulong At = start;
            public byte Byte() { if (At >= end) throw new InvalidDataException("Truncated frame"); return image.Read(At++, 1)[0]; }
            public uint U32() { if (At+4 > end) throw new InvalidDataException("Truncated frame"); uint result = image.U32(At); At += 4; return result; }
            public int I32() => unchecked((int)U32());
            public void Skip(ulong length) { if (length > end-At) throw new InvalidDataException("Truncated augmentation"); At += length; }
            public ulong Leb()
            {
                ulong result = 0;
                for (int shift = 0; shift < 70; shift += 7)
                { byte value = Byte(); if (shift == 63 && (value & 0x7E) != 0) throw new InvalidDataException("LEB overflow"); result |= (ulong)(value & 0x7F) << shift; if ((value & 0x80) == 0) return result; }
                throw new InvalidDataException("Unterminated LEB");
            }
            public string Text()
            {
                var text = new System.Text.StringBuilder();
                for (int index = 0; index < 32; index++) { byte value = Byte(); if (value == 0) return text.ToString(); if (value is < 32 or > 126) break; text.Append((char)value); }
                throw new InvalidDataException("Invalid CIE augmentation text");
            }
        }
    }
}
