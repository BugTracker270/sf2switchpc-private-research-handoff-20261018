using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Utils;
using System.Reflection;

if (args.Length is < 1 or > 2) throw new ArgumentException("Verified USB root and optional version tag required");
bool testRecovery = args.Length == 2;
if (testRecovery && !System.Text.RegularExpressions.Regex.IsMatch(args[1], "^[a-z0-9-]+$")) throw new ArgumentException("Invalid report tag");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var binary = Guard("unpacked/effective/exefs/main");
var metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (Hash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Original source hash differs");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
if (testRecovery) Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var types = app.Assemblies.SelectMany(assembly => assembly.Types).ToArray();
var anchorTypes = new[] { "CodeStage.AntiCheat.ObscuredTypes.ObscuredInt", "System.Boolean", "System.Int32", "System.Double" };
var observations = new List<object>();
var tests = new List<object>();
void Check(string name, bool condition) { if (!condition) throw new Exception("Value-this check failed: " + name); tests.Add(new { name, status = "PASS" }); }
if (testRecovery) Console.WriteLine(JsonSerializer.Serialize(new { frame_error=LegacyArm64ValueThisThunks.FrameError(app), accepted=LegacyArm64ValueThisThunks.AcceptedMappings(app).Count,
    rejected=LegacyArm64ValueThisThunks.Rejections(app).Count }));
foreach (var name in anchorTypes)
{
    var type = types.Single(candidate => candidate.FullName == name);
    var method = name.StartsWith("CodeStage", StringComparison.Ordinal)
        ? type.Methods.Single(candidate => candidate.Name == "InternalDecrypt")
        : type.Methods.Single(candidate => candidate.Name.EndsWith("ToType", StringComparison.Ordinal));
    var raw = (int)app.Binary.MapVirtualAddressToRaw(method.UnderlyingPointer);
    var span = app.Binary.GetRawBinaryContent().Slice(raw, 8);
    uint first = BinaryPrimitives.ReadUInt32LittleEndian(span), branch = BinaryPrimitives.ReadUInt32LittleEndian(span[4..]);
    int immediate = (int)(branch & 0x3FFFFFF); if ((immediate & 0x2000000) != 0) immediate -= 0x4000000;
    ulong target = unchecked((ulong)((long)method.UnderlyingPointer + 4L + immediate * 4L));
    bool exact = first == 0x91004000 && (branch & 0xFC000000) == 0x14000000;
    if (testRecovery)
    {
        Check(name+" exact selected body", exact && LegacyArm64ValueThisThunks.TryGetBody(method, out ulong selected, out int size) && selected == target && size == (name.StartsWith("CodeStage", StringComparison.Ordinal) ? 520 : 252));
        Check(name+" registered pointer remains", method.UnderlyingPointer == method.Definition!.MethodPointer && method.UnderlyingPointer != target);
        Check(name+" unique direct unboxed alias", app.MethodsByAddress.TryGetValue(target, out var aliases) && aliases.Count == 1 && ReferenceEquals(aliases[0], method));
        Check(name+" registered alias retained", app.MethodsByAddress[method.UnderlyingPointer].Contains(method));
        Check(name+" exact raw body", method.RawBytes.Length == (name.StartsWith("CodeStage", StringComparison.Ordinal) ? 520 : 252));
    }
    observations.Add(new { type = name, type.IsValueType, method = method.Name, underlying_pointer = $"0x{method.UnderlyingPointer:X}", definition_pointer = $"0x{method.Definition!.MethodPointer:X}",
        first_instruction = $"0x{first:X8}", second_instruction = $"0x{branch:X8}", exact_add16_tail_branch = exact,
        target = exact ? $"0x{target:X}" : null, registered_aliases = app.MethodsByAddress.GetValueOrDefault(method.UnderlyingPointer)?.Select(candidate => candidate.FullName).ToArray(),
        target_aliases = exact ? app.MethodsByAddress.GetValueOrDefault(target)?.Select(candidate => candidate.FullName).ToArray() : null,
        instance_fields = type.Fields.Where(field=>!field.IsStatic).Select(field=>new { field.Name, normalized_offset=field.Offset,
            backing_offset=field.BackingData?.FieldOffset, override_offset=field.OverrideOffset, type=field.FieldType.FullName }).ToArray(),
        method.IsStatic, parameters = method.Parameters.Select(parameter => parameter.ParameterType.FullName).ToArray(), returns = method.ReturnType.FullName });
}
if (testRecovery)
{
    Check("signed backward tail branch decoded", LegacyArm64ValueThisThunks.TryDecodeWords(0x91004000,0x17FFFF47,0x7A9200,out ulong target) && target==0x7A8F20);
    foreach (uint first in new uint[] {0x91002000,0x91008000,0x91004001,0x91004020,0xD503201F})
        Check($"different receiver adjustor rejected {first:X}", !LegacyArm64ValueThisThunks.TryDecodeWords(first,0x17FFFF47,0x7A9200,out _));
    Check("call instead of tail branch rejected", !LegacyArm64ValueThisThunks.TryDecodeWords(0x91004000,0x97FFFF47,0x7A9200,out _));
    Check("self target rejected", !LegacyArm64ValueThisThunks.TryDecodeWords(0x91004000,0x17FFFFFF,0x7A9200,out _));
    Check("unaligned entry rejected", !LegacyArm64ValueThisThunks.TryDecodeWords(0x91004000,0x17FFFF47,0x7A9201,out _));
    var internalDecrypt = types.Single(type=>type.FullName==anchorTypes[0]).Methods.Single(method=>method.Name=="InternalDecrypt");
    var ordinary = typeof(LegacyArm64ValueThisThunks).GetMethod("HasOrdinaryValueReceiver", BindingFlags.NonPublic|BindingFlags.Static)!;
    Check("actual ordinary receiver metadata", (bool)ordinary.Invoke(null,[internalDecrypt])!);
    var attributes = internalDecrypt.OverrideAttributes;
    try { internalDecrypt.OverrideAttributes=internalDecrypt.Attributes|MethodAttributes.Static; Check("static metadata rejected", !(bool)ordinary.Invoke(null,[internalDecrypt])!); }
    finally { internalDecrypt.OverrideAttributes=attributes; }
    var reference = app.SystemTypes.SystemObjectType.Methods.First(method=>method.Name=="ToString" && method.Parameters.Count==0);
    Check("reference receiver metadata rejected", !(bool)ordinary.Invoke(null,[reference])!);
    Check("shared target overload identities rejected", LegacyArm64ValueThisThunks.Rejections(app).Count(rejection=>rejection.Target is 0x82A2A0 or 0x59F850)==4
        && !app.MethodsByAddress.ContainsKey(0x82A2A0) && !app.MethodsByAddress.ContainsKey(0x59F850));
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA",null);
    Check("opt-in disabled lookup", !LegacyArm64ValueThisThunks.TryGetBody(internalDecrypt,out _,out _) && LegacyArm64ValueThisThunks.AnalysisAddress(internalDecrypt)==internalDecrypt.UnderlyingPointer);
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");
    Check("native frame table accepted", LegacyArm64ValueThisThunks.FrameError(app)==null);
}
var report = new { status = testRecovery ? "PASS_SCOPED_VALUE_THIS_THUNK_SELECTION_AND_ALIASES" : "CPP2IL_REGISTERED_POINTER_OBSERVATIONS_ONLY", observations, checks=tests.Count, tests,
    accepted_bodies = testRecovery ? LegacyArm64ValueThisThunks.AcceptedMappings(app).Count : 0,
    rejections = testRecovery ? LegacyArm64ValueThisThunks.Rejections(app) : [],
    frame_error = testRecovery ? LegacyArm64ValueThisThunks.FrameError(app) : null,
    source_binary_sha256 = Hash(binary), source_metadata_sha256 = Hash(metadata),
    scope = testRecovery ? "Metadata/native exact FDE body selection, retained registered pointers, unique aliases and rejection guards only. Original boxed/unboxed codec equivalence is separately tested; recovered InternalDecrypt CIL and complete source still require validation."
        : "Observed actual Cpp2IL context pointer and native entry representation; no recovery-address correction, target aliases, behavior or source claim." };
File.WriteAllText(Guard(testRecovery ? $"reports/value-this-thunks-{args[1]}.json" : "reports/value-this-pointer-observations.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
