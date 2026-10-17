using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Cpp2IL.Core.Utils;

if (args.Length != 2 || !Regex.IsMatch(args[1], "^[a-z0-9-]+$")) throw new ArgumentException("Verified USB root and immutable recovery run required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar), run = args[1];
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? dir = new(Path.GetDirectoryName(path)!); dir != null; dir = dir.Parent)
        if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
string FileHash(string path) => Hash(File.ReadAllBytes(path));
const ulong helper = 0xB2E720;
byte[] raw = File.ReadAllBytes(Guard("analysis/nso/main-uncompressed.nso"));
if (Hash(raw) != "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968"
    || BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(0x10, 4)) != 0x100
    || BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(0x14, 4)) != 0) throw new IOException("Original native image or text layout differs");
ulong textEnd = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(0x18, 4));
using var ciesDoc = JsonDocument.Parse(File.ReadAllText(Guard("analysis/nso/unwind-inventory-v1/cies.json")));
var cies = ciesDoc.RootElement.EnumerateArray().ToDictionary(e => e.GetProperty("rva").GetUInt64(), e => e.Clone());
var groups = new Dictionary<string, Group>(StringComparer.Ordinal);
var starts = new HashSet<ulong>(); int frameCount = 0, sites = 0;
string detailPath = Guard("analysis/reconstruction/class-guard-cfg-v35/native-candidate-frame-inventory.jsonl");
Directory.CreateDirectory(Path.GetDirectoryName(detailPath)!);
using (var detail = new StreamWriter(detailPath))
foreach (string line in File.ReadLines(Guard("analysis/nso/unwind-inventory-v1/frames.jsonl")))
{
    using var doc = JsonDocument.Parse(line); var frame = doc.RootElement;
    ulong start = frame.GetProperty("rva").GetUInt64(), end = frame.GetProperty("end_rva").GetUInt64();
    if (!starts.Add(start) || start % 4 != 0 || end <= start || (end - start) % 4 != 0 || end > textEnd || end - start > 65536)
        throw new IOException("Original exact frame inventory uniqueness, alignment or scan bound differs");
    var cie = cies[frame.GetProperty("cie_rva").GetUInt64()];
    string augmentation = cie.GetProperty("augmentation").GetString()!;
    bool eligiblePlain = augmentation == "zR" && cie.GetProperty("lsda_encoding").GetInt32() == 255
        && cie.GetProperty("personality").ValueKind == JsonValueKind.Null;
    if (!groups.TryGetValue(augmentation, out var group)) groups[augmentation] = group = new Group { plain_eligibility = eligiblePlain };
    if (group.plain_eligibility != eligiblePlain) throw new IOException("Conflicting CIE augmentation semantics");
    group.exact_frames++; frameCount++;
    int size = checked((int)(end - start));
    var body = raw.AsSpan(checked(0x100 + (int)start), size);
    var candidates = LegacyArm64AllocationPattern.ClassInitSites(body, start).Where(s => s.Target == helper).ToArray();
    if (candidates.Length == 0) continue;
    group.candidate_callers++; group.candidate_sites += candidates.Length; sites += candidates.Length;
    detail.WriteLine(JsonSerializer.Serialize(new { rva = $"0x{start:X}", end_rva = $"0x{end:X}", bytes = size,
        body_sha256 = Hash(body.ToArray()), cie_augmentation = augmentation, conservative_plain_frame_eligibility = eligiblePlain,
        candidates = candidates.Select(s => new { start = $"0x{s.Start:X}", skip = $"0x{s.Skip:X}", target = $"0x{s.Target:X}" }) }));
}
var assemblies = new List<object>(); var parseErrors = new List<object>(); var exceptionalExamples = new List<object>();
var specificUnload = new List<object>(); var specificGetSafe = new List<object>();
int methods = 0, methodsWithHandlers = 0, regionTotal = 0;
foreach (string path in Directory.GetFiles(Guard($"analysis/il2cpp/cpp2il-recovery-{run}"), "*.dll").Order())
{
    using var stream = File.OpenRead(path); using var pe = new PEReader(stream);
    var reader = pe.GetMetadataReader(); int assemblyBodies = 0, assemblyWithHandlers = 0, assemblyRegions = 0;
    foreach (var typeHandle in reader.TypeDefinitions)
    {
        var type = reader.GetTypeDefinition(typeHandle);
        string typeName = reader.GetString(type.Name), ns = reader.GetString(type.Namespace);
        foreach (var methodHandle in type.GetMethods())
        {
            var method = reader.GetMethodDefinition(methodHandle);
            if (method.RelativeVirtualAddress == 0) continue;
            string methodName = reader.GetString(method.Name);
            try
            {
                var body = pe.GetMethodBody(method.RelativeVirtualAddress);
                int count = body.ExceptionRegions.Length;
                assemblyBodies++; methods++; assemblyRegions += count; regionTotal += count;
                if (count > 0)
                {
                    assemblyWithHandlers++; methodsWithHandlers++;
                    if (exceptionalExamples.Count < 16) exceptionalExamples.Add(new { assembly = Path.GetFileName(path), type = ns + "." + typeName, method = methodName, exception_regions = count });
                }
                if (ns.Length == 0 && typeName == "BundlesUtil" && methodName is "UnloadDependencies" or "GetAssetBundleSafe")
                {
                    var observation = new { assembly = Path.GetFileName(path), type = typeName, method = methodName,
                        exception_regions = count, body_il_sha256 = Hash(body.GetILBytes()!),
                        handlers = body.ExceptionRegions.Select(r => new { kind = r.Kind.ToString(), r.TryOffset, r.TryLength, r.HandlerOffset, r.HandlerLength }) };
                    if (methodName == "UnloadDependencies") specificUnload.Add(observation); else specificGetSafe.Add(observation);
                }
            }
            catch (Exception error) { parseErrors.Add(new { assembly = Path.GetFileName(path), type = typeName, method = methodName, error = error.ToString() }); }
        }
    }
    assemblies.Add(new { file = Path.GetFileName(path), sha256 = FileHash(path), bodies = assemblyBodies, methods_with_exception_regions = assemblyWithHandlers, exception_regions = assemblyRegions });
}
var report = new { status = parseErrors.Count == 0 ? "READ_ONLY_NATIVE_CIE_CANDIDATES_AND_ACTUAL_CIL_EH_INVENTORY" : "CIL_EH_INVENTORY_PARSE_LIMITATIONS",
    recovery_run = run, original_native_sha256 = Hash(raw), exact_frames = frameCount, candidate_sites = sites,
    candidate_scope = "Current sequential native window matcher sites with known B2E720 target; distinct exact FDE callers grouped by original CIE augmentation. These are static candidates, not accepted CFG normalizations or recovered game methods.",
    groups, native_candidate_details = Path.GetRelativePath(root, detailPath), native_candidate_details_sha256 = FileHash(detailPath),
    cil_assembly_count = assemblies.Count, cil_method_bodies = methods, cil_methods_with_exception_regions = methodsWithHandlers, cil_exception_regions = regionTotal,
    cil_parse_errors = parseErrors, exceptional_examples = exceptionalExamples, specific_unload = specificUnload, specific_get_safe = specificGetSafe, assemblies,
    matcher_source_sha256 = FileHash(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64AllocationPattern.cs")),
    probe_source_sha256 = FileHash(Guard("src/re/ClassGuardEhInventoryProbe/Program.cs")),
    frames_sha256 = FileHash(Guard("analysis/nso/unwind-inventory-v1/frames.jsonl")), cies_sha256 = FileHash(Guard("analysis/nso/unwind-inventory-v1/cies.json")),
    core_referenced_or_built = false, original_code_modified = false, assemblies_executed_or_modified = false,
    scope = "Read-only static exact-frame/CIE candidate grouping and PE exception-region metadata inventory. The plain zR/no-LSDA/no-personality condition is only a conservative future eligibility gate; native proof, typed origin, effect ordering and production runtime validation remain required. Native frames and emitted managed method bodies have different sharing/ownership denominators; no aggregate EH-recovery percentage is asserted. Existing original Unload LSDA landing entries must be restored before whole-method equivalence can be claimed; an ordinary-branch CFG cannot prove them unreachable. No whole-decompile or portable-game claim." };
File.WriteAllText(Guard("reports/class-guard-eh-eligibility-inventory-v35.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true, IncludeFields = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { report.status, frameCount, sites, groups, assemblies = assemblies.Count, methods, methodsWithHandlers, regionTotal, parse_errors = parseErrors.Count }, new JsonSerializerOptions { IncludeFields = true }));

sealed class Group
{
    public int exact_frames;
    public int candidate_callers;
    public int candidate_sites;
    public bool plain_eligibility;
}
