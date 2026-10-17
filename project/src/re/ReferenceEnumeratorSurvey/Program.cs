using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;
using LibCpp2IL;

if (args.Length != 1) throw new ArgumentException("Verified USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
ulong Number(string? value) => value is null ? 0 : Convert.ToUInt64(value.StartsWith("0x") ? value[2..] : value, 16);
var hasAnyGenericParameters = typeof(Cpp2IlApi).Assembly.GetType("Cpp2IL.Core.Utils.GenericInstantiation", throwOnError: true)!
    .GetMethod("HasAnyGenericParameters", BindingFlags.Public | BindingFlags.Static)!;
bool KnownReference(TypeAnalysisContext type) => !type.IsValueType && type is not PointerTypeAnalysisContext and not ByRefTypeAnalysisContext
    && (type is GenericInstanceTypeAnalysisContext || type.GenericParameters.Count == 0) && !(bool)hasAnyGenericParameters.Invoke(null, [type])!;
bool Layout(GenericInstanceTypeAnalysisContext returned, TypeAnalysisContext element, TypeAnalysisContext listDefinition)
{
    var type = returned.GenericType;
    if (!returned.IsValueType || type.Definition == null || type.Definition.PackingSize != 0
        || (type.DefaultAttributes & TypeAttributes.LayoutMask) != TypeAttributes.SequentialLayout) return false;
    var fields = type.Fields.Where(f => (f.DefaultAttributes & (FieldAttributes.Static | FieldAttributes.Literal)) == 0)
        .Select(f => new ConcreteGenericFieldAnalysisContext(f, returned)).ToArray();
    return fields.Length == 4 && fields.All(f => f.DefaultOffset == 0)
        && fields[0].DefaultName == "l" && fields[0].FieldType is GenericInstanceTypeAnalysisContext list
        && ReferenceEquals(list.GenericType, listDefinition) && list.GenericArguments.Count == 1
        && ReferenceEquals(list.GenericArguments[0], element) && KnownReference(list)
        && fields[1].DefaultName == "next" && fields[1].FieldType.DefaultFullName == "System.Int32"
        && fields[2].DefaultName == "ver" && fields[2].FieldType.DefaultFullName == "System.Int32"
        && fields[3].DefaultName == "current" && ReferenceEquals(fields[3].FieldType, element) && KnownReference(element);
}
const ulong target = 0x1585F60;
string binary = Guard("unpacked/effective/exefs/main"), metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (Hash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Original input differs");
string inventoryPath = Guard("analysis/nso/reference-enumerator-sret-survey-v35.json");
using var inventory = JsonDocument.Parse(File.ReadAllText(inventoryPath));
if (inventory.RootElement.GetProperty("native_source_sha256").GetString() != "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968")
    throw new IOException("Native inventory source differs");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var aliases = app.MethodsByAddress[target];
var baseMethod = aliases.Single(a => a is not ConcreteGenericMethodAnalysisContext);
if (aliases.Count != 279 || baseMethod.DefaultName != "GetEnumerator" || baseMethod.Parameters.Count != 0
    || baseMethod.DeclaringType?.DefaultFullName != "System.Collections.Generic.List`1") throw new InvalidDataException("Verified canonical family changed");
var privateRows = new List<object>();
var rejectionCounts = new Dictionary<string, int>();
var elementTypes = new HashSet<string>();
var byCallerAssembly = new Dictionary<string, (int Total, int Typed, int Adjacent, int BothDead, int EhFree, int ReceiverShape)>();
int total = 0, slots = 0, typed = 0, adjacent = 0, adjacentBothDead = 0, callerUnique = 0;
foreach (var call in inventory.RootElement.GetProperty("calls").EnumerateArray())
{
    if (Number(call.GetProperty("target_rva").GetString()) != target || call.GetProperty("branch_kind").GetString() != "bl") continue;
    total++;
    string reason = "no_straight_line_slot";
    string? element = null, methodName = null;
    ulong slot = call.TryGetProperty("methodinfo_slot_rva", out var slotElement) ? Number(slotElement.GetString()) : 0;
    ulong callerAddress = call.TryGetProperty("caller_rva", out var callerElement) ? Number(callerElement.GetString()) : 0;
    var callerAliases = app.MethodsByAddress.TryGetValue(callerAddress, out var named) ? named.ToArray() : [];
    bool eligible = false;
    int registeredMatches = 0;
    if (slot != 0)
    {
        slots++;
        var usage = app.LibCpp2IlContext.GetMethodGlobalByAddress(slot);
        if (usage?.Type != MetadataUsageType.MethodRef) reason = "slot_not_methodref";
        else if (app.ResolveContextForMethod(usage) is not ConcreteGenericMethodAnalysisContext concrete) reason = "not_concrete_generic_method";
        else
        {
            methodName = concrete.FullName;
            if (!ReferenceEquals(concrete.BaseMethodContext, baseMethod) || concrete.TypeGenericParameters.Count != 1 || concrete.MethodGenericParameters.Count != 0
                || concrete.UnderlyingPointer is not (0 or target)) reason = "different_canonical_method_family";
            else
            {
                var parameter = concrete.TypeGenericParameters[0]; element = parameter.DefaultFullName;
                registeredMatches = aliases.OfType<ConcreteGenericMethodAnalysisContext>().Count(a => ReferenceEquals(a.BaseMethodContext, baseMethod)
                    && a.UnderlyingPointer == target && a.TypeGenericParameters.SequenceEqual(concrete.TypeGenericParameters)
                    && a.MethodGenericParameters.SequenceEqual(concrete.MethodGenericParameters));
                if (!KnownReference(parameter)) reason = "nonreference_or_unresolved_element";
                else if (concrete.ReturnType is not GenericInstanceTypeAnalysisContext returned
                    || returned.GenericType.DefaultFullName != "System.Collections.Generic.List`1+Enumerator"
                    || !ReferenceEquals(returned.GenericType.DeclaringType, baseMethod.DeclaringType)
                    || returned.GenericArguments.Count != 1 || !ReferenceEquals(returned.GenericArguments[0], parameter)
                    || !Layout(returned, parameter, baseMethod.DeclaringType!)) reason = "outside_verified_reference_enumerator_layout";
                else if (registeredMatches != 1) reason = "registered_alias_not_unique";
                else { eligible = true; reason = "metadata_matches_verified_reference_family"; typed++; elementTypes.Add(element); }
            }
        }
    }
    bool hasAdjacent = call.TryGetProperty("adjacent_x8_sp_buffer", out var a8) && a8.GetBoolean();
    bool bothDead = call.TryGetProperty("x0_after_call", out var x0) && x0.GetProperty("passed").GetBoolean()
        && call.TryGetProperty("x8_after_call", out var x8) && x8.GetProperty("passed").GetBoolean();
    string? cie = call.TryGetProperty("caller_cie_augmentation", out var cieElement) ? cieElement.GetString() : null;
    string[] assemblies = callerAliases.Select(a => a.DeclaringType?.DeclaringAssembly.Name ?? "UNKNOWN_METADATA").Distinct().Order().ToArray();
    string assemblyGroup = assemblies.Length == 1 ? assemblies[0] : assemblies.Length == 0 ? "UNKNOWN_METADATA" : "MIXED_ALIAS_ASSEMBLIES";
    bool receiverShape = false;
    if (hasAdjacent && call.TryGetProperty("buffer_address_takes", out var takesElement))
    {
        var takes = takesElement.EnumerateArray().ToArray();
        receiverShape = takes.Length >= 2 && takes.Count(t => t.GetProperty("destination").GetString() == "x8") == 1
            && takes.All(t => t.GetProperty("relative_offset").GetInt32() == 0
                && (t.GetProperty("destination").GetString() == "x8"
                    || t.GetProperty("destination").GetString() == "x0" && t.GetProperty("known_consumer").GetString() is "MoveNext" or "Current" or "Dispose"));
    }
    var group = byCallerAssembly.GetValueOrDefault(assemblyGroup);
    byCallerAssembly[assemblyGroup] = (group.Total + 1, group.Typed + (eligible ? 1 : 0), group.Adjacent + (eligible && hasAdjacent ? 1 : 0),
        group.BothDead + (eligible && hasAdjacent && bothDead ? 1 : 0), group.EhFree + (eligible && hasAdjacent && cie == "zR" ? 1 : 0),
        group.ReceiverShape + (eligible && hasAdjacent && cie == "zR" && receiverShape ? 1 : 0));
    if (eligible && hasAdjacent) adjacent++;
    if (eligible && hasAdjacent && bothDead) adjacentBothDead++;
    if (eligible && callerAliases.Length == 1) callerUnique++;
    rejectionCounts[reason] = rejectionCounts.GetValueOrDefault(reason) + 1;
    privateRows.Add(new { call_rva = call.GetProperty("call_rva").GetString(), caller_rva = $"0x{callerAddress:X}",
        metadata_slot_rva = slot == 0 ? null : $"0x{slot:X}", eligible_verified_metadata_family = eligible,
        reason, method = methodName, element_type = element, registered_alias_matches = registeredMatches,
        adjacent_x8_sp_buffer = hasAdjacent, both_registers_dead_normal_cfg = bothDead,
        caller_cie_augmentation = cie, receiver_address_takes_only_shape = receiverShape,
        caller_assembly_group = assemblyGroup, caller_assembly_names = assemblies,
        full_24byte_storage_ownership_proved = false,
        caller_aliases = callerAliases.Select(a => new { method = a.FullName, assembly = a.DeclaringType?.DeclaringAssembly.Name, context = a.GetType().Name }).ToArray() });
}
string detailPath = Guard("analysis/nso/reference-enumerator-sret-metadata-v35.json");
File.WriteAllText(detailPath, JsonSerializer.Serialize(privateRows, new JsonSerializerOptions { WriteIndented = true }) + "\n");
var result = new { status = "READ_ONLY_REFERENCE_ENUMERATOR_METADATA_CANDIDATES_NOT_PRODUCTION_ACCEPTANCE", total_native_getenumerator_calls = total,
    native_slot_candidates = slots, typed_registered_reference_family_calls = typed, typed_adjacent_x8_sp_calls = adjacent,
    typed_adjacent_both_dead_normal_cfg_calls = adjacentBothDead, typed_calls_with_unique_caller_alias = callerUnique,
    distinct_closed_reference_elements = elementTypes.Order().ToArray(), classification_counts = rejectionCounts,
    by_caller_assembly = byCallerAssembly.ToDictionary(pair => pair.Key, pair => new { native_calls = pair.Value.Total, typed_family_calls = pair.Value.Typed,
        typed_adjacent_x8_sp_calls = pair.Value.Adjacent, typed_adjacent_both_dead_calls = pair.Value.BothDead,
        typed_adjacent_eh_free_calls = pair.Value.EhFree, typed_adjacent_eh_free_receiver_address_shape_calls = pair.Value.ReceiverShape }),
    canonical_family_registered_aliases = aliases.Count, source_binary_sha256 = Hash(binary), source_metadata_sha256 = Hash(metadata),
    native_inventory_sha256 = Hash(inventoryPath), tool_core_sha256 = Hash(typeof(Cpp2IlApi).Assembly.Location),
    probe_source_sha256 = Hash(Guard("src/re/ReferenceEnumeratorSurvey/Program.cs")), details = Path.GetRelativePath(root, detailPath), details_sha256 = Hash(detailPath),
    core_edited = false, production_acceptances = 0, caller_cil_or_game_executed = false, generic_struct_size_classifier_used = false,
    scope = "Actual original metadata resolves native straight-line X1 slot candidates to the existing verified 24-byte List<referenceT>.Enumerator family, requiring unique identical registered aliases and exact substituted declaration identities. Counts remain static candidates. Caller storage ownership/escape/overlap, full CFG/EH, current pre-SSA integration, complete result-use/lifetime and actual CIL/runtime validation remain separate requirements. Frozen copied Core is used for metadata reading only; no shared Core build or production adapter change occurs." };
File.WriteAllText(Guard("reports/reference-enumerator-sret-metadata-v35.json"), JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(result));
