using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;

if (args.Length != 1) throw new ArgumentException("Verified USB root required");
var root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB root");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(string file) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))).ToLowerInvariant();
var binary = Guard("unpacked/effective/exefs/main");
var metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (Hash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Original input hash differs");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var types = app.Assemblies.SelectMany(assembly => assembly.Types).ToArray();
var currency = types.Single(type => type.FullName == "Nekki.SF2.Core.Utils.CurrencyStruct");
var setter = currency.Methods.Single(method => method.Name == "set_Count");
var getter = currency.Methods.Single(method => method.Name == "get_Count");
var value = setter.Parameters.Single().ParameterType;
var field = currency.Fields.Single(candidate => candidate.Offset == 0x18);
var tests = new List<object>();
void Check(string name, bool condition)
{
    if (!condition) throw new Exception("Aggregate leaf check failed: " + name);
    tests.Add(new { name, status = "PASS" });
}
byte[] Body(MethodAnalysisContext method)
{
    var raw = (int)app.Binary.MapVirtualAddressToRaw(method.UnderlyingPointer);
    var content = app.Binary.GetRawBinaryContent();
    var first = BinaryPrimitives.ReadUInt32LittleEndian(content.Slice(raw, 4));
    int length = (first & 0xFFC07FFF) == 0xA9000801 ? 8 : (first & 0xFFC07FFF) == 0xA9400408 ? 12
        : throw new Exception("Fixture lacks exact pair-copy entry");
    if (app.GetAddressOfNextFunctionStart(method.UnderlyingPointer) < method.UnderlyingPointer + (ulong)length) throw new Exception("Fixture crosses native function boundary");
    return content.Slice(raw, length).ToArray();
}
var store = Body(setter); var load = Body(getter);
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", null);
Check("disabled by default", LegacyArm64AggregateLeaves.Describe(setter, store) == null);
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
Console.WriteLine(JsonSerializer.Serialize(new { observation = "actual aggregate leaf metadata", owner = currency.FullName,
    owner_attributes = currency.Attributes.ToString(), owner_size = currency.Definition?.RawSizes.instance_size,
    value_attributes = value.Attributes.ToString(), value_size = TypeSizes.UnboxedSize(value, 8), value_packing = value.Definition?.PackingSize,
    body_bytes = store.Length, instruction = $"0x{BinaryPrimitives.ReadUInt32LittleEndian(store):X8}",
    field_offset = field.Offset, same_type = ReferenceEquals(field.FieldType, value),
    direct_match = LegacyArm64AggregateLeaves.Describe(setter, store) != null,
    fields = value.Fields.Select(candidate => new { candidate.Name, candidate.Offset, type = candidate.FieldType.FullName, candidate.IsStatic }).ToArray() }));
Check("actual setter complete decoded body", LegacyArm64AggregateLeaves.Describe(setter) is { IsSetter: true } actualStore && ReferenceEquals(actualStore.Field, field));
Check("actual getter complete decoded body", LegacyArm64AggregateLeaves.Describe(getter) is { IsSetter: false } actualLoad && ReferenceEquals(actualLoad.Field, field));
Check("actual integer shape", TypeSizes.UnboxedSize(value, 8) == 16
    && value.Fields.Where(candidate => !candidate.IsStatic).Select(candidate => candidate.Offset).SequenceEqual(new[] { 0, 4, 8, 12 }));
void MutatedBody(string name, MethodAnalysisContext method, byte[] original, int offset, uint word)
{
    var changed = original.ToArray(); BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(offset), word);
    Check(name, LegacyArm64AggregateLeaves.Describe(method, changed) == null);
}
MutatedBody("different store receiver rejected", setter, store, 0, BinaryPrimitives.ReadUInt32LittleEndian(store) | (1u << 5));
MutatedBody("different second argument word rejected", setter, store, 0, BinaryPrimitives.ReadUInt32LittleEndian(store) ^ (1u << 10));
MutatedBody("store writeback rejected", setter, store, 0, BinaryPrimitives.ReadUInt32LittleEndian(store) ^ (1u << 23));
MutatedBody("wrong store offset rejected", setter, store, 0, (BinaryPrimitives.ReadUInt32LittleEndian(store) & 0xFFC07FFF) | (1u << 15));
MutatedBody("missing setter return rejected", setter, store, 4, 0xD503201F);
MutatedBody("different getter result word rejected", getter, load, 4, 0xAA0903E0);
MutatedBody("wrong first getter destination register rejected", getter, load, 0, BinaryPrimitives.ReadUInt32LittleEndian(load) ^ 1u);
MutatedBody("effect in getter rejected", getter, load, 4, 0x94000000);
Check("appended observable code rejected", LegacyArm64AggregateLeaves.Describe(setter, store.Concat(new byte[] { 0, 0, 0, 0x94 }).ToArray()) == null);
Check("truncated body rejected", LegacyArm64AggregateLeaves.Describe(getter, load.AsSpan(0, 8)) == null);
var oldOffset = field.OverrideOffset;
try { field.OverrideOffset = 0x20; Check("field metadata offset mismatch rejected", LegacyArm64AggregateLeaves.Describe(setter, store) == null); }
finally { field.OverrideOffset = oldOffset; }
var oldAttributes = field.OverrideAttributes;
try { field.OverrideAttributes = field.Attributes | FieldAttributes.InitOnly; Check("readonly setter rejected", LegacyArm64AggregateLeaves.Describe(setter, store) == null); }
finally { field.OverrideAttributes = oldAttributes; }
var valueField = value.Fields.Single(candidate => candidate.Name == "hiddenValue");
var oldValueOffset = valueField.OverrideOffset;
try { valueField.OverrideOffset = 0; Check("overlapping value fields rejected", LegacyArm64AggregateLeaves.Describe(setter, store) == null); }
finally { valueField.OverrideOffset = oldValueOffset; }
var oldFieldType = valueField.OverrideFieldType;
try { valueField.OverrideFieldType = app.SystemTypes.SystemSingleType; Check("floating or unknown field shape rejected", LegacyArm64AggregateLeaves.Describe(setter, store) == null); }
finally { valueField.OverrideFieldType = oldFieldType; }
var wrongSignature = new InjectedMethodAnalysisContext(currency, "WrongSetter", app.SystemTypes.SystemVoidType, MethodAttributes.Public, [app.SystemTypes.SystemInt32Type]);
Check("different managed signature rejected", LegacyArm64AggregateLeaves.Describe(wrongSignature, store) == null);
var staticSignature = new InjectedMethodAnalysisContext(currency, "StaticSetter", app.SystemTypes.SystemVoidType, MethodAttributes.Public | MethodAttributes.Static, [value]);
Check("static dummy argument shape rejected", LegacyArm64AggregateLeaves.Describe(staticSignature, store) == null);
var structOwner = new InjectedMethodAnalysisContext(value, "ValueOwnerSetter", app.SystemTypes.SystemVoidType, MethodAttributes.Public, [value]);
Check("unboxed value owner rejected", LegacyArm64AggregateLeaves.Describe(structOwner, store) == null);
var spilledSignature = new InjectedMethodAnalysisContext(currency, "SpilledSetter", app.SystemTypes.SystemVoidType, MethodAttributes.Public,
    Enumerable.Repeat(app.SystemTypes.SystemInt32Type, 7).Append(value).ToArray());
Check("spilled or preceding-argument signature rejected", LegacyArm64AggregateLeaves.Describe(spilledSignature, store) == null);
var oldAggregateType = field.OverrideFieldType;
try
{
    field.OverrideFieldType = app.SystemTypes.SystemInt64Type;
    var undersized = new InjectedMethodAnalysisContext(currency, "UndersizedSetter", app.SystemTypes.SystemVoidType, MethodAttributes.Public, [app.SystemTypes.SystemInt64Type]);
    Check("undersized matched field and argument rejected", LegacyArm64AggregateLeaves.Describe(undersized, store) == null);
}
finally { field.OverrideFieldType = oldAggregateType; }
var hits = new List<object>();
foreach (var method in types.Where(type => !type.IsValueType && type.DeclaringAssembly.Name is "Assembly-CSharp" or "Assembly-CSharp-firstpass").SelectMany(type => type.Methods))
{
    if (method.UnderlyingPointer == 0 || method.IsStatic
        || !((method.Parameters.Count == 1 && method.IsVoid && ReferenceEquals(method.Parameters[0].ParameterType, value))
            || (method.Parameters.Count == 0 && ReferenceEquals(method.ReturnType, value)))) continue;
    if (LegacyArm64AggregateLeaves.Describe(method) is not { } match) continue;
    var bytes = Body(method);
    hits.Add(new { rva = $"0x{method.UnderlyingPointer:X}", method = method.FullName, field = match.Field.Name, field_offset = $"0x{match.Field.Offset:X}", setter = match.IsSetter,
        body_bytes = bytes.Length, native_text_sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() });
}
Check("actual CurrencyStruct getter and setter inventoried", hits.Count >= 2);
var report = new { status = "PASS_SCOPED_16BYTE_NATIVE_FIELD_COPY_RECOGNITION", checks = tests.Count, tests,
    matched_obscured_int_leaves = hits.Count, leaves = hits,
    value_layout = new { type = value.FullName, size = TypeSizes.UnboxedSize(value, 8), attributes = value.Attributes.ToString(),
        fields = value.Fields.Where(candidate => !candidate.IsStatic).Select(candidate => new { name = candidate.Name, type = candidate.FieldType.FullName, offset = candidate.Offset }).ToArray() },
    helper_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64AggregateLeaves.cs")),
    scope = "Native bytes and metadata recognition only. No recovered CIL execution, general integer aggregate call/entry/return ABI, padding-byte identity, currency codec, or complete game-source claim. Direct managed field copies must be independently emitted and executed against original native fixtures." };
File.WriteAllText(Guard("reports/integer-aggregate-leaf-recognition.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine($"PASS: {tests.Count} metadata/native recognition checks; {hits.Count} exact ObscuredInt leaf matches");
