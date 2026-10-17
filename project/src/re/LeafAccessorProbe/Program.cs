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
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var binary = Guard("unpacked/effective/exefs/main");
var metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (Hash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Input differs");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var types = app.Assemblies.SelectMany(assembly => assembly.Types).ToArray();
TypeAnalysisContext Type(string name) => types.Single(type => type.FullName == name);
var mapping = Type("InControl.InputControlMapping");
var handle = mapping.Fields.Single(field => field.Name == "handle");
var setter = mapping.Properties.Single(property => property.Name == "Handle").Setter!;
var getter = mapping.Properties.Single(property => property.Name == "Handle").Getter!;
var node = Type("Nekki.SF2.Core.Fights.Model.Components.Nodes.ModelNode");
var current = node.Fields.Single(field => field.Name == "_Current");
var currentGetter = node.Properties.Single(property => property.Name == "CurrentPosition").Getter!;
var perk = Type("Nekki.SF2.Core.Utils.Perks.PerkAction");
var modifier = perk.Fields.Single(field => field.Name == "<Modificator>k__BackingField");
var modifierGetter = perk.Properties.Single(property => property.Name == "Modificator").Getter!;
var modifierSetter = perk.Properties.Single(property => property.Name == "Modificator").Setter!;
var checks = new List<object>();
void Check(string name, bool actual, bool expected)
{
    if (actual != expected) throw new Exception($"{name}: {actual} != {expected}");
    checks.Add(new { name, expected, status = "PASS" });
}
Check("actual reference field setter native proof", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), true);
Check("effectful fallback getter rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, getter, false), false);
Check("cache returns actual original setter", ReferenceEquals(LegacyArm64LeafAccessors.Find(handle, true), setter), true);
Check("cache rejects effectful original getter", LegacyArm64LeafAccessors.Find(handle, false) == null, true);
Check("actual reference getter native proof", LegacyArm64LeafAccessors.IsExactLeaf(current, currentGetter, false), true);
Check("actual byte boolean getter native proof", LegacyArm64LeafAccessors.IsExactLeaf(modifier, modifierGetter, false), true);
Check("protected canonicalizing setter rejected", LegacyArm64LeafAccessors.IsExactLeaf(modifier, modifierSetter, true), false);
Check("foreign owner rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, currentGetter, false), false);
var oldFieldOffset = handle.OverrideOffset;
try
{
    handle.OverrideOffset = handle.Offset + 8;
    Check("wrong aligned field offset rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
    handle.OverrideOffset = 0;
    Check("object header rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
    handle.OverrideOffset = 17;
    Check("misaligned field rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
}
finally { handle.OverrideOffset = oldFieldOffset; }
var oldFieldAttributes = handle.OverrideAttributes;
try
{
    handle.Attributes |= FieldAttributes.InitOnly;
    Check("readonly field write rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
    handle.Attributes = (oldFieldAttributes ?? handle.DefaultAttributes) | FieldAttributes.Static;
    Check("static field rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
}
finally { handle.OverrideAttributes = oldFieldAttributes; }
var oldMethodAttributes = setter.OverrideAttributes;
try
{
    setter.Attributes |= MethodAttributes.Virtual;
    Check("virtual accessor rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
    setter.Attributes = ((oldMethodAttributes ?? setter.DefaultAttributes) & ~MethodAttributes.MemberAccessMask) | MethodAttributes.Private;
    Check("private accessor rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
    setter.Attributes = (oldMethodAttributes ?? setter.DefaultAttributes) | MethodAttributes.Static;
    Check("static accessor rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
}
finally { setter.OverrideAttributes = oldMethodAttributes; }
var oldFieldType = handle.OverrideFieldType;
try
{
    handle.FieldType = app.SystemTypes.SystemInt32Type;
    Check("mismatched field signature rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
    handle.FieldType = Type("UnityEngine.Vector3");
    Check("aggregate field rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
}
finally { handle.OverrideFieldType = oldFieldType; }
var oldOwnerAttributes = mapping.OverrideAttributes;
try
{
    mapping.Attributes = (mapping.Attributes & ~TypeAttributes.LayoutMask) | TypeAttributes.ExplicitLayout;
    Check("explicit owner layout rejected", LegacyArm64LeafAccessors.IsExactLeaf(handle, setter, true), false);
}
finally { mapping.OverrideAttributes = oldOwnerAttributes; }
var rows = new List<object>();
int getters = 0, setters = 0, fieldsExamined = 0;
foreach (var type in types.Where(type => type.DeclaringAssembly.Name is "Assembly-CSharp" or "Assembly-CSharp-firstpass"))
foreach (var field in type.Fields)
{
    fieldsExamined++;
    var get = LegacyArm64LeafAccessors.Find(field, false);
    var set = LegacyArm64LeafAccessors.Find(field, true);
    if (get != null) getters++;
    if (set != null) setters++;
    if (ReferenceEquals(field, handle) || ReferenceEquals(field, current) || ReferenceEquals(field, modifier))
        rows.Add(new { owner = type.FullName, field = field.Name, field_visibility = field.Visibility.ToString(),
            field_offset = $"0x{field.Offset:X}", type = field.FieldType.FullName,
            getter = get?.FullName, getter_rva = get == null ? null : $"0x{get.Rva:X}",
            setter = set?.FullName, setter_rva = set == null ? null : $"0x{set.Rva:X}" });
}
var report = new { status = "PASS_NATIVE_LEAF_ACCESSOR_SELECTION_ONLY", checks = checks.Count, fixtures = checks,
    fields_examined = fieldsExamined, selected_getters = getters, selected_setters = setters, witnesses = rows,
    game_metadata_modified = false, original_native_executed = false, recovered_cil_executed = false,
    whole_game_source_ready = false,
    scope = "Existing nonvirtual public instance property accessors are selected only after exact original native scalar/ref field-access plus RET proof. Private field flags remain unchanged. Original side-effectful fallback getters, aggregate/value receivers, generic and explicit layouts, readonly stores, static fields and nonpublic or virtual accessors remain rejected. This report validates selection and negative guards; caller emission, compiled behavior and whole-source compilation require separate tests." };
File.WriteAllText(Guard("reports/private-access-leaf-selection-v28.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine($"PASS: {checks.Count} selection checks, {getters} getters/{setters} setters over {fieldsExamined} fields");
