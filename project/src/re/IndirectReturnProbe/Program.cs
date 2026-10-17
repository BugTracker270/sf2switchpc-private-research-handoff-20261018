using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.InstructionSets;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;
using Disarm;

if (args.Length != 1) throw new ArgumentException("Verified USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point");
    return path;
}
string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
var tests = new List<object>();
int failures = 0;
void Check(string name, bool passed, object? details = null)
{ tests.Add(new { name, passed, details }); if (!passed) failures++; }
string binary = Guard("unpacked/effective/exefs/main"), metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (Hash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Original input differs");
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var owner = app.Assemblies.SelectMany(a => a.Types).Single(t => t.FullName == "Nekki.SF2.Core.Fights.Fight");
var method = owner.Methods.Single(m => m.Name == "SetStage" && m.UnderlyingPointer == 0xC9F3F0);
method.EnsureRawBytes();
var production = app.InstructionSet.GetIsilFromMethod(method);
var productionCall = production.Single(i => i.OpCode == OpCode.Call && i.Operands[0] is Immediate t && t.UnsignedValue == 0x1585F60);
var productionNative = NewArm64Utils.GetArm64MethodBodyAtVirtualAddress(app, method.UnderlyingPointer);
Check("actual production converter binds reviewed return buffer", productionCall.Destination is StackOffset { Offset: 8 }, new
{
    destination = productionCall.Destination?.ToString(), production_instructions = production.Count,
    source_byte_length = method.RawBytes.Length, native_instruction_count = productionNative.Count,
    last_native_rva = $"0x{productionNative[^1].Address:X}", last_native_operation = productionNative[^1].Mnemonic.ToString(),
    last_isil_operations = production.TakeLast(4).Select(i => new { i.Index, op = i.OpCode.ToString() }).ToArray()
});

// Re-run only the original per-native-instruction converter through its private API to
// obtain independent pre-adapter ISIL and native-address correspondence. No helper/body
// bindings, metadata substitutions or output assembly modifications occur.
var converter = new NewArmV8InstructionSet();
var convert = typeof(NewArmV8InstructionSet).GetMethod("ConvertInstructionStatement", BindingFlags.Instance | BindingFlags.NonPublic)!;
var adrp = typeof(NewArmV8InstructionSet).GetField("adrpOffsets", BindingFlags.Static | BindingFlags.NonPublic)!;
object? savedAdrp = adrp.GetValue(null);
var raw = new List<Instruction>(); var addresses = new List<ulong>();
try
{
    adrp.SetValue(null, new Dictionary<string, ulong>());
    foreach (var insn in Disassembler.Disassemble(method.RawBytes.AsSpan(), method.UnderlyingPointer, new Disassembler.Options(true, true, false)))
        convert.Invoke(converter, new object[] { insn, raw, addresses, method });
}
finally { adrp.SetValue(null, savedAdrp); }
foreach (var row in raw)
{
    if (row.OpCode is not (OpCode.Jump or OpCode.ConditionalJump)) continue;
    ulong target = ((Immediate)row.Operands[0]).UnsignedValue;
    int index = addresses.FindIndex(a => a == target);
    if (index < 0) throw new InvalidOperationException("Original native branch lies outside converted body");
    row.SetOperand(0, raw[index]);
}
int callPosition = addresses.FindIndex(a => a == 0xC9F4DC);
Check("independent raw converter retains original X0 return destination", raw[callPosition].Destination is Register { Name: "X0" });

List<Instruction> Clone()
{
    var map = raw.ToDictionary(i => i, i => new Instruction(i.Index, i.OpCode, i.Operands.ToList()) { ImplicitDefinition = i.ImplicitDefinition });
    foreach (var row in map.Values)
        for (int i = 0; i < row.Operands.Count; i++)
            if (row.Operands[i] is Instruction target) row.SetOperand(i, map[target]);
    return raw.Select(i => map[i]).ToList();
}
(Instruction Row, int Index, OpCode Op, IOperand[] Operands, Register? Implicit)[] Snapshot(List<Instruction> list) =>
    list.Select(i => (i, i.Index, i.OpCode, i.Operands.ToArray(), i.ImplicitDefinition)).ToArray();
bool Unchanged((Instruction Row, int Index, OpCode Op, IOperand[] Operands, Register? Implicit)[] before, List<Instruction> after, bool allowedDestination)
{
    if (before.Length != after.Count) return false;
    for (int i = 0; i < after.Count; i++)
    {
        var old = before[i]; var row = after[i];
        if (!ReferenceEquals(old.Row, row) || old.Index != row.Index || old.Op != row.OpCode
            || old.Implicit != row.ImplicitDefinition || old.Operands.Length != row.Operands.Count) return false;
        for (int j = 0; j < row.Operands.Count; j++)
        {
            if (allowedDestination && i == callPosition && j == 1) continue;
            if (!Equals(old.Operands[j], row.Operands[j])) return false;
        }
    }
    return true;
}
var valid = Clone(); var validBefore = Snapshot(valid);
int accepted = LegacyArm64IndirectReturns.Apply(method, valid, addresses);
Check("canonical full native-derived ISIL accepted with sole destination mutation", accepted == 1
    && valid[callPosition].Destination is StackOffset { Offset: 8 } && Unchanged(validBefore, valid, true));
var repeatedBefore = Snapshot(valid);
Check("already adapted call rejected atomically", LegacyArm64IndirectReturns.Apply(method, valid, addresses) == 0 && Unchanged(repeatedBefore, valid, false));

void Reject(string name, Action<List<Instruction>, List<ulong>> mutate, bool disabled = false, bool wrongCaller = false)
{
    var list = Clone(); var sites = addresses.ToList(); mutate(list, sites);
    var before = Snapshot(list);
    if (disabled) Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", null);
    int count;
    try { count = LegacyArm64IndirectReturns.Apply(wrongCaller ? owner.Methods.First(m => m.UnderlyingPointer != 0xC9F3F0) : method, list, sites); }
    finally { Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1"); }
    Check(name, count == 0 && Unchanged(before, list, false), new { count, atomic_rejection = Unchanged(before, list, false) });
}
Reject("disabled opt-in", (_, _) => { }, disabled: true);
Reject("unreviewed caller", (_, _) => { }, wrongCaller: true);
Reject("incomplete native address correspondence", (_, sites) => sites.RemoveAt(sites.Count - 1));
Reject("duplicate call native address", (_, sites) => sites[0] = 0xC9F4DC);
Reject("wrong direct target", (list, _) => list[callPosition].SetOperand(0, new Immediate(0x1585F64)));
Reject("wrong hidden register", (list, _) => list[callPosition - 1].SetOperand(0, new Register(null, "X7")));
Reject("overlapping hidden buffer", (list, _) => list[callPosition - 1].SetOperand(1, new AddressOf(new StackOffset(16))));
Reject("unreviewed escaping address register", (list, sites) => list[sites.FindIndex(a => a == 0xC9F50C)].SetOperand(0, new Register(null, "X2")));
Reject("unreviewed overlapping storage write", (list, _) => list[11].SetOperands(new StackOffset(12), new Immediate(0)));
Reject("native X0 return pointer remains live", (list, _) => list[callPosition + 1].SetOperands(new Register(null, "X22"), new Register(null, "X0")));
Reject("native X8 address remains live after clobber", (list, _) => list[callPosition + 1].SetOperands(new Register(null, "X22"), new Register(null, "X8")));
Reject("branch target outside source instruction list", (list, _) => list.First(i => i.OpCode == OpCode.Jump).SetOperand(0, new Instruction(12345, OpCode.Return)));
Reject("already normalized block target", (list, _) => list.First(i => i.OpCode == OpCode.Jump).SetOperand(0, new Block()));
Reject("nonsequential instruction identities", (list, _) => list[11].Index = 12345);
Reject("malformed consumer operands", (list, sites) => list[sites.FindIndex(a => a == 0xC9F50C)].SetOperands());
Reject("unreviewed cleanup receiver", (list, sites) => list[sites.FindIndex(a => a == 0xC9F5DC)].SetOperand(0, new Register(null, "X2")));
Reject("wrong cleanup consumer target", (list, sites) => list[sites.FindIndex(a => a == 0xC9F5E0)].SetOperand(0, new Immediate(0x11DD3B4)));
Reject("incomplete aggregate zero coverage", (list, sites) => list[sites.FindIndex(a => a == 0xC9F440) + 1].SetOperand(0, new StackOffset(32)));
Reject("nonzero initializer payload", (list, sites) => list[sites.FindIndex(a => a == 0xC9F444)].SetOperand(1, new Immediate(1)));

if (failures != 0)
{
    var helper = typeof(LegacyArm64IndirectReturns);
    object? Invoke(string name, params object[] values) => helper.GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, values);
    var alias = app.MethodsByAddress[0x1585F60].OrderByDescending(m => m.Parameters.Count + (m.IsStatic ? 0 : 1)).First();
    var concrete = (ConcreteGenericMethodAnalysisContext)app.ResolveContextForMethod(app.LibCpp2IlContext.GetMethodGlobalByAddress(0x3B4CE60))!;
    var returned = (GenericInstanceTypeAnalysisContext)concrete.ReturnType;
    var rejectedLayouts = app.MethodsByAddress[0x1585F60].OfType<ConcreteGenericMethodAnalysisContext>()
        .Where(a => !(bool)Invoke("ReferenceEnumeratorLayout", a.ReturnType, a.TypeGenericParameters[0], concrete.BaseMethodContext.DeclaringType!)!)
        .Select(a => a.FullName).ToArray();
    File.WriteAllText(Guard("reports/indirect-return-helper-v32-diagnostic.json"), JsonSerializer.Serialize(new
    {
        descriptor_present = Invoke("DescribeNative", method) != null,
        caller_exact = Invoke("ExactBody", method, 552, "a1752250eaef0b5c3c2714f7dd5995a15560d9f83f7ad057b5078a62eb93efe9"),
        selected_pointer = $"0x{alias.UnderlyingPointer:X}", target_exact = Invoke("ExactBody", alias, 36, "43694a140756dab00d417fb317762c8d7e917bea857ba9368f482b6e80c7235a"),
        constructor_exact = LegacyArm64ValueThisThunks.TryGetExactBodyRange(app, 0x11DD130, out int size) && size == 16,
        constructor_hash = Invoke("BodyHash", app, 0x11DD130UL, 16, "93f97aee4056e153eb26e662e2518b5597090fb7491333fa0a160c01ed376afe"),
        caller_default_name = method.DefaultName, caller_default_type = method.DeclaringType!.DefaultFullName,
        concrete_base_type = concrete.BaseMethodContext.DeclaringType!.DefaultFullName, enum_base_type = returned.GenericType.DefaultFullName,
        known_element = Invoke("KnownReference", concrete.TypeGenericParameters[0]), layouts_rejected = rejectedLayouts.Length,
        first_rejected_layouts = rejectedLayouts.Take(3), storage_uses = Invoke("ReviewedStorageUses", raw, addresses),
        storage_rows = raw.Select((r, i) => new { r, address = addresses[i] }).Where(p => p.r.Operands.Any(o =>
            o is StackOffset s && s.Offset >= 0 && s.Offset < 32 || o is AddressOf { Target: StackOffset t } && t.Offset >= 0 && t.Offset < 32
            || o is MemoryOperand mem && (mem.Base is StackOffset or AddressOf || mem.Index is StackOffset or AddressOf)))
            .Select(p => new { site = $"0x{p.address:X}", op = p.r.OpCode.ToString(), operands = p.r.Operands.Select(o => new { kind = o.GetType().Name, text = o.ToString() }).ToArray() }).ToArray(),
        native_address_count = addresses.Count, converted_count = raw.Count
    }, new JsonSerializerOptions { WriteIndented = true }));
}

var options = new JsonSerializerOptions { WriteIndented = true };
File.WriteAllText(Guard("reports/indirect-return-helper-v32.json"), JsonSerializer.Serialize(new
{
    status = failures == 0 ? "PASS_EXACT_NATIVE_INDIRECT_RETURN_ADAPTER_AND_ATOMIC_REJECTIONS" : "FAIL_INDIRECT_RETURN_ADAPTER_GUARDS",
    checks = tests.Count, failures, tests, game_code_executed = false,
    original_binary_sha256 = Hash(binary), original_metadata_sha256 = Hash(metadata),
    tool_core_sha256 = Hash(typeof(LegacyArm64IndirectReturns).Assembly.Location),
    helper_source_sha256 = Hash(Guard("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64IndirectReturns.cs")),
    probe_source_sha256 = Hash(Guard("src/re/IndirectReturnProbe/Program.cs")),
    scope = "Actual production GetIsil converter result and original per-native-instruction conversion of the pinned SetStage body. Helper guards are exercised on disjoint copied ISIL/address fixtures; only a canonical accepted call destination may change. Negative fixture mutations are explicit diagnostic inputs, not recovered behavior. No game method executes, no CIL/source result or full game semantics is certified."
}, options));
Console.WriteLine($"Indirect return helper: {tests.Count - failures}/{tests.Count} checks, {failures} failures");
if (failures != 0) Environment.ExitCode = 1;
