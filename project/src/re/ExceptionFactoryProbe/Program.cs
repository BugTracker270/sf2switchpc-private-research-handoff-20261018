using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;

if (args.Length != 1) throw new ArgumentException("Verified USB project root required");
var root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
var binary = Guard("unpacked/effective/exefs/main");
var metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
string Hash(string file) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))).ToLowerInvariant();
if (Hash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Original input hash differs");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var checks = 0;
void Check(bool condition, string label) { if (!condition) throw new Exception(label); checks++; }
var type = ThrowHelperRecovery.GetThrownException(app, 0xB4DA50);
Check(type?.FullName == "System.ArrayTypeMismatchException", "Exact returning factory type not recovered");
var ctor = ThrowHelperRecovery.GetProvenDefaultConstructor(app, 0xB4DA50, type!);
Check(ctor is { Name: ".ctor", Parameters.Count: 0, IsStatic: false } && ReferenceEquals(ctor.DeclaringType, type), "Exact default constructor not proven");
foreach (var address in new ulong[] { 0xB4D8B0, 0xB4D660, 0xB5B110, 0xB5B390, 0xB04F60 })
    Check(ThrowHelperRecovery.GetProvenDefaultConstructor(app, address, type!) == null, $"Nonzero-message/non-factory accepted: {address:X}");
Check(ThrowHelperRecovery.GetProvenDefaultConstructor(app, 0xB4DA50, app.SystemTypes.SystemObjectType) == null, "Non-exception type accepted");
Check(ThrowHelperRecovery.GetProvenDefaultConstructor(app, 0xB4DA50, app.SystemTypes.SystemExceptionType) == null, "Wrong exception constructor identity accepted");
var existingFactoryType = ThrowHelperRecovery.GetThrownException(app, 0xB4D8F0);
Check(existingFactoryType?.FullName == "System.IndexOutOfRangeException", "Existing 64-byte factory changed type");
Check(ThrowHelperRecovery.GetProvenDefaultConstructor(app, 0xB4D8F0, existingFactoryType!) is { Parameters.Count: 0 } existingCtor
    && ReferenceEquals(existingCtor.DeclaringType, existingFactoryType), "Existing factory default initialization not preserved");
var caller = app.Assemblies.SelectMany(a => a.Types).Single(t => t.FullName == "AuthenticationSample").Methods.Single(m => m.Name == "Start");
caller.Analyze();
var rows = new List<object>();
var findCtor = typeof(IlGenerator).GetMethod("FindConstructorCall", BindingFlags.NonPublic | BindingFlags.Static)!;
foreach (var block in caller.ControlFlowGraph!.Blocks)
for (var i = 0; i + 1 < block.Instructions.Count; i++)
{
    var allocation = block.Instructions[i];
    var next = block.Instructions[i + 1];
    if (allocation is not { OpCode: Cpp2IL.Core.ISIL.OpCode.Newobj, Operands: [LocalVariable local, TypeAnalysisContext allocated] }
        || allocated.FullName != "System.ArrayTypeMismatchException") continue;
    Check(next is { OpCode: Cpp2IL.Core.ISIL.OpCode.CallVoid, Operands: [MethodAnalysisContext target, LocalVariable receiver] }
        && ReferenceEquals(target, ctor) && ReferenceEquals(receiver, local), "Factory constructor pair was not kept adjacent in the same block");
    Check(ReferenceEquals(findCtor.Invoke(null, [caller, allocation]), next), "Generator did not select exact factory constructor pair");
    rows.Add(new { block = block.ID, type = allocated.FullName, constructor = ctor!.FullName });
}
Check(rows.Count == 7, "Actual caller did not contain all seven returning array-mismatch factories");
File.WriteAllText(Guard("analysis/il2cpp/exception-factory-caller-isil.txt"), string.Join("\n", caller.ControlFlowGraph.Blocks.Select(b => b.ToString())) + "\n");
var report = new { status = "PASS_NATIVE_FACTORY_METADATA_AND_EXACT_CONSTRUCTOR_PAIR", checks,
    factory_rva = "0xB4DA50", caller_rva = $"0x{caller.UnderlyingPointer:X}", caller_factories = rows,
    binary_sha256 = Hash(binary), metadata_sha256 = Hash(metadata),
    scope = "Native witness and actual normalized caller IR plus strict generator pair selection. This probe does not execute recovered CIL, original constructor bodies or whole gameplay." };
var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
File.WriteAllText(Guard("reports/compiler-priority-exception-factory.json"), json + "\n");
Console.WriteLine(json);
