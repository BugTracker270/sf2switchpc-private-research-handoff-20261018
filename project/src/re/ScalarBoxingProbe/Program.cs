using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.Utils;
using Cpp2IL.Core.Il2CppApiFunctions;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.Graphs;

if (args.Length is < 1 or > 2 || args.Length == 2 && args[1] is not ("--validate" or "--liveness-before" or "--liveness-after")) throw new ArgumentException("Verified USB project root and optional probe mode required");
var validate = args.Length == 2 && args[1] == "--validate";
if (validate) Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
var root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    var path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point forbidden");
    return path;
}
string Hash(string file) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))).ToLowerInvariant();
if (args.Length == 2 && args[1].StartsWith("--liveness", StringComparison.Ordinal))
{
    var input = new LocalVariable("input",new Register(0,"X0"));
    var slot = new LocalVariable("copied_slot",new Register(null,"SLOT"));
    var readResultLocal = new LocalVariable("read_result",new Register(null,"RESULT"));
    var copy = new Instruction(0,Cpp2IL.Core.ISIL.OpCode.Move,slot,input);
    var address = new AddressOf(slot);
    var call = new Instruction(1,Cpp2IL.Core.ISIL.OpCode.Call,new StringLiteral("read_then_mutate_slot"),readResultLocal,address);
    var graph = new ISILControlFlowGraph([copy,call,new Instruction(2,Cpp2IL.Core.ISIL.OpCode.Return,readResultLocal)]);
    (int? Returned,int Argument,int? Slot,string? Error) Execute()
    {
        var values = new Dictionary<LocalVariable,int> { [input] = 0x12345678 };
        try
        {
            foreach (var instruction in graph.Instructions)
            {
                if (instruction.OpCode == Cpp2IL.Core.ISIL.OpCode.Move && instruction.Operands is [LocalVariable to,LocalVariable from]) values[to]=values[from];
                else if (instruction.OpCode == Cpp2IL.Core.ISIL.OpCode.Call && instruction.Operands[2] is AddressOf { Target: LocalVariable target })
                {
                    if (!values.TryGetValue(target,out var read)) throw new Exception("Addressed storage was not initialized");
                    values[readResultLocal]=read; values[target]=-7;
                }
                else if (instruction.OpCode == Cpp2IL.Core.ISIL.OpCode.Return)
                    return (values[readResultLocal],values[input],values.GetValueOrDefault(slot),null);
            }
            throw new Exception("Fixture did not return");
        }
        catch (Exception ex) { return (null,values[input],values.TryGetValue(slot,out var value) ? value : null,ex.Message); }
    }
    var before = Execute();
    SsaSimplifier.Run(graph,[input]);
    var after = Execute();
    bool pass = before == (0x12345678,0x12345678,-7,null) && after == before && copy.OpCode == Cpp2IL.Core.ISIL.OpCode.Move
        && ReferenceEquals(((AddressOf)call.Operands[2]).Target,slot);
    var report = new { status=pass ? "PASS_ADDRESSED_COPY_INITIALIZATION_AND_IDENTITY_PRESERVED" : "ADDRESSED_STORAGE_INITIALIZATION_LOSS_CONFIRMED",
        before=new { before.Returned,before.Argument,before.Slot,before.Error },after=new { after.Returned,after.Argument,after.Slot,after.Error },
        initializer_retained=copy.OpCode==Cpp2IL.Core.ISIL.OpCode.Move,address_identity_retained=ReferenceEquals(((AddressOf)call.Operands[2]).Target,slot),
        core_assembly_sha256=Hash(typeof(SsaSimplifier).Assembly.Location),
        scope="Independent ISIL fixture copies an input into distinct local storage, reads and mutates that storage through its address, and requires the original input to remain unchanged. No application metadata or native code is involved; actual SetAge input provenance is tested separately." };
    var text=JsonSerializer.Serialize(report,new JsonSerializerOptions { WriteIndented=true });
    File.WriteAllText(Guard(args[1]=="--liveness-before" ? "reports/addressed-storage-liveness-before-v30.json" : "reports/addressed-storage-liveness-after-v30.json"),text+"\n");
    Console.WriteLine(text);
    Environment.ExitCode=pass ? 0 : 2;
    return;
}
var binary = Guard("unpacked/effective/exefs/main");
var metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
if (Hash(binary) != "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
    || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85") throw new IOException("Original input hash differs");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var keys = app.GetOrCreateKeyFunctionAddresses();
var primitives = new[] { app.SystemTypes.SystemBooleanType, app.SystemTypes.SystemCharType,
    app.SystemTypes.SystemSByteType, app.SystemTypes.SystemByteType, app.SystemTypes.SystemInt16Type,
    app.SystemTypes.SystemUInt16Type, app.SystemTypes.SystemInt32Type, app.SystemTypes.SystemUInt32Type,
    app.SystemTypes.SystemInt64Type, app.SystemTypes.SystemUInt64Type, app.SystemTypes.SystemSingleType,
    app.SystemTypes.SystemDoubleType };
var layouts = primitives.Select(t => new {
    type = t.FullName, value_type = t.IsValueType,
    instance_size = t.Definition?.RawSizes.instance_size,
    native_size = t.Definition?.RawSizes.native_size,
    has_static_constructor = t.Methods.Any(m => m.Name == ".cctor"),
    methods = t.Methods.Where(m => m.Name.Contains("IConvertible.ToType", StringComparison.Ordinal)).Select(m => new {
        name = m.FullName, underlying_pointer = $"0x{m.UnderlyingPointer:X}",
        parameters = m.Parameters.Select(p => p.ParameterType.FullName).ToArray() }).ToArray()
}).ToArray();
var caller = app.Assemblies.SelectMany(a => a.Types).Single(t => t.FullName == "FyberPlugin.User").Methods.Single(m => m.Name == "SetAge");
caller.Analyze();
File.WriteAllText(Guard(validate ? "analysis/il2cpp/scalar-boxing-setage-after-isil.txt" : "analysis/il2cpp/scalar-boxing-setage-before-isil.txt"), string.Join("\n", caller.ControlFlowGraph!.Blocks.Select(b => b.ToString())) + "\n");
var calls = caller.ControlFlowGraph!.Instructions.Where(i => i.OpCode == Cpp2IL.Core.ISIL.OpCode.Call
    && i.Operands[0] is Immediate { UnsignedValue: 0xB5B070 }).Select(i => new {
        arguments = i.Operands.Skip(2).Select(o => new {
            kind = o.GetType().Name,
            type = o is TypeAnalysisContext t ? t.FullName : o is LocalVariable l ? l.Type?.FullName : null,
            address_of_type = o is AddressOf { Target: LocalVariable v } ? v.Type?.FullName : null
        }).ToArray()
    }).ToArray();
var checks = 0;
void Check(bool condition, string label) { if (!condition) throw new Exception(label); checks++; }
var boxes = caller.ControlFlowGraph!.Instructions.Where(i => i.OpCode == Cpp2IL.Core.ISIL.OpCode.Box).ToArray();
if (validate)
{
    Check(keys is NewArm64KeyFunctionAddresses { LegacyScalarBoxingCandidate: 0xB5B070 }, "Boxing candidate not discovered from exact primitive body witnesses");
    Check(!keys.IsKeyFunctionAddress(0xB5B070) && !keys.Pairs.Any(p => p.Value == 0xB5B070), "Scalar candidate leaked into unconditional key-function classification");
    Check(keys.il2cpp_value_box == 0 && keys.il2cpp_vm_object_box == 0, "Generic boxing discovery was broadened");
    Check(LegacyArm64ScalarBoxing.FindCandidate(app, keys.il2cpp_codegen_object_new + 4) == 0, "Wrong allocator identity accepted");
    foreach (var primitive in primitives)
    {
        bool allowed = primitive != app.SystemTypes.SystemBooleanType && primitive != app.SystemTypes.SystemCharType;
        Check((LegacyArm64ScalarBoxing.PrimitiveWidth(app, primitive) > 0) == allowed, "Primitive/cctor scope differs: " + primitive.FullName);
    }
    Check(calls.Length == 0 && boxes.Length == 1, "Actual caller did not recover exactly one box");
    Check(boxes[0].Operands is [LocalVariable, TypeAnalysisContext t, AddressOf { Target: LocalVariable stored }]
        && t == app.SystemTypes.SystemInt32Type && stored.Type == t, "Actual caller box type/storage differs");
    var storedValue = ((AddressOf)boxes[0].Operands[2]).Target;
    var resultLocal = (LocalVariable)boxes[0].Operands[0];
    var actualType = app.SystemTypes.SystemInt32Type;
    var rejectCases = new (string Name, IOperand Target, IOperand Type, IOperand Value, Cpp2IL.Core.ISIL.OpCode Op)[] {
        ("wrong helper", new Immediate(0xB5B074), actualType, new AddressOf(storedValue), Cpp2IL.Core.ISIL.OpCode.Call),
        ("bool cctor", new Immediate(0xB5B070), app.SystemTypes.SystemBooleanType, new AddressOf(storedValue), Cpp2IL.Core.ISIL.OpCode.Call),
        ("char cctor", new Immediate(0xB5B070), app.SystemTypes.SystemCharType, new AddressOf(storedValue), Cpp2IL.Core.ISIL.OpCode.Call),
        ("reference type", new Immediate(0xB5B070), app.SystemTypes.SystemObjectType, new AddressOf(storedValue), Cpp2IL.Core.ISIL.OpCode.Call),
        ("mismatched scalar storage", new Immediate(0xB5B070), app.SystemTypes.SystemUInt32Type, new AddressOf(storedValue), Cpp2IL.Core.ISIL.OpCode.Call),
        ("value instead of address", new Immediate(0xB5B070), actualType, storedValue, Cpp2IL.Core.ISIL.OpCode.Call),
        ("undefined typed local", new Immediate(0xB5B070), actualType, new AddressOf(new LocalVariable("uninitialized", new Register(null,"UNINITIALIZED"),actualType)), Cpp2IL.Core.ISIL.OpCode.Call),
        ("indirect target", new Immediate(0xB5B070), actualType, new AddressOf(storedValue), Cpp2IL.Core.ISIL.OpCode.IndirectCall),
    };
    foreach (var row in rejectCases)
        Check(!LegacyArm64ScalarBoxing.TryRewrite(caller, new Instruction(999,row.Op,row.Target,resultLocal,row.Type,row.Value)), "Unsafe scalar boxing accepted: " + row.Name);
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","0");
    Check(!LegacyArm64ScalarBoxing.TryRewrite(caller,new Instruction(999,Cpp2IL.Core.ISIL.OpCode.Call,new Immediate(0xB5B070),resultLocal,actualType,new AddressOf(storedValue))), "Scalar rewrite bypassed opt-in");
    Check(LegacyArm64ScalarBoxing.FindCandidate(app,keys.il2cpp_codegen_object_new) == 0, "Scalar discovery bypassed opt-in");
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA","1");
}
var result = new { status = validate ? "PASS_TYPED_SCALAR_BOX_DISCOVERY_AND_CALLER_IR" : "SCALAR_BOXING_METADATA_OBSERVATIONS_ONLY", checks,
    binary_sha256 = Hash(binary), metadata_sha256 = Hash(metadata), primitives = layouts,
    key_functions = new { value_box = $"0x{keys.il2cpp_value_box:X}", vm_object_box = $"0x{keys.il2cpp_vm_object_box:X}",
        object_new = $"0x{keys.il2cpp_codegen_object_new:X}" },
    selected_caller = new { type = caller.DeclaringType!.FullName, name = caller.Name, underlying_pointer = $"0x{caller.UnderlyingPointer:X}", unresolved_box_calls = calls },
    recovered_boxes = boxes.Select(i => new { type = ((TypeAnalysisContext)i.Operands[1]).FullName,
        storage_is_parameter = i.Operands[2] is AddressOf { Target: LocalVariable v } && caller.ParameterLocals.Any(p => ReferenceEquals(p,v)) }).ToArray(),
    scope = "Actual Cpp2IL method context addresses and primitive class layout/cctor observations. No native boxing or recovered CIL execution is implied." };
var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
File.WriteAllText(Guard(validate ? "reports/scalar-boxing-validation-v30.json" : "reports/scalar-boxing-metadata-v30.json"), json + "\n");
Console.WriteLine(json);
