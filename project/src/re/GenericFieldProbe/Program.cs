using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Analysis;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;

if (args.Length is < 1 or > 2 || (args.Length == 2 && !System.Text.RegularExpressions.Regex.IsMatch(args[1], "^[a-z0-9-]+$"))) throw new ArgumentException("Verified USB project root and optional report tag required");
var tag = args.Length == 2 ? args[1] : "v22";
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
    || Hash(metadata) != "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85")
    throw new IOException("Original input hash differs");
Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
var app = Cpp2IlApi.CurrentAppContext!;
var types = app.Assemblies.SelectMany(a => a.Types).ToList();
var names = new[] { "DG.Tweening.Tween", "DG.Tweening.Tweener", "DG.Tweening.Core.TweenerCore`3", "DG.Tweening.Core.Surrogates.Vector3Wrapper", "DG.Tweening.Plugins.Options.VectorOptions", "UnityEngine.Vector3" };
var rows = types.Where(t => names.Contains(t.FullName)).Select(t => new
{
    type = t.FullName, base_type = t.BaseType?.FullName, value_type = t.IsValueType,
    attributes = t.Attributes.ToString(), packing = t.Definition?.PackingSize,
    instance_size = t.Definition?.RawSizes.instance_size, native_size = t.Definition?.RawSizes.native_size,
    fields = t.Fields.Select(f => new { name = f.Name, type = f.FieldType.FullName, offset = f.Offset, attributes = f.Attributes.ToString() }).ToArray()
}).ToArray();
var caller = types.Single(t => t.FullName == "DG.Tweening.Plugins.Vector3WrapperPlugin").Methods.Single(m => m.Name == "SetRelativeEndValue");
var aggregateMethods = types.Where(t => t.FullName == "DG.Tweening.Core.Surrogates.Vector3Wrapper" || t.FullName == "DG.Tweening.Plugins.Vector3WrapperPlugin")
    .SelectMany(t => t.Methods).Select(m => new { name = m.FullName, rva = $"0x{m.UnderlyingPointer:X}", returns = m.ReturnType.FullName,
        parameters = m.Parameters.Select(p => p.ParameterType.FullName).ToArray() }).ToArray();
var report = new { status = "METADATA_LAYOUT_OBSERVATIONS_ONLY", source_binary_sha256 = Hash(binary), source_metadata_sha256 = Hash(metadata), caller_rva = $"0x{caller.UnderlyingPointer:X}", parameter_type = caller.Parameters[0].ParameterType.FullName, types = rows, aggregate_methods = aggregateMethods };
var text = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
File.WriteAllText(Guard("analysis/il2cpp/generic-field-layout-observations.json"), text + "\n");
Console.WriteLine(text);
var owner = caller.Parameters[0].ParameterType;
var tests = new List<object>();
void CheckPath(long offset, int size, string? expected)
{
    var path = LegacyArm64FieldPaths.Find(owner, offset, size);
    var actual = path == null ? null : string.Join(".", path.Select(f => f.Name));
    if (actual != expected) throw new Exception($"Path at {offset:X}/{size}: {actual} != {expected}");
    tests.Add(new { offset = $"0x{offset:X}", size, expected, status = "PASS" });
}
CheckPath(0x10c, 4, "startValue.value.x");
CheckPath(0x110, 4, "startValue.value.y");
CheckPath(0x114, 4, "startValue.value.z");
CheckPath(0x118, 4, "endValue.value.x");
CheckPath(0x11c, 4, "endValue.value.y");
CheckPath(0x120, 4, "endValue.value.z");
CheckPath(0x124, 4, "changeValue.value.x");
CheckPath(0x10a, 4, null); // base tail padding
CheckPath(0x119, 4, null); // misaligned interior
CheckPath(0x118, 8, null); // FP width differs from the declared leaf
CheckPath(0x10, 4, null); // no field guessed from object header bytes
CheckPath(0x134, 4, null); // bool and struct tail padding cannot be read as float
CheckPath(0x118, 16, null);
var wrapper = types.Single(t => t.FullName == "DG.Tweening.Core.Surrogates.Vector3Wrapper");
var vector = types.Single(t => t.FullName == "UnityEngine.Vector3");
void CheckShape(string name, TypeAnalysisContext type, string[]? expected)
{
    var shape = Cpp2IL.Core.Utils.LegacyArm64Hfa.Describe(type);
    var actual = shape?.Fields.Select(f => string.Join(".", f.Path.Select(p => p.Name)) + ":" + f.Offset).ToArray();
    if (actual == null != (expected == null) || (actual != null && !actual.SequenceEqual(expected!))) throw new Exception("HFA shape differs: " + name);
    tests.Add(new { name, status = "PASS", expected });
}
CheckShape("nested Vector3 wrapper", wrapper, ["value.x:0", "value.y:4", "value.z:8"]);
CheckShape("flat vector", vector, ["x:0", "y:4", "z:8"]);
CheckShape("mixed enum and bool rejected", types.Single(t => t.FullName == "DG.Tweening.Plugins.Options.VectorOptions"), null);
CheckShape("scalar float is not an aggregate", app.SystemTypes.SystemSingleType, null);
CheckShape("generic reference owner is not an HFA", owner, null);
var z = vector.Fields.Single(f => f.Name == "z");
var oldOffset = z.OverrideOffset;
try
{
    z.OverrideOffset = 12;
    CheckShape("flat padding rejected", vector, null);
    CheckShape("nested padding rejected", wrapper, null);
}
finally { z.OverrideOffset = oldOffset; }
var binder = typeof(LocalVariables).GetMethod("PropagateFromParameters", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
int parameterBindingCases = 0, parameterBindingChecks = 0;
var parameterTypes = new[] { app.SystemTypes.SystemInt32Type, app.SystemTypes.SystemSingleType, app.SystemTypes.SystemDoubleType, app.SystemTypes.SystemStringType };
var parameterRegisters = new[] { "X1", "V0", "V1", "X2" };
foreach (bool isStatic in new[] { false, true })
foreach (bool withThis in isStatic ? new[] { false } : new[] { false, true })
foreach (bool withInfo in new[] { false, true })
for (int present = 0; present < 16; present++)
{
    var fixture = new InjectedMethodAnalysisContext(caller.DeclaringType!, "ParameterBindingFixture", app.SystemTypes.SystemVoidType,
        System.Reflection.MethodAttributes.Public | (isStatic ? System.Reflection.MethodAttributes.Static : 0), parameterTypes);
    var thisRegister = new Register(null, "X0");
    if (!isStatic) fixture.ParameterOperands.Add(thisRegister);
    fixture.ParameterOperands.AddRange(parameterRegisters.Select(name => (IOperand)new Register(null, name)));
    fixture.ParameterOperands.Add(new Register(null, "X3"));
    if (withThis) fixture.ParameterLocals.Add(new LocalVariable("this", thisRegister) { IsThis = true });
    for (int i = 0; i < 4; i++)
        if ((present & (1 << i)) != 0) fixture.ParameterLocals.Add(new LocalVariable("same-name", new Register(null, parameterRegisters[i])));
    if (withInfo) fixture.ParameterLocals.Add(new LocalVariable("methodInfo", new Register(null, "X3")) { IsMethodInfo = true });
    binder.Invoke(null, [fixture]);
    foreach (var local in fixture.ParameterLocals)
    {
        if (local.IsThis ? local.Type != caller.DeclaringType
            : local.IsMethodInfo ? local.Type is not RuntimeMethodInfoAnalysisContext
            : local.Type != parameterTypes[Array.IndexOf(parameterRegisters, local.Register.Name)])
            throw new Exception("Sparse parameter/signature binding failed");
        parameterBindingChecks++;
    }
    parameterBindingCases++;
}
tests.Add(new { name = "sparse original-position parameter bindings", status = "PASS", cases = parameterBindingCases, checks = parameterBindingChecks });
Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
caller.Analyze();
var operations = caller.ControlFlowGraph!.Instructions;
var references = operations.SelectMany(i => i.Operands).OfType<FieldReference>().Where(f => f.Path.Length > 1).ToArray();
var reads = operations.Count(i => i.OpCode == Cpp2IL.Core.ISIL.OpCode.Move && i.Operands[1] is FieldReference { Path.Length: > 1 });
var writes = operations.Count(i => i.OpCode == Cpp2IL.Core.ISIL.OpCode.Move && i.Operands[0] is FieldReference { Path.Length: > 1 });
if (reads != 6 || writes != 3) throw new Exception($"Actual caller paths: reads={reads}, writes={writes}");
File.WriteAllText(Guard("analysis/il2cpp/generic-field-caller-isil.txt"), string.Join("\n", operations) + "\n");
var convert = types.Single(t => t.FullName == "DG.Tweening.Plugins.Vector3WrapperPlugin").Methods.Single(m => m.Name == "ConvertToStartValue");
convert.Analyze();
if (convert.ParameterLocals.Single(local => local.Name == "value").Type != wrapper) throw new Exception("Actual optimized-out prefix shifted the wrapper parameter type");
File.WriteAllText(Guard("analysis/il2cpp/generic-field-convert-isil.txt"), string.Join("\n", convert.ControlFlowGraph!.Instructions) + "\n");
var backKeyCtor = types.Single(t => t.FullName == "BackKeyManager").Methods.Single(m => m.Name == ".ctor");
backKeyCtor.Analyze();
File.WriteAllText(Guard("analysis/il2cpp/back-key-constructor-isil.txt"), string.Join("\n", backKeyCtor.ControlFlowGraph!.Blocks.Select(b => b.ToString())) + "\n");
var constructorObservations = new List<object>();
foreach (var block in backKeyCtor.ControlFlowGraph!.Blocks)
foreach (var allocation in block.Instructions.Where(i => i.OpCode == Cpp2IL.Core.ISIL.OpCode.Newobj))
{
    if (allocation.Operands[0] is not LocalVariable local) continue;
    foreach (var call in backKeyCtor.ControlFlowGraph.Instructions.Where(i => i.IsCall && i.Operands[0] is MethodAnalysisContext { Name: ".ctor" }))
    {
        var receiverIndex = call.OpCode == Cpp2IL.Core.ISIL.OpCode.Call ? 2 : 1;
        if (call.Operands.Count <= receiverIndex || !ReferenceEquals(call.Operands[receiverIndex], local)) continue;
        var target = (MethodAnalysisContext)call.Operands[0];
        constructorObservations.Add(new { caller_rva = $"0x{backKeyCtor.UnderlyingPointer:X}",
            allocation_block = block.ID, constructor_block = backKeyCtor.ControlFlowGraph.Blocks.Single(b => b.Instructions.Contains(call)).ID,
            allocated_type = local.Type?.FullName, constructor_type = target.DeclaringType?.FullName,
            same_context_reference = ReferenceEquals(local.Type, target.DeclaringType),
            allocation_context = local.Type?.GetType().Name, constructor_context = target.DeclaringType?.GetType().Name });
    }
}
File.WriteAllText(Guard("analysis/il2cpp/back-key-constructor-observations.json"), JsonSerializer.Serialize(constructorObservations, new JsonSerializerOptions { WriteIndented = true }) + "\n");
var allCtorInstructions = backKeyCtor.ControlFlowGraph.Instructions;
var actualAllocation = allCtorInstructions.Single(i => i.OpCode == Cpp2IL.Core.ISIL.OpCode.Newobj);
var actualLocal = (LocalVariable)actualAllocation.Operands[0];
var allocatedOwner = (GenericInstanceTypeAnalysisContext)actualLocal.Type!;
var actualCtorCall = allCtorInstructions.Single(i => i.IsCall && i.Operands[0] is MethodAnalysisContext { Name: ".ctor" } target
    && target.DeclaringType is GenericInstanceTypeAnalysisContext);
var actualCtor = (MethodAnalysisContext)actualCtorCall.Operands[0];
var sameClosedType = typeof(IlGenerator).GetMethod("SameClosedReferenceType", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
int constructorChecks = 0;
void CheckClosed(string name, TypeAnalysisContext left, TypeAnalysisContext right, bool expected)
{
    bool actual = (bool)sameClosedType.Invoke(null, [left, right])!;
    if (actual != expected) throw new Exception("Closed constructor type identity differs: " + name);
    tests.Add(new { name, expected, status = "PASS" });
    constructorChecks++;
}
CheckClosed("actual distinct generic owner contexts", allocatedOwner, actualCtor.DeclaringType!, true);
CheckClosed("different string argument rejected", allocatedOwner, new GenericInstanceTypeAnalysisContext(allocatedOwner.GenericType, [app.SystemTypes.SystemStringType]), false);
CheckClosed("different int argument rejected", allocatedOwner, new GenericInstanceTypeAnalysisContext(allocatedOwner.GenericType, [app.SystemTypes.SystemInt32Type]), false);
CheckClosed("base object is not exact allocated type", allocatedOwner, app.SystemTypes.SystemObjectType, false);
CheckClosed("open generic argument rejected", allocatedOwner, new GenericInstanceTypeAnalysisContext(allocatedOwner.GenericType, [allocatedOwner.GenericType.GenericParameters[0]]), false);
CheckClosed("value type excluded from new structural fusion", vector, vector, false);
var element = allocatedOwner.GenericArguments[0];
var arrayListA = new GenericInstanceTypeAnalysisContext(allocatedOwner.GenericType, [new SzArrayTypeAnalysisContext(element)]);
var arrayListB = new GenericInstanceTypeAnalysisContext(allocatedOwner.GenericType, [new SzArrayTypeAnalysisContext(element)]);
CheckClosed("equivalent array type arguments", arrayListA, arrayListB, true);
CheckClosed("array and scalar type arguments differ", allocatedOwner, arrayListA, false);
var findCtor = typeof(IlGenerator).GetMethod("FindConstructorCall", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
if (!ReferenceEquals(findCtor.Invoke(null, [backKeyCtor, actualAllocation]), actualCtorCall)) throw new Exception("Actual adjacent closed generic constructor was not selected");
tests.Add(new { name = "actual same-block allocation constructor match", status = "PASS" });
constructorChecks++;
void CheckBlocked(string name, bool differentReceiver, bool barrier, bool separateBlock)
{
    var fixture = new InjectedMethodAnalysisContext(backKeyCtor.DeclaringType!, "ConstructorFusionFixture", app.SystemTypes.SystemVoidType, System.Reflection.MethodAttributes.Public, []);
    var local = new LocalVariable("created", new Register(null, "FIXTURE_CREATED"), allocatedOwner);
    var allocation = new Instruction(0, Cpp2IL.Core.ISIL.OpCode.Newobj, local, allocatedOwner);
    var receiver = differentReceiver ? new LocalVariable("other", new Register(null, "FIXTURE_OTHER"), allocatedOwner) : local;
    var call = new Instruction(2, Cpp2IL.Core.ISIL.OpCode.CallVoid, actualCtor, receiver);
    var graph = new Cpp2IL.Core.Graphs.ISILControlFlowGraph([new Instruction(3, Cpp2IL.Core.ISIL.OpCode.Return)]);
    var block = new Cpp2IL.Core.Graphs.Block { ID = 99, Instructions = [allocation] };
    if (barrier) block.Instructions.Add(new Instruction(1, Cpp2IL.Core.ISIL.OpCode.CallVoid, new StringLiteral("observable-boundary")));
    if (!separateBlock) block.Instructions.Add(call);
    else graph.Blocks.Add(new Cpp2IL.Core.Graphs.Block { ID = 100, Instructions = [call] });
    graph.Blocks.Add(block);
    fixture.ControlFlowGraph = graph;
    if (findCtor.Invoke(null, [fixture, allocation]) != null) throw new Exception("Unsafe constructor fusion accepted: " + name);
    tests.Add(new { name, status = "PASS" });
    constructorChecks++;
}
CheckBlocked("different receiver rejected", true, false, false);
CheckBlocked("observable intervening call rejected", false, true, false);
CheckBlocked("different block rejected", false, false, true);
var result = new { status = "PASS_SCOPED_METADATA_GENERIC_FP_FIELD_PATHS", checks = tests.Count + 2 + parameterBindingChecks + 1, tests, parameter_binding_cases = parameterBindingCases, parameter_binding_checks = parameterBindingChecks, actual_caller_reads = reads, actual_caller_writes = writes,
    constructor_checks = constructorChecks,
    scope = "Metadata layout and selected actual recovered caller ISIL only. Requires separate recovered-CIL execution against original ARM64 fixtures; no complete source claim." };
File.WriteAllText(Guard($"reports/generic-field-path-{tag}.json"), JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(result));
