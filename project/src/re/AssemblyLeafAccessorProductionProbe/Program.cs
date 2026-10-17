using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.OutputFormats;
using Cpp2IL.Core.Utils;
using Cpp2IL.Core.Utils.AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

if (args.Length != 1) throw new ArgumentException("Verified USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? d = new(Path.GetDirectoryName(path)!); d != null; d = d.Parent)
        if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point");
    return path;
}
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var checks = new List<object>(); var methods = new List<object>(); var details = new List<object>(); string? fatal = null;
void Check(string name, bool pass) { checks.Add(new { name, status = pass ? "PASS" : "FAIL" }); if (!pass) throw new Exception(name); }
List<string> Normalize(MethodDefinition method)
{
    var body = method.CilMethodBody!; var rows = new List<string>(); body.Instructions.CalculateOffsets();
    foreach (var i in body.Instructions)
    {
        string op = i.OpCode.Code.ToString();
        if (op is "Ldarg" or "Ldarg_S" or "Ldarg_0" or "Ldarg_1" or "Ldarg_2" or "Ldarg_3") rows.Add("Ldarg:" + i.GetParameterIndex());
        else if (op is "Ldloc" or "Ldloc_S" or "Ldloc_0" or "Ldloc_1" or "Ldloc_2" or "Ldloc_3") rows.Add("Ldloc:" + i.GetLocalVariableIndex());
        else if (op is "Stloc" or "Stloc_S" or "Stloc_0" or "Stloc_1" or "Stloc_2" or "Stloc_3") rows.Add("Stloc:" + i.GetLocalVariableIndex());
        else if (i.Operand is ICilLabel label) rows.Add(op.Replace("_S", "", StringComparison.Ordinal) + ":row" + body.Instructions.ToList().FindIndex(x => x.Offset == label.Offset));
        else rows.Add(op + ":" + i.Operand?.ToString());
    }
    return rows;
}
try
{
    string binary = Guard("unpacked/effective/exefs/main"), metadata = Guard("unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat");
    Check("original input identities", Hash(binary) == "94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238"
        && Hash(metadata) == "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85");
    Environment.SetEnvironmentVariable("CPP2IL_LEGACY_HFA", "1");
    Cpp2IlApi.Init(Guard("analysis/empty-probe-plugins"));
    Cpp2IlApi.InitializeLibCpp2Il(binary, metadata, new UnityVersion(2018, 1, 9, UnityVersionType.Final, 1));
    var app = Cpp2IlApi.CurrentAppContext!;
    var assemblyContext = app.GetAssemblyByName("Assembly-CSharp-firstpass")!;
    var owner = assemblyContext.Types.Single(t => t.FullName == "Newtonsoft.Json.Serialization.JsonSerializerInternalBase");
    var field = owner.Fields.Single(f => f.Name == "<Serializer>k__BackingField");
    var getter = owner.Properties.Single(p => p.Name == "Serializer").Getter!;
    var proxy = assemblyContext.Types.Single(t => t.FullName == "Newtonsoft.Json.Serialization.JsonSerializerProxy");
    _ = app.GetOrCreateKeyFunctionAddresses(); IlGenerator.InjectHelpersType(app);
    var stubApi = typeof(AsmResolverDllOutputFormat).GetMethod("BuildStubAssemblies", BindingFlags.Instance | BindingFlags.NonPublic)!;
    stubApi.Invoke(new AsmResolverDllOutputFormatEmpty(), [app]);
    foreach (var a in app.Assemblies) AsmResolverAssemblyPopulator.ConfigureHierarchy(a);
    foreach (var a in app.Assemblies) AsmResolverAssemblyPopulator.CopyDataFromIl2CppToManaged(a);
    var outputField = field.GetExtraData<FieldDefinition>("AsmResolverField")!;
    var outputGetter = getter.GetExtraData<MethodDefinition>("AsmResolverMethod")!;
    var priorPath = Guard("analysis/il2cpp/cpp2il-recovery-nso-virtual-companion-copy-v38/Assembly-CSharp-firstpass.dll");
    var prior = ModuleDefinition.FromFile(priorPath); var priorProxy = prior.GetAllTypes().Single(t => t.FullName == proxy.FullName);
    var priorOwner = prior.GetAllTypes().Single(t => t.FullName == owner.FullName);
    var priorField = priorOwner.Fields.Single(f => f.Name == field.Name);
    foreach (var context in proxy.Methods.Where(m => m.Name == ".ctor" && m.Parameters.Count == 1).OrderBy(m => m.UnderlyingPointer))
    {
        var original = priorProxy.Methods.Single(m => m.Name == ".ctor" && m.Signature!.ParameterTypes.Count == 1
            && m.Signature.ParameterTypes[0].FullName == context.Parameters[0].ParameterType.FullName);
        var definition = context.GetExtraData<MethodDefinition>("AsmResolverMethod")!;
        context.Analyze();
        var reads = context.ControlFlowGraph!.Instructions.SelectMany(i => i.Operands.OfType<FieldReference>()).Where(f => ReferenceEquals(f.Field, field)).ToArray();
        Check("original private field receiver survives actual pipeline: " + context.UnderlyingPointer.ToString("X"), reads.Length == 1
            && reads[0].Path.Length == 1 && ReferenceEquals(reads[0].Local.Type, context.Parameters[0].ParameterType));
        Check("actual attached original caller has assembly capability", LegacyArm64LeafAccessors.CanCallAssemblyGetter(field, getter, definition));
        IlGenerator.GenerateIl(context, definition);
        var before = original.CilMethodBody!.Instructions; var after = definition.CilMethodBody!.Instructions;
        Check("original v38 caller has one exact backing field read", before.Count(i => i.OpCode == CilOpCodes.Ldfld && ReferenceEquals(i.Operand, priorField)) == 1);
        Check("new actual caller emits exact existing nonvirtual internal getter", after.Count(i => i.OpCode == CilOpCodes.Call && ReferenceEquals(i.Operand, outputGetter)) == 1
            && !after.Any(i => i.OpCode == CilOpCodes.Ldfld && ReferenceEquals(i.Operand, outputField)));
        var beforeRows = Normalize(original); var afterRows = Normalize(definition);
        var differences = Enumerable.Range(0, Math.Min(beforeRows.Count, afterRows.Count)).Where(i => beforeRows[i] != afterRows[i]).ToArray();
        details.Add(new { method = context.FullName, rva = $"0x{context.UnderlyingPointer:X}", before = beforeRows, after = afterRows,
            differences, original_receiver = reads[0].Local.ToString(), original_receiver_type = reads[0].Local.Type?.FullName });
        Check("only original field load changes to exact getter call; all other effects/control remain", beforeRows.Count == afterRows.Count && differences.Length == 1
            && beforeRows[differences[0]].StartsWith("Ldfld:", StringComparison.Ordinal) && afterRows[differences[0]].StartsWith("Call:", StringComparison.Ordinal));
        Check("actual caller locals/init/EH remain unchanged", original.CilMethodBody.InitializeLocals == definition.CilMethodBody.InitializeLocals
            && original.CilMethodBody.ExceptionHandlers.Count == definition.CilMethodBody.ExceptionHandlers.Count
            && original.CilMethodBody.LocalVariables.Select(l => l.VariableType.FullName).SequenceEqual(definition.CilMethodBody.LocalVariables.Select(l => l.VariableType.FullName)));
        methods.Add(new { original_native_rva = $"0x{context.UnderlyingPointer:X}", original_parameter_type = context.Parameters[0].ParameterType.FullName,
            backing_field_reads_before = 1, backing_field_reads_after = 0, exact_nonvirtual_getter_calls_after = 1,
            unchanged_other_instruction_rows = beforeRows.Count - 1, receiver_type_preserved = true, existing_effect_and_control_rows_preserved = true });
    }
    Check("both original Reader/Writer constructors inspected", methods.Count == 2);
    Check("original private field/internal getter metadata preserved", field.Visibility == FieldAttributes.Private && getter.Visibility == MethodAttributes.Assembly
        && outputField.IsPrivate && outputGetter.IsAssembly);
}
catch (Exception error) { fatal = error.ToString(); }
string detailPath = Guard("analysis/reconstruction/assembly-leaf-v39/actual-constructor-emission.json");
Directory.CreateDirectory(Path.GetDirectoryName(detailPath)!); File.WriteAllText(detailPath, JsonSerializer.Serialize(details, new JsonSerializerOptions { WriteIndented = true }));
var report = new { status = fatal == null ? "PASS_ACTUAL_ORIGINAL_CONSTRUCTOR_RECEIVER_AND_ASSEMBLY_GETTER_EMISSION" : "ACTUAL_CONSTRUCTOR_ASSEMBLY_GETTER_EMISSION_FAILED",
    checks = checks.Count, tests = checks, fatal, core_sha256 = Hash(typeof(Cpp2IlApi).Assembly.Location),
    probe_source_sha256 = Hash(Guard("src/re/AssemblyLeafAccessorProductionProbe/Program.cs")),
    baseline_run = "nso-virtual-companion-copy-v38", baseline_assembly_sha256 = Hash(Guard("analysis/il2cpp/cpp2il-recovery-nso-virtual-companion-copy-v38/Assembly-CSharp-firstpass.dll")),
    methods, private_detail_sha256 = Hash(detailPath), original_game_methods_executed = 0,
    production_outputs_written = false, whole_game_source_ready = false,
    scope = "Two actual original JsonSerializerProxy constructors run through current production Analyze and real IlGenerator in memory. Exact original receiver field read becomes existing internal nonvirtual getter call; normalized arg/local/branch macro forms compare every other effect/control instruction and local/init/EH shape with immutable v38. No constructor, getter, game or Unity code executes, and no complete assembly/source export or full behavior parity is claimed." };
File.WriteAllText(Guard("reports/assembly-leaf-accessor-production-v39.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { report.status, report.checks, fatal }));
return fatal == null ? 0 : 2;
