using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using AssetRipper.Primitives;
using Cpp2IL.Core;
using Cpp2IL.Core.Graphs;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using Cpp2IL.Core.OutputFormats;
using Cpp2IL.Core.Utils;
using Cpp2IL.Core.Utils.AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AMethod = AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes;
using AType = AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes;
using IOp = Cpp2IL.Core.ISIL.OpCode;

if (args.Length is < 1 or > 2 || args.Length == 2 && args[1] != "--baseline") throw new ArgumentException("USB root and optional --baseline required");
bool baseline = args.Length == 2;
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
string Guard(string relative)
{
    string path = Path.GetFullPath(Path.Combine(root, relative));
    if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB workspace");
    for (DirectoryInfo? directory = new(Path.GetDirectoryName(path)!); directory != null; directory = directory.Parent)
        if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point");
    return path;
}
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var checks = new List<object>(); var emissions = new List<object>(); var inventory = new List<object>(); string? fatal = null;
string? nativeHash = null, recoveredGetterAssemblyHash = null; int recoveredGetterFieldLoads = 0;
void Check(string name, bool pass) { checks.Add(new { name, status = pass ? "PASS" : "FAIL" }); if (!pass) throw new Exception(name); }
bool ExactGetterFlow(MethodDefinition method, FieldDefinition field)
{
    var body = method.CilMethodBody;
    if (body == null || body.ExceptionHandlers.Count != 0 || method.IsStatic || method.Signature?.ParameterTypes.Count != 0) return false;
    var stack = new Stack<int>(); var locals = new Dictionary<int, int>(); int loads = 0, returns = 0;
    foreach (var row in body.Instructions)
    {
        var op = row.OpCode;
        if (op == CilOpCodes.Ldarg || op == CilOpCodes.Ldarg_S || op == CilOpCodes.Ldarg_0 || op == CilOpCodes.Ldarg_1 || op == CilOpCodes.Ldarg_2 || op == CilOpCodes.Ldarg_3)
        { if (row.GetParameterIndex() != 0) return false; stack.Push(0); }
        else if (op == CilOpCodes.Stloc || op == CilOpCodes.Stloc_S || op == CilOpCodes.Stloc_0 || op == CilOpCodes.Stloc_1 || op == CilOpCodes.Stloc_2 || op == CilOpCodes.Stloc_3)
        { if (stack.Count == 0) return false; locals[row.GetLocalVariableIndex()] = stack.Pop(); }
        else if (op == CilOpCodes.Ldloc || op == CilOpCodes.Ldloc_S || op == CilOpCodes.Ldloc_0 || op == CilOpCodes.Ldloc_1 || op == CilOpCodes.Ldloc_2 || op == CilOpCodes.Ldloc_3)
        { if (!locals.TryGetValue(row.GetLocalVariableIndex(), out int value)) return false; stack.Push(value); }
        else if (op == CilOpCodes.Ldfld)
        { if (!ReferenceEquals(row.Operand, field) || stack.Count == 0 || stack.Pop() != 0) return false; loads++; stack.Push(1); }
        else if (op == CilOpCodes.Ret)
        { if (!ReferenceEquals(row, body.Instructions[^1]) || stack.Count != 1 || stack.Pop() != 1) return false; returns++; }
        else return false;
    }
    return loads == 1 && returns == 1 && stack.Count == 0;
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
    var owner = app.Assemblies.SelectMany(a => a.Types).Single(t => t.FullName == "Newtonsoft.Json.Serialization.JsonSerializerInternalBase");
    var field = owner.Fields.Single(f => f.Name == "<Serializer>k__BackingField");
    var getter = owner.Properties.Single(p => p.Name == "Serializer").Getter!;
    var setter = owner.Properties.Single(p => p.Name == "Serializer").Setter!;
    var proxy = owner.DeclaringAssembly.Types.Single(t => t.FullName == "Newtonsoft.Json.Serialization.JsonSerializerProxy");
    Check("original private field and Assembly getter preserved", field.Visibility == FieldAttributes.Private
        && getter.Visibility == MethodAttributes.Assembly && setter.Visibility == MethodAttributes.Private
        && getter.UnderlyingPointer == 0x1E6850 && field.Offset == 0x20 && !getter.IsVirtual && !getter.IsStatic);
    Check("owner is nonnested nongeneric reference class without cctor", !owner.IsValueType && owner.DeclaringType == null
        && owner.GenericParameters.Count == 0 && !owner.Methods.Any(m => m.Name == ".cctor"));
    var raw = app.Binary.GetRawBinaryContent(); int at = checked((int)app.Binary.MapVirtualAddressToRaw(getter.UnderlyingPointer));
    var code = raw.Slice(at, 8).ToArray(); nativeHash = Convert.ToHexString(SHA256.HashData(code)).ToLowerInvariant();
    Check("original getter exact native field load and return", Convert.ToHexString(code) == "001040F9C0035FD6");
    Check("public getter route remains distinct and rejects Assembly getter", LegacyArm64LeafAccessors.Find(field, false) == null
        && !LegacyArm64LeafAccessors.IsExactLeaf(field, getter, false));
    Check("private setter remains rejected by public route", !LegacyArm64LeafAccessors.IsExactLeaf(field, setter, true));

    string recoveredPath = Guard("analysis/il2cpp/cpp2il-recovery-nso-virtual-companion-copy-v38/Assembly-CSharp-firstpass.dll");
    recoveredGetterAssemblyHash = Hash(recoveredPath);
    var recovered = ModuleDefinition.FromFile(recoveredPath);
    var recoveredOwner = recovered.GetAllTypes().Single(t => t.FullName == owner.FullName);
    var recoveredGetter = recoveredOwner.Methods.Single(m => m.Name == "get_Serializer");
    var recoveredField = recoveredOwner.Fields.Single(f => f.Name == field.Name);
    var recoveredRows = recoveredGetter.CilMethodBody!.Instructions;
    recoveredGetterFieldLoads = recoveredRows.Count(i => i.OpCode == CilOpCodes.Ldfld && ReferenceEquals(i.Operand, recoveredField));
    Check("current v38 recovered getter retains original Assembly/private metadata", recoveredGetter.IsAssembly && !recoveredGetter.IsStatic
        && !recoveredGetter.IsVirtual && recoveredField.IsPrivate && !recoveredOwner.Methods.Any(m => m.Name == ".cctor"));
    Check("current recovered getter has exact one field read and return with local copies only", recoveredGetterFieldLoads == 1
        && recoveredRows.Count(i => i.OpCode == CilOpCodes.Ret) == 1
        && recoveredRows.All(i => i.OpCode == CilOpCodes.Ldfld || i.OpCode == CilOpCodes.Ret
            || i.OpCode.Code.ToString().StartsWith("Ldarg", StringComparison.Ordinal)
            || i.OpCode.Code.ToString().StartsWith("Ldloc", StringComparison.Ordinal)
            || i.OpCode.Code.ToString().StartsWith("Stloc", StringComparison.Ordinal))
        && recoveredGetter.CilMethodBody.ExceptionHandlers.Count == 0);

    var findApi = typeof(LegacyArm64LeafAccessors).GetMethod("FindAssemblyGetter", BindingFlags.Public | BindingFlags.Static);
    var accessApi = typeof(LegacyArm64LeafAccessors).GetMethod("CanCallAssemblyGetter", BindingFlags.Public | BindingFlags.Static);
    if (baseline)
    {
        Check("immutable v38 baseline has no internal-getter recovery API", findApi == null && accessApi == null);
    }
    else
    {
        Check("new APIs exist", findApi != null && accessApi != null);
        Check("current recovered getter returns exactly original receiver field through local copies", ExactGetterFlow(recoveredGetter, recoveredField));
        MethodAnalysisContext? Find(FieldAnalysisContext f) => (MethodAnalysisContext?)findApi!.Invoke(null, [f]);
        bool Can(FieldAnalysisContext? f, MethodAnalysisContext? m, MethodDefinition? caller) => (bool)accessApi!.Invoke(null, [f, m, caller])!;
        Check("native-only selector returns original unique Assembly getter", ReferenceEquals(Find(field), getter));
        bool Exact(FieldAnalysisContext f, MethodAnalysisContext m) => (bool)typeof(LegacyArm64LeafAccessors)
            .GetMethod("IsExactAssemblyGetter", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, [f, m])!;
        Check("private setter is not an Assembly getter", !Exact(field, setter));
        var oldOffset = field.OverrideOffset;
        try { field.OverrideOffset = field.Offset + 8; Check("wrong native field offset rejects", !Exact(field, getter)); }
        finally { field.OverrideOffset = oldOffset; }
        var cctor = new InjectedMethodAnalysisContext(owner, ".cctor", app.SystemTypes.SystemVoidType, MethodAttributes.Private | MethodAttributes.Static, []);
        try { owner.Methods.Add(cctor); Check("any owner cctor rejects even BeforeFieldInit", !Exact(field, getter)); }
        finally { owner.Methods.Remove(cctor); }
        var genericParameter = app.Assemblies.SelectMany(a => a.Types).SelectMany(t => t.GenericParameters).First();
        try { owner.GenericParameters.Add(genericParameter); Check("generic owner rejects", !Exact(field, getter)); }
        finally { owner.GenericParameters.Remove(genericParameter); }
        var declaringTypeProperty = typeof(TypeAnalysisContext).GetProperty("DeclaringType")!;
        try { declaringTypeProperty.SetValue(owner, proxy); Check("nested owner rejects", !Exact(field, getter)); }
        finally { declaringTypeProperty.SetValue(owner, null); }
        var duplicate = new MethodAnalysisContext(getter.Definition, owner);
        var ambiguousProperty = new InjectedPropertyAnalysisContext("AmbiguousGetterFixture", field.FieldType, duplicate, null, PropertyAttributes.None, owner);
        try
        {
            owner.Properties.Add(ambiguousProperty);
            var freshFieldKey = new FieldAnalysisContext(field.BackingData, owner);
            Check("distinct exact native getter candidates reject instead of choosing first", Find(freshFieldKey) == null);
        }
        finally { owner.Properties.Remove(ambiguousProperty); }
        var modules = new Dictionary<string, ModuleDefinition>(StringComparer.Ordinal);
        foreach (var a in app.Assemblies.Where(a => a.Name is "Assembly-CSharp" or "Assembly-CSharp-firstpass"))
        {
            var outputPath = Guard($"analysis/il2cpp/cpp2il-recovery-nso-virtual-companion-copy-v38/{a.Name}.dll");
            var outputHash = Hash(outputPath);
            modules.Add(a.Name, ModuleDefinition.FromFile(outputPath));
            foreach (var f in a.Types.SelectMany(t => t.Fields).Where(f => f.Visibility == FieldAttributes.Private))
            {
                var m = Find(f); if (m == null) continue;
                var ownerDefinition = modules[a.Name].GetAllTypes().Single(t => t.FullName == f.DeclaringType.FullName);
                var methodDefinition = ownerDefinition.Methods.Single(md => md.Name == m.Name && md.Signature!.ParameterTypes.Count == 0);
                var fieldDefinition = ownerDefinition.Fields.Single(fd => fd.Name == f.Name);
                var rows = methodDefinition.CilMethodBody?.Instructions;
                bool valid = methodDefinition.IsAssembly && !methodDefinition.IsStatic && !methodDefinition.IsVirtual
                    && fieldDefinition.IsPrivate && !ownerDefinition.Methods.Any(md => md.Name == ".cctor")
                    && rows != null && ExactGetterFlow(methodDefinition, fieldDefinition);
                inventory.Add(new { assembly = a.Name, owner = f.DeclaringType.FullName, field = f.Name,
                    getter = m.Name, native_rva = $"0x{m.UnderlyingPointer:X}", valid,
                    output_assembly_sha256 = outputHash });
                Check("eligible getter retains exact current recovered field semantics: " + f.DeclaringType.FullName + "::" + m.Name, valid);
            }
        }
        Check("all-eligible getter inventory includes original Serializer candidate", inventory.Count > 0);

        // Invoke the actual production stub/type/member population stages in memory.
        // No method-body export, serialization, source rewrite, or disk assembly is performed.
        var format = new AsmResolverDllOutputFormatEmpty();
        var stubApi = typeof(AsmResolverDllOutputFormat).GetMethod("BuildStubAssemblies", BindingFlags.Instance | BindingFlags.NonPublic)!;
        stubApi.Invoke(format, [app]);
        foreach (var a in app.Assemblies) AsmResolverAssemblyPopulator.ConfigureHierarchy(a);
        foreach (var a in app.Assemblies) AsmResolverAssemblyPopulator.CopyDataFromIl2CppToManaged(a);
        var assembly = owner.DeclaringAssembly.GetExtraData<AssemblyDefinition>("AsmResolverAssembly")!;
        var ownerType = owner.GetExtraData<TypeDefinition>("AsmResolverType")!;
        var proxyType = proxy.GetExtraData<TypeDefinition>("AsmResolverType")!;
        var target = getter.GetExtraData<MethodDefinition>("AsmResolverMethod")!;
        var fieldDef = field.GetExtraData<FieldDefinition>("AsmResolverField")!;
        var caller = proxy.Methods.First(m => m.Name == ".ctor").GetExtraData<MethodDefinition>("AsmResolverMethod")!;
        Check("real output attachment identities are consistent", ReferenceEquals(caller.DeclaringModule!.Assembly, assembly)
            && ReferenceEquals(target.DeclaringType, ownerType) && ReferenceEquals(target.DeclaringModule!.Assembly, assembly)
            && ReferenceEquals(fieldDef.DeclaringType, ownerType));
        MethodDefinition FlowFixture(string name, params CilInstruction[] rows)
        {
            var method = new MethodDefinition(name, AMethod.Assembly, MethodSignature.CreateInstance(field.FieldType.ToTypeSignature()));
            ownerType.Methods.Add(method); method.CilMethodBody = new CilMethodBody();
            foreach (var row in rows) method.CilMethodBody.Instructions.Add(row);
            return method;
        }
        Check("getter dataflow control accepts direct field return", ExactGetterFlow(FlowFixture("DirectReturnFixture",
            new(CilOpCodes.Ldarg_0), new(CilOpCodes.Ldfld, fieldDef), new(CilOpCodes.Ret)), fieldDef));
        Check("getter dataflow rejects returning receiver instead of field", !ExactGetterFlow(FlowFixture("WrongReturnFixture",
            new(CilOpCodes.Ldarg_0), new(CilOpCodes.Stloc_0), new(CilOpCodes.Ldarg_0), new(CilOpCodes.Ldfld, fieldDef),
            new(CilOpCodes.Stloc_1), new(CilOpCodes.Ldloc_0), new(CilOpCodes.Ret)), fieldDef));
        Check("getter dataflow rejects uninitialized result", !ExactGetterFlow(FlowFixture("UninitializedReturnFixture",
            new(CilOpCodes.Ldarg_0), new(CilOpCodes.Ldfld, fieldDef), new(CilOpCodes.Stloc_1), new(CilOpCodes.Ldloc_0), new(CilOpCodes.Ret)), fieldDef));
        Check("getter dataflow rejects another argument as receiver", !ExactGetterFlow(FlowFixture("WrongArgumentFixture",
            new(CilOpCodes.Ldarg_1), new(CilOpCodes.Ldfld, fieldDef), new(CilOpCodes.Ret)), fieldDef));
        Check("getter dataflow rejects address load", !ExactGetterFlow(FlowFixture("AddressArgumentFixture",
            new(CilOpCodes.Ldarga_S, (byte)0), new(CilOpCodes.Ldfld, fieldDef), new(CilOpCodes.Ret)), fieldDef));
        Check("real same-assembly original caller is accessible", Can(field, getter, caller));
        Check("original getter recursion rejects", !Can(field, getter, target));
        Check("same owner other method remains a field access", !Can(field, getter, setter.GetExtraData<MethodDefinition>("AsmResolverMethod")));
        Check("null caller/field/getter reject", !Can(field, getter, null) && !Can(null, getter, caller) && !Can(field, null, caller));
        var detached = new MethodDefinition("Detached", AMethod.Public | AMethod.Static, MethodSignature.CreateStatic(assembly.ManifestModule!.CorLibTypeFactory.Void));
        Check("detached method rejects", !Can(field, getter, detached));
        var sameName = new AssemblyDefinition(assembly.Name, assembly.Version);
        var otherModule = new ModuleDefinition(assembly.ManifestModule.Name); sameName.Modules.Add(otherModule);
        var otherType = new TypeDefinition(proxyType.Namespace, proxyType.Name, AType.Public, otherModule.CorLibTypeFactory.Object.Type); otherModule.TopLevelTypes.Add(otherType);
        otherType.Methods.Add(detached);
        Check("same-name distinct assembly object rejects", !ReferenceEquals(sameName, assembly) && !Can(field, getter, detached));
        var crossAssemblyCaller = app.GetAssemblyByName("Assembly-CSharp")!.Types.First(t => t.Methods.Count > 0).Methods[0].GetExtraData<MethodDefinition>("AsmResolverMethod")!;
        Check("real different output assembly rejects", !Can(field, getter, crossAssemblyCaller));
        Check("non-Assembly private setter rejects", !Can(field, setter, caller));
        var oldGetter = getter.OverrideAttributes;
        try
        {
            foreach (var visibility in new[] { MethodAttributes.Public, MethodAttributes.Private, MethodAttributes.Family, MethodAttributes.FamORAssem, MethodAttributes.FamANDAssem })
            {
                getter.Attributes = (getter.Attributes & ~MethodAttributes.MemberAccessMask) | visibility;
                Check("non-Assembly getter rejects: " + visibility, !Can(field, getter, caller));
            }
        }
        finally { getter.OverrideAttributes = oldGetter; }
        var attachedTarget = getter.GetExtraData<MethodDefinition>("AsmResolverMethod");
        try { getter.PutExtraData<MethodDefinition>("AsmResolverMethod", null!); Check("missing target attachment rejects", !Can(field, getter, caller)); }
        finally { getter.PutExtraData("AsmResolverMethod", attachedTarget!); }
        try { owner.PutExtraData<TypeDefinition>("AsmResolverType", null!); Check("missing owner attachment rejects", !Can(field, getter, caller)); }
        finally { owner.PutExtraData("AsmResolverType", ownerType); }
        try { field.PutExtraData<FieldDefinition>("AsmResolverField", null!); Check("missing field attachment rejects", !Can(field, getter, caller)); }
        finally { field.PutExtraData("AsmResolverField", fieldDef); }
        try { owner.DeclaringAssembly.PutExtraData("AsmResolverAssembly", sameName); Check("wrong same-name owner assembly attachment rejects", !Can(field, getter, caller)); }
        finally { owner.DeclaringAssembly.PutExtraData("AsmResolverAssembly", assembly); }
        try { ownerType.Methods.Remove(target); Check("detached target definition rejects", !Can(field, getter, caller)); }
        finally { ownerType.Methods.Add(target); }
        try { proxyType.Methods.Remove(caller); Check("original caller detached from its type rejects", !Can(field, getter, caller)); }
        finally { proxyType.Methods.Add(caller); }
        var targetAttributes = target.Attributes;
        try { target.Attributes = (target.Attributes & ~AMethod.MemberAccessMask) | AMethod.Public; Check("output method visibility mismatch rejects", !Can(field, getter, caller)); }
        finally { target.Attributes = targetAttributes; }
        var signature = target.Signature;
        try { target.Signature = MethodSignature.CreateInstance(assembly.ManifestModule!.CorLibTypeFactory.Int32); Check("output return signature mismatch rejects", !Can(field, getter, caller)); }
        finally { target.Signature = signature; }
        var attachedCctor = new MethodDefinition(".cctor", AMethod.Private | AMethod.Static | AMethod.SpecialName | AMethod.RuntimeSpecialName,
            MethodSignature.CreateStatic(assembly.ManifestModule!.CorLibTypeFactory.Void));
        try { ownerType.Methods.Add(attachedCctor); Check("attached output-only owner cctor rejects", !Can(field, getter, caller)); }
        finally { ownerType.Methods.Remove(attachedCctor); }
        Check("positive after negative caller sites is not poisoned by cache", ReferenceEquals(Find(field), getter) && Can(field, getter, caller));

        MethodDefinition Emit(string name, bool store, bool cross = false)
        {
            var context = new InjectedMethodAnalysisContext(proxy, name, store ? app.SystemTypes.SystemVoidType : field.FieldType,
                MethodAttributes.Public | MethodAttributes.Static, store ? [owner, field.FieldType] : [owner], store ? ["receiver", "value"] : ["receiver"]);
            var receiver = new LocalVariable("receiver", new Register(null, "X0", 0), owner);
            var value = new LocalVariable("value", new Register(null, "X1", 0), field.FieldType);
            context.ParameterLocals.Add(receiver); context.Locals.Add(receiver);
            if (store) { context.ParameterLocals.Add(value); context.Locals.Add(value); }
            var reference = new FieldReference(field, receiver, 0);
            context.ControlFlowGraph = new ISILControlFlowGraph(store ? [new Instruction(0, IOp.Move, reference, value), new Instruction(1, IOp.Return)] : [new Instruction(0, IOp.Return, reference)]);
            var module = cross ? otherModule : assembly.ManifestModule!;
            var definition = new MethodDefinition(name, AMethod.Public | AMethod.Static,
                MethodSignature.CreateStatic(store ? module.CorLibTypeFactory.Void : field.FieldType.ToTypeSignature(),
                    store ? [owner.ToTypeSignature(), field.FieldType.ToTypeSignature()] : [owner.ToTypeSignature()]));
            definition.Parameters[0].GetOrCreateDefinition().Name = "receiver";
            if (store) definition.Parameters[1].GetOrCreateDefinition().Name = "value";
            (cross ? otherType : proxyType).Methods.Add(definition);
            IlGenerator.GenerateIl(context, definition); return definition;
        }
        var load = Emit("AssemblyLeafLoad", false); var store = Emit("AssemblyLeafStoreUnchanged", true); var foreign = Emit("ForeignLoadUnchanged", false, true);
        Check("real emitter replaces eligible private field read with exact direct internal Call", load.CilMethodBody!.Instructions.Count(i => i.OpCode == CilOpCodes.Call && ReferenceEquals(i.Operand, target)) == 1
            && !load.CilMethodBody.Instructions.Any(i => i.OpCode == CilOpCodes.Ldfld || i.OpCode == CilOpCodes.Callvirt || i.OpCode == CilOpCodes.Ldstr));
        Check("real emitter leaves private field stores unchanged", store.CilMethodBody!.Instructions.Count(i => i.OpCode == CilOpCodes.Stfld && ReferenceEquals(i.Operand, fieldDef)) == 1
            && !store.CilMethodBody.Instructions.Any(i => i.OpCode == CilOpCodes.Call));
        Check("real emitter leaves cross-assembly private field read unchanged", foreign.CilMethodBody!.Instructions.Count(i => i.OpCode == CilOpCodes.Ldfld) == 1
            && !foreign.CilMethodBody.Instructions.Any(i => i.OpCode == CilOpCodes.Call));
        foreach (var emitted in new[] { load, store, foreign }) emissions.Add(new { name = emitted.Name?.ToString(), opcodes = emitted.CilMethodBody!.Instructions.Select(i => i.OpCode.ToString()) });
        Check("original output metadata flags remain unchanged", field.Visibility == FieldAttributes.Private && getter.Visibility == MethodAttributes.Assembly
            && fieldDef.IsPrivate && target.IsAssembly && !owner.Methods.Any(m => m.Name == ".cctor"));
    }
}
catch (Exception error) { fatal = error.ToString(); }
var report = new { status = fatal == null ? baseline ? "PASS_BASELINE_PUBLIC_ONLY_LEAF_ROUTE_REJECTS_INTERNAL_GETTER" : "PASS_ASSEMBLY_LEAF_GETTER_NATIVE_ACCESSIBILITY_AND_EMISSION_CONTRACT" : "ASSEMBLY_LEAF_GETTER_CONTRACT_FAILED",
    checks = checks.Count, tests = checks, fatal, baseline, core_sha256 = Hash(typeof(Cpp2IlApi).Assembly.Location),
    probe_source_sha256 = Hash(Guard("src/re/AssemblyLeafAccessorContractProbe/Program.cs")), native_getter_sha256 = nativeHash,
    recovered_getter_run = "nso-virtual-companion-copy-v38", recovered_getter_assembly_sha256 = recoveredGetterAssemblyHash,
    recovered_getter_field_loads = recoveredGetterFieldLoads, eligible_getter_inventory = inventory, emitted = emissions,
    original_game_methods_executed = 0, original_game_metadata_modified = false, production_outputs_written = false,
    scope = "Original input/native/getter metadata and current recovered CIL are read-only. Baseline distinguishes public-only rejection. New API fixtures populate actual production stub/type/member attachment stages in memory, then test caller assembly object identity and real emitter instructions. Temporary in-process metadata-attribute/attachment negatives are restored; no game code is executed, no private flags are widened and no static/setter/aggregate recovery is asserted." };
File.WriteAllText(Guard(baseline ? "reports/assembly-leaf-accessor-contract-v39-baseline.json" : "reports/assembly-leaf-accessor-contract-v39.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { report.status, report.checks, fatal }));
return fatal == null ? 0 : 2;
