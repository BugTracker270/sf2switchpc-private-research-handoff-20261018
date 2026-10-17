using System.Security.Cryptography;
using System.Text.Json;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

if (args.Length != 1) throw new ArgumentException("USB root required");
string root = Path.GetFullPath(args[0]).TrimEnd(Path.DirectorySeparatorChar);
const string run = "nso-assembly-leaf-getter-v39", baseline = "nso-virtual-companion-copy-v38";
string Guard(string relative) { string p = Path.GetFullPath(Path.Combine(root, relative)); if (!p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Outside USB"); for (DirectoryInfo? d = new(Path.GetDirectoryName(p)!); d != null; d = d.Parent) if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse point"); return p; }
string Hash(string relative) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Guard(relative)))).ToLowerInvariant();
var tests = new List<object>(); var getters = new List<object>(); var constructors = new List<object>(); var privateDetails = new List<object>(); string? fatal = null;
void Check(string name, bool pass) { tests.Add(new { name, passed = pass }); if (!pass) throw new InvalidDataException(name); }
bool ExactGetterFlow(MethodDefinition method, FieldDefinition field)
{
    var body = method.CilMethodBody; if (body == null || body.ExceptionHandlers.Count != 0 || method.IsStatic || method.Signature?.ParameterTypes.Count != 0) return false;
    var stack = new Stack<int>(); var locals = new Dictionary<int, int>(); int loads = 0, returns = 0;
    foreach (var row in body.Instructions)
    {
        string op = row.OpCode.Code.ToString();
        if (op is "Ldarg" or "Ldarg_S" or "Ldarg_0" or "Ldarg_1" or "Ldarg_2" or "Ldarg_3") { if (row.GetParameterIndex() != 0) return false; stack.Push(0); }
        else if (op is "Stloc" or "Stloc_S" or "Stloc_0" or "Stloc_1" or "Stloc_2" or "Stloc_3") { if (stack.Count == 0) return false; locals[row.GetLocalVariableIndex()] = stack.Pop(); }
        else if (op is "Ldloc" or "Ldloc_S" or "Ldloc_0" or "Ldloc_1" or "Ldloc_2" or "Ldloc_3") { if (!locals.TryGetValue(row.GetLocalVariableIndex(), out int value)) return false; stack.Push(value); }
        else if (row.OpCode == CilOpCodes.Ldfld) { if (!ReferenceEquals(row.Operand, field) || stack.Count == 0 || stack.Pop() != 0) return false; loads++; stack.Push(1); }
        else if (row.OpCode == CilOpCodes.Ret) { if (!ReferenceEquals(row, body.Instructions[^1]) || stack.Count != 1 || stack.Pop() != 1) return false; returns++; }
        else return false;
    }
    return loads == 1 && returns == 1 && stack.Count == 0;
}
List<string> Normalize(MethodDefinition method)
{
    var body = method.CilMethodBody!; var rows = new List<string>(); body.Instructions.CalculateOffsets();
    foreach (var row in body.Instructions)
    {
        string op = row.OpCode.Code.ToString();
        if (op is "Ldarg" or "Ldarg_S" or "Ldarg_0" or "Ldarg_1" or "Ldarg_2" or "Ldarg_3") rows.Add("Ldarg:" + row.GetParameterIndex());
        else if (op is "Ldloc" or "Ldloc_S" or "Ldloc_0" or "Ldloc_1" or "Ldloc_2" or "Ldloc_3") rows.Add("Ldloc:" + row.GetLocalVariableIndex());
        else if (op is "Stloc" or "Stloc_S" or "Stloc_0" or "Stloc_1" or "Stloc_2" or "Stloc_3") rows.Add("Stloc:" + row.GetLocalVariableIndex());
        else if (row.Operand is ICilLabel label) rows.Add(op.Replace("_S", "", StringComparison.Ordinal) + ":row" + body.Instructions.ToList().FindIndex(i => i.Offset == label.Offset));
        else if (row.Operand is IEnumerable<ICilLabel> labels) rows.Add(op + ":rows" + string.Join(",", labels.Select(label => body.Instructions.ToList().FindIndex(i => i.Offset == label.Offset))));
        else rows.Add(op + ":" + row.Operand?.ToString());
    }
    return rows;
}
string Shape(MethodDefinition method)
{
    var body = method.CilMethodBody!; var indices = body.Instructions.ToList();
    int Index(ICilLabel? label) => label == null ? -1 : label.Offset == body.Instructions.EndLabel.Offset ? indices.Count : indices.FindIndex(row => row.Offset == label.Offset);
    return JsonSerializer.Serialize(new { method.Attributes, signature = method.Signature?.ToString(), locals = body.LocalVariables.Select(l => new { type = l.VariableType.FullName, kind = l.VariableType.ElementType.ToString(), complete_signature = l.VariableType.ToString() }), body.InitializeLocals, body.MaxStack,
        handlers = body.ExceptionHandlers.Select(h => new { h.HandlerType, try_start = Index(h.TryStart), try_end = Index(h.TryEnd), handler_start = Index(h.HandlerStart), handler_end = Index(h.HandlerEnd), filter = Index(h.FilterStart), catch_type = h.ExceptionType?.FullName }) });
}
try
{
    using var contract = JsonDocument.Parse(File.ReadAllText(Guard("reports/assembly-leaf-accessor-contract-v39.json")));
    using var production = JsonDocument.Parse(File.ReadAllText(Guard("reports/assembly-leaf-accessor-production-v39.json")));
    Check("frozen78/15 original native/accessibility/emission contracts pass", contract.RootElement.GetProperty("status").GetString() == "PASS_ASSEMBLY_LEAF_GETTER_NATIVE_ACCESSIBILITY_AND_EMISSION_CONTRACT" && contract.RootElement.GetProperty("checks").GetInt32() == 78 && production.RootElement.GetProperty("status").GetString() == "PASS_ACTUAL_ORIGINAL_CONSTRUCTOR_RECEIVER_AND_ASSEMBLY_GETTER_EMISSION" && production.RootElement.GetProperty("checks").GetInt32() == 15);
    Check("both contracts bind exact v39 Core", contract.RootElement.GetProperty("core_sha256").GetString() == "52e9fa40275b71be5ea48e1bab1816e59dc4412ddfc0c627c29345f3086a4929" && production.RootElement.GetProperty("core_sha256").GetString() == contract.RootElement.GetProperty("core_sha256").GetString());
    var modules = new Dictionary<(string Run, string Assembly), ModuleDefinition>();
    ModuleDefinition Module(string recovery, string name) { var key = (recovery, name); if (!modules.TryGetValue(key, out var value)) modules.Add(key, value = ModuleDefinition.FromFile(Guard($"analysis/il2cpp/cpp2il-recovery-{recovery}/{name}.dll"))); return value; }
    foreach (var item in contract.RootElement.GetProperty("eligible_getter_inventory").EnumerateArray())
    {
        string assembly = item.GetProperty("assembly").GetString()!, owner = item.GetProperty("owner").GetString()!, fieldName = item.GetProperty("field").GetString()!, getterName = item.GetProperty("getter").GetString()!;
        Check("immutable selected getter baseline assembly hash", Hash($"analysis/il2cpp/cpp2il-recovery-{baseline}/{assembly}.dll") == item.GetProperty("output_assembly_sha256").GetString());
        var previousType = Module(baseline, assembly).GetAllTypes().Single(t => t.FullName == owner); var currentType = Module(run, assembly).GetAllTypes().Single(t => t.FullName == owner);
        var previousField = previousType.Fields.Single(f => f.Name == fieldName); var currentField = currentType.Fields.Single(f => f.Name == fieldName);
        var previous = previousType.Methods.Single(m => m.Name == getterName && m.Signature!.ParameterTypes.Count == 0); var current = currentType.Methods.Single(m => m.Name == getterName && m.Signature!.ParameterTypes.Count == 0);
        Check("fresh getter keeps original Assembly/private/no-cctor/nongeneric/nonnested contract: " + owner + "::" + getterName,
            current.IsAssembly && !current.IsStatic && !current.IsVirtual && !current.IsAbstract && currentType.DeclaringType == null && currentType.GenericParameters.Count == 0 && !currentType.Methods.Any(m => m.Name == ".cctor") && currentField.IsPrivate && !currentField.IsStatic && SignatureComparer.Default.Equals(current.Signature!.ReturnType, currentField.Signature!.FieldType));
        Check("fresh getter exactly returns same receiver field through local copies: " + owner + "::" + getterName, ExactGetterFlow(previous, previousField) && ExactGetterFlow(current, currentField));
        Check("fresh getter retains complete prior instructions/locals/init/maxstack/EH: " + owner + "::" + getterName, Normalize(previous).SequenceEqual(Normalize(current)) && Shape(previous) == Shape(current) && previousField.Attributes == currentField.Attributes);
        getters.Add(new { assembly, owner, field = fieldName, getter = getterName, original_native_rva = item.GetProperty("native_rva").GetString(), current_getter_token = current.MetadataToken.ToString(), instructions = current.CilMethodBody!.Instructions.Count, exact_original_field_flow = true, original_flags_preserved = true });
    }
    Check("all27 original selected getters examined", getters.Count == 27);
    const string firstpass = "Assembly-CSharp-firstpass", fieldOwner = "Newtonsoft.Json.Serialization.JsonSerializerInternalBase", proxy = "Newtonsoft.Json.Serialization.JsonSerializerProxy";
    var oldOwner = Module(baseline, firstpass).GetAllTypes().Single(t => t.FullName == fieldOwner); var newOwner = Module(run, firstpass).GetAllTypes().Single(t => t.FullName == fieldOwner);
    var oldField = oldOwner.Fields.Single(f => f.Name == "<Serializer>k__BackingField"); var newField = newOwner.Fields.Single(f => f.Name == "<Serializer>k__BackingField"); var newGetter = newOwner.Methods.Single(m => m.Name == "get_Serializer");
    foreach (var item in production.RootElement.GetProperty("methods").EnumerateArray())
    {
        string parameterType = item.GetProperty("original_parameter_type").GetString()!;
        MethodDefinition Ctor(string recovery) => Module(recovery, firstpass).GetAllTypes().Single(t => t.FullName == proxy).Methods.Single(m => m.Name == ".ctor" && m.Signature!.ParameterTypes.Count == 1 && m.Signature.ParameterTypes[0].FullName == parameterType);
        var previous = Ctor(baseline); var current = Ctor(run); var before = previous.CilMethodBody!.Instructions; var after = current.CilMethodBody!.Instructions;
        Check("fresh original constructor exactly substitutes its own internal getter: " + parameterType, before.Count(i => i.OpCode == CilOpCodes.Ldfld && ReferenceEquals(i.Operand, oldField)) == 1 && after.Count(i => i.OpCode == CilOpCodes.Call && ReferenceEquals(i.Operand, newGetter)) == 1 && !after.Any(i => i.OpCode == CilOpCodes.Ldfld && ReferenceEquals(i.Operand, newField)));
        var left = Normalize(previous); var right = Normalize(current); var changes = Enumerable.Range(0, Math.Min(left.Count, right.Count)).Where(i => left[i] != right[i]).ToArray();
        Check("all other fresh constructor rows preserve original control/effect/operands: " + parameterType, left.Count == right.Count && changes.Length == 1 && before[changes[0]].OpCode == CilOpCodes.Ldfld && ReferenceEquals(before[changes[0]].Operand, oldField) && after[changes[0]].OpCode == CilOpCodes.Call && ReferenceEquals(after[changes[0]].Operand, newGetter) && left.Count - 1 == item.GetProperty("unchanged_other_instruction_rows").GetInt32());
        Check("fresh constructor full local/init/maxstack/EH/signature shape remains exact: " + parameterType, Shape(previous) == Shape(current));
        privateDetails.Add(new { parameter_type = parameterType, before = left, after = right, changed_rows = changes });
        constructors.Add(new { parameter_type = parameterType, original_native_rva = item.GetProperty("original_native_rva").GetString(), current_method_token = current.MetadataToken.ToString(), changed_instruction_rows = changes.Length, unchanged_instruction_rows = left.Count - 1, original_receiver_sequence_preserved = true, body_shape_unchanged = true });
    }
    Check("both original constructors compared", constructors.Count == 2);
}
catch (Exception error) { fatal = error.ToString(); }
string privatePath = "analysis/reconstruction/assembly-leaf-v39/fresh-output-cil-comparison.json"; Directory.CreateDirectory(Path.GetDirectoryName(Guard(privatePath))!); File.WriteAllText(Guard(privatePath), JsonSerializer.Serialize(privateDetails, new JsonSerializerOptions { WriteIndented = true }) + "\n");
string status = fatal == null ? "PASS_FRESH_ORIGINAL_ASSEMBLY_GETTERS_AND_CONSTRUCTOR_CALL_CORRELATION" : "FRESH_ASSEMBLY_GETTER_CIL_CORRELATION_FAILED";
var report = new { status, recovery_run = run, baseline_run = baseline, checks = tests.Count, tests, getters, constructors, selected_getters = getters.Count, actual_constructors = constructors.Count, fatal,
    source_sha256 = Hash("src/re/RecoveredAssemblyLeafProbe/Program.cs"), contract_report_sha256 = Hash("reports/assembly-leaf-accessor-contract-v39.json"), production_report_sha256 = Hash("reports/assembly-leaf-accessor-production-v39.json"), invocation_report_sha256 = Hash($"logs/cpp2il-{run}-result.json"),
    baseline_main_sha256 = Hash($"analysis/il2cpp/cpp2il-recovery-{baseline}/Assembly-CSharp.dll"), baseline_firstpass_sha256 = Hash($"analysis/il2cpp/cpp2il-recovery-{baseline}/Assembly-CSharp-firstpass.dll"), actual_main_sha256 = Hash($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp.dll"), actual_firstpass_sha256 = Hash($"analysis/il2cpp/cpp2il-recovery-{run}/Assembly-CSharp-firstpass.dll"),
    private_cil_comparison = privatePath, private_cil_sha256 = Hash(privatePath), core_dependency_loaded = false, recovered_game_methods_invoked = 0, constructors_invoked = 0, original_cil_modified = false, metadata_flags_changed = false, tokens_remapped = 0, full_clean_decompile_ready = false,
    scope = "Offline AsmResolver metadata/CIL inspection of fresh complete v39 output. All27 native-selected internal getters must retain exact receiver-to-original-private-field-to-return value flow with no extra effects/EH or owner .cctor; two original proxy constructors must differ from immutable v38 only at exactly one private field load becoming the existing same-assembly nonvirtual getter Call. Argument/local macros and branch labels are normalized by exact index; all remaining operand identities, local type/pinning signatures, MaxStack, InitLocals and EH shape remain exact. Original code is never loaded for execution or rewritten; no whole-game behavior or compilation success is claimed." };
File.WriteAllText(Guard($"reports/recovered-assembly-leaves-{run}.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n"); Console.WriteLine(JsonSerializer.Serialize(new { status, checks = tests.Count, getters = getters.Count, constructors = constructors.Count, fatal })); return fatal == null ? 0 : 2;
