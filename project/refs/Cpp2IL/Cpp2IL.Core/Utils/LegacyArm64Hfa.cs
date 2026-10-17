using System;
using System.Collections.Generic;
using System.Linq;
using Cpp2IL.Core.ISIL;
using Cpp2IL.Core.Model.Contexts;
using LibCpp2IL.NintendoSwitch;

namespace Cpp2IL.Core.Utils;

/// <summary>Opt-in metadata-validated HFA recovery; retains one managed value per aggregate.</summary>
public static class LegacyArm64Hfa
{
    private static int vectorWitnessLogged;
    public sealed record Leaf(FieldAnalysisContext[] Path, long Offset)
    {
        public TypeAnalysisContext FieldType => Path[^1].FieldType;
    }
    public sealed record Shape(TypeAnalysisContext Type, Leaf[] Fields);
    public sealed record Binding(Register Aggregate, Shape Shape, Register[] Components);

    public static bool Enabled(MethodAnalysisContext method) =>
        Environment.GetEnvironmentVariable("CPP2IL_LEGACY_HFA") == "1"
        && method.AppContext.Binary is NsoFile && method.AppContext.MetadataVersion == 24f;

    public static Shape? Describe(TypeAnalysisContext type)
    {
        if (!type.IsValueType || type.IsEnumType || type is ByRefTypeAnalysisContext
            || type.FullName is "System.Single" or "System.Double") return null;
        var leaves = new List<Leaf>();
        if (!Gather(type, [], 0, leaves, new HashSet<TypeAnalysisContext>(), 0)) return null;
        var fields = leaves.OrderBy(field => field.Offset).ToArray();
        if (fields.Length is < 1 or > 4) return null;
        var name = fields[0].FieldType.FullName;
        var size = name == "System.Single" ? 4 : name == "System.Double" ? 8 : 0;
        if (type.FullName == "UnityEngine.Vector3" && System.Threading.Interlocked.Exchange(ref vectorWitnessLogged, 1) == 0)
            Console.Error.WriteLine($"HFA Vector3 metadata: unboxed size={TypeSizes.UnboxedSize(type, 8)}; fields={string.Join(",", fields.Select(field => $"{string.Join(".", field.Path.Select(part => part.Name))}:{field.Offset}:{field.FieldType.FullName}"))}");
        if (size == 0 || fields.Any(field => field.FieldType.FullName != name)
            // LibCpp2IL has already removed the boxed object header from
            // value-type field offsets. Synthetic aggregate values are unboxed.
            || fields.Where((field, index) => field.Offset != index * size).Any()
            || TypeSizes.UnboxedSize(type, 8) != size * fields.Length) return null;
        return new Shape(type, fields);
    }

    private static bool Gather(TypeAnalysisContext type, FieldAnalysisContext[] prefix, long offset,
        List<Leaf> leaves, HashSet<TypeAnalysisContext> active, int depth)
    {
        if (depth > 12 || type.Definition == null || !type.IsValueType || type.IsEnumType
            || type.Definition.PackingSize != 0
            || (type.Attributes & System.Reflection.TypeAttributes.LayoutMask) == System.Reflection.TypeAttributes.ExplicitLayout
            || !active.Add(type)) return false;
        try
        {
            var fields = type.Fields.Where(field => !field.IsStatic).ToArray();
            if (fields.Length == 0) return false;
            foreach (var field in fields)
            {
                if (field.Offset < 0) return false;
                var path = prefix.Concat(new[] { field }).ToArray();
                if (field.FieldType.FullName is "System.Single" or "System.Double")
                    leaves.Add(new Leaf(path, offset + field.Offset));
                else if (!Gather(field.FieldType, path, offset + field.Offset, leaves, active, depth + 1))
                    return false;
                if (leaves.Count > 4) return false;
            }
            // A nested structure must have the same storage extent as its
            // recursively flattened leaves; padding/overlap cannot create an HFA.
            var own = leaves.Where(leaf => leaf.Path.Length > prefix.Length
                && leaf.Path.Take(prefix.Length).SequenceEqual(prefix)).ToArray();
            if (own.Length == 0) return false;
            var elementName = own[0].FieldType.FullName;
            var size = elementName == "System.Single" ? 4 : 8;
            return own.All(leaf => leaf.FieldType.FullName == elementName)
                && own.OrderBy(leaf => leaf.Offset).Select((leaf, i) => leaf.Offset == offset + i * size).All(value => value)
                && TypeSizes.UnboxedSize(type, 8) == own.Length * size;
        }
        finally { active.Remove(type); }
    }

    public static Shape? ReturnShape(MethodAnalysisContext method) =>
        Enabled(method) && !method.IsVoid ? Describe(method.ReturnType) : null;

    public static Register ReturnValue(MethodAnalysisContext method, ulong? callSite = null) =>
        new(null, callSite.HasValue ? $"HFA_CALL_RESULT_{callSite.Value:X}" : "HFA_OWN_RETURN");

    public static (IOperand[] Arguments, List<Binding> Bindings) Resolve(MethodAnalysisContext method, ulong? callSite = null)
    {
        var arguments = new List<IOperand>();
        var bindings = new List<Binding>();
        int integer = method.IsStatic ? 1 : 0, floating = 0, stack = 0;
        void Ordinary(bool fp)
        {
            if (fp && floating < 8) arguments.Add(new Register(null, $"V{floating++}"));
            else if (!fp && integer < 8) arguments.Add(new Register(null, $"X{integer++}"));
            else { arguments.Add(new StackOffset(stack)); stack += 8; }
        }
        if (!method.IsStatic) Ordinary(false);
        for (int index = 0; index < method.Parameters.Count; index++)
        {
            var type = method.Parameters[index].ParameterType;
            if (Describe(type) is not { } shape)
            {
                Ordinary(BaseCallingConventionResolver.IsFloatingPoint(type));
                continue;
            }
            if (floating + shape.Fields.Length > 8)
                throw new DecompilerException("HFA stack spill requires explicit aggregate stack recovery");
            var value = new Register(null, callSite.HasValue ? $"HFA_CALL_{callSite.Value:X}_ARG_{index}" : $"HFA_PARAM_{index}");
            var components = Enumerable.Range(floating, shape.Fields.Length).Select(reg => new Register(null, $"V{reg}")).ToArray();
            arguments.Add(value); bindings.Add(new Binding(value, shape, components)); floating += components.Length;
        }
        Ordinary(false); // Legacy MethodInfo follows the real arguments.
        return (arguments.ToArray(), bindings);
    }

    public static IEnumerable<(IOperand Destination, IOperand Source)> Copies(Binding binding, bool pack)
    {
        for (int i = 0; i < binding.Components.Length; i++)
        {
            var leaf = binding.Shape.Fields[i];
            var field = new MemoryOperand(binding.Aggregate, addend: leaf.Offset)
            {
                ScalarFloatingSize = leaf.FieldType.FullName == "System.Single" ? 4 : 8
            };
            yield return pack ? (field, binding.Components[i]) : (binding.Components[i], field);
        }
    }

    public static Binding ReturnBinding(MethodAnalysisContext method, ulong? callSite = null)
    {
        var shape = ReturnShape(method) ?? throw new DecompilerException("Missing HFA result shape");
        return new Binding(ReturnValue(method, callSite), shape,
            Enumerable.Range(0, shape.Fields.Length).Select(reg => new Register(null, $"V{reg}")).ToArray());
    }
}
