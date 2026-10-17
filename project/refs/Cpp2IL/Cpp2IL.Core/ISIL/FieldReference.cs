using System.Linq;
using Cpp2IL.Core.Model.Contexts;

namespace Cpp2IL.Core.ISIL;

public class FieldReference : IOperand
{
    public readonly FieldAnalysisContext Field;
    public readonly FieldAnalysisContext[] Path;
    public LocalVariable Local;
    public int Offset;

    public FieldReference(FieldAnalysisContext field, LocalVariable local, int offset)
        : this([field], local, offset) { }

    public FieldReference(FieldAnalysisContext[] path, LocalVariable local, int offset)
    {
        Path = path;
        Field = path[^1];
        Local = local;
        Offset = offset;
    }

    public override string ToString() => $"{Local.Name}.{string.Join(".", Path.Select(f => f.Name))} ({Field.FieldType.FullName})";
}
