using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace Cpp2IL.Core;

/// <summary>Explicit lowering of separate native reference allocation, without running an instance constructor.</summary>
public static class UninitializedObjectAllocation
{
    public static void Emit(MethodDefinition method, ITypeDefOrRef allocatedType)
    {
        var factory = method.DeclaringModule!.CorLibTypeFactory;
        var scope = factory.CorLibScope;
        var systemType = scope.CreateTypeReference("System", "Type");
        var handle = scope.CreateTypeReference("System", "RuntimeTypeHandle");
        var fromHandle = systemType.CreateMemberReference("GetTypeFromHandle",
            MethodSignature.CreateStatic(systemType.ToTypeSignature(false), [handle.ToTypeSignature(true)]));
        var allocate = scope.CreateTypeReference("System.Runtime.Serialization", "FormatterServices")
            .CreateMemberReference("GetUninitializedObject",
                MethodSignature.CreateStatic(factory.Object, [systemType.ToTypeSignature(false)]));
        var instructions = method.CilMethodBody!.Instructions;
        instructions.Add(CilOpCodes.Ldtoken, allocatedType);
        instructions.Add(CilOpCodes.Call, fromHandle);
        instructions.Add(CilOpCodes.Call, allocate);
        instructions.Add(CilOpCodes.Castclass, allocatedType);
    }
}
