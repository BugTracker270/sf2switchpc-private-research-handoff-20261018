using System.Reflection;
using System.Reflection.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using Cpp2IL.Core;

public static class AllocationEmissionChecks
{
    public static int Run()
    {
        var module = new ModuleDefinition("AllocationLoweringFixture.dll");
        var assembly = new AssemblyDefinition("AllocationLoweringFixture", new Version(1, 0));
        assembly.Modules.Add(module);
        var owner = new TypeDefinition("Fixtures", "Factory", AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes.Public,
            module.CorLibTypeFactory.Object.Type);
        module.TopLevelTypes.Add(owner);
        var target = module.DefaultImporter.ImportType(typeof(AllocationFixture));
        var method = new MethodDefinition("Allocate", AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Public |
            AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes.Static,
            MethodSignature.CreateStatic(target.ToTypeSignature(false)));
        owner.Methods.Add(method);
        method.CilMethodBody = new CilMethodBody { ComputeMaxStackOnBuild = true };
        UninitializedObjectAllocation.Emit(method, target);
        method.CilMethodBody.Instructions.Add(CilOpCodes.Ret);
        using var bytes = new MemoryStream();
        module.Write(bytes);
        var loaded = Assembly.Load(bytes.ToArray());
        AllocationFixture.ConstructorCalls = 0;
        var value = loaded.GetType("Fixtures.Factory")!.GetMethod("Allocate")!.Invoke(null, null);
        if (value is not AllocationFixture fixture) throw new Exception("Allocation lost its exact reference type");
        if (fixture.Value != 0 || AllocationFixture.ConstructorCalls != 0)
            throw new Exception("Allocation ran an instance constructor or field initializer");
        fixture.Value = 7;
        var ctor = new DynamicMethod("ExplicitConstructor", typeof(void), [typeof(AllocationFixture)], typeof(AllocationEmissionChecks).Module, true);
        var il = ctor.GetILGenerator();
        il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Call, typeof(AllocationFixture).GetConstructor(Type.EmptyTypes)!); il.Emit(OpCodes.Ret);
        ctor.CreateDelegate<Action<AllocationFixture>>()(fixture);
        if (fixture.Value != 42 || AllocationFixture.ConstructorCalls != 1)
            throw new Exception("Explicit subsequent constructor failed or ran more than once");
        if (method.CilMethodBody.Instructions.Any(i => i.OpCode == CilOpCodes.Newobj))
            throw new Exception("Raw allocation unexpectedly emits a constructor call");
        return 4;
    }
}

public sealed class AllocationFixture
{
    public static int ConstructorCalls;
    public int Value = 42;
    public AllocationFixture() { ConstructorCalls++; }
}
