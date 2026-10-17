using System.Collections.Generic;
using System.Linq;
using System.Buffers.Binary;
using Disarm;
using Cpp2IL.Core.Logging;
using Cpp2IL.Core.Utils;
using LibCpp2IL.NintendoSwitch;

namespace Cpp2IL.Core.Il2CppApiFunctions;

public class NewArm64KeyFunctionAddresses : BaseKeyFunctionAddresses
{
    // Deliberately outside BaseKeyFunctionAddresses.Pairs/resolvedAddressSet:
    // only the later scalar operand/provenance guard may lower these calls.
    public ulong LegacyScalarBoxingCandidate { get; private set; }

    protected override void AttemptInstructionAnalysisToFillGaps()
    {
        base.AttemptInstructionAnalysisToFillGaps();
        if (_appContext.Binary is not NsoFile || _appContext.MetadataVersion < 24f || _appContext.MetadataVersion >= 24.2f) return;
        RecoverLegacySingletonAllocation();
        RecoverLegacyClassInit();
        RecoverLegacyExceptionRaiser();
        RecoverLegacyArrayAllocation();
        LegacyScalarBoxingCandidate = LegacyArm64ScalarBoxing.FindCandidate(_appContext, il2cpp_codegen_object_new);
        if (LegacyScalarBoxingCandidate != 0)
            Logger.InfoNewline($"Experimental legacy scalar boxing candidate at 0x{LegacyScalarBoxingCandidate:X}; typed storage is checked separately.");
    }

    private void RecoverLegacyArrayAllocation()
    {
        if (_appContext.MetadataVersion != 24f || il2cpp_vm_array_new_specific != 0 || il2cpp_array_new_specific != 0 || SzArrayNew != 0 || il2cpp_vm_exception_raise == 0) return;
        var binary = _appContext.Binary;
        var text = binary.GetVirtualAddressOfPrimaryExecutableSection();
        var textEnd = text + (ulong)binary.GetEntirePrimaryExecutableSection().Length;
        var cache = new Dictionary<ulong, bool>();
        ulong? agreed = null;
        foreach (var name in new[] { "String", "BitConverter", "Convert" })
        {
            var type = ReflectionCache.GetType(name, "System");
            if (type?.Methods == null) return;
            var candidates = new HashSet<ulong>();
            foreach (var method in type.Methods.Where(m => m.MethodPointer != 0))
            {
                var next = _appContext.GetAddressOfNextFunctionStart(method.MethodPointer);
                if (next <= method.MethodPointer || next - method.MethodPointer > 65536) continue;
                if (!binary.TryMapVirtualAddressToRaw(method.MethodPointer, out var start) || !binary.TryMapVirtualAddressToRaw(next, out var end)
                    || end <= start || end - start > 65536) continue;
                var code = binary.GetRawBinaryContent().Slice((int)start, (int)(end - start));
                for (var offset = 0; offset + 4 <= code.Length; offset += 4)
                {
                    var word = BinaryPrimitives.ReadUInt32LittleEndian(code[offset..]);
                    if ((word & 0xfc000000) != 0x94000000) continue;
                    var target = unchecked((ulong)((long)method.MethodPointer + offset + (((int)(word << 6)) >> 4)));
                    if (target < text || target + 244 > textEnd || _appContext.MethodsByAddress.ContainsKey(target)) continue;
                    if (!cache.TryGetValue(target, out var matches))
                    {
                        matches = binary.TryMapVirtualAddressToRaw(target, out var raw)
                            && LegacyArm64ArrayAllocationPattern.Match(binary.GetRawBinaryContent().Slice((int)raw, 244), target, il2cpp_vm_exception_raise) != null;
                        cache[target] = matches;
                    }
                    if (matches) candidates.Add(target);
                }
            }
            if (candidates.Count != 1) return;
            var candidate = candidates.Single();
            if (agreed != null && candidate != agreed) return;
            agreed = candidate;
        }
        if (agreed is not { } allocator) return;
        il2cpp_vm_array_new_specific = allocator;
        Logger.InfoNewline($"Recovered legacy NSO array allocation at 0x{allocator:X} from three corlib families and checked size/header/return flow.");
    }

    private void RecoverLegacyExceptionRaiser()
    {
        if (_appContext.MetadataVersion != 24f || il2cpp_vm_exception_raise != 0 || il2cpp_raise_exception != 0 || il2cpp_codegen_raise_exception != 0) return;
        var binary = _appContext.Binary;
        var text = binary.GetVirtualAddressOfPrimaryExecutableSection();
        var textEnd = text + (ulong)binary.GetEntirePrimaryExecutableSection().Length;
        var cache = new Dictionary<ulong, LegacyArm64ExceptionRaiserPattern.Witness?>();
        ulong? agreed = null;
        foreach (var name in new[] { "String", "Array", "Convert" })
        {
            var type = ReflectionCache.GetType(name, "System");
            if (type?.Methods == null) return;
            var candidates = new HashSet<ulong>();
            foreach (var method in type.Methods.Where(m => m.MethodPointer != 0))
            {
                var next = _appContext.GetAddressOfNextFunctionStart(method.MethodPointer);
                if (next <= method.MethodPointer || next - method.MethodPointer > 65536) continue;
                if (!binary.TryMapVirtualAddressToRaw(method.MethodPointer, out var start) || !binary.TryMapVirtualAddressToRaw(next, out var end)
                    || end <= start || end - start > 65536) continue;
                var code = binary.GetRawBinaryContent().Slice((int)start, (int)(end - start));
                for (var offset = 0; offset + 4 <= code.Length; offset += 4)
                {
                    var word = BinaryPrimitives.ReadUInt32LittleEndian(code[offset..]);
                    if ((word & 0xfc000000) != 0x94000000) continue;
                    var target = unchecked((ulong)((long)method.MethodPointer + offset + (((int)(word << 6)) >> 4)));
                    if (target < text || target >= textEnd || _appContext.MethodsByAddress.ContainsKey(target)) continue;
                    if (!cache.TryGetValue(target, out var witness))
                    {
                        witness = null;
                        if (binary.TryMapVirtualAddressToRaw(target, out var raw))
                            witness = LegacyArm64ExceptionRaiserPattern.Match(binary.GetRawBinaryContent().Slice((int)raw, (int)System.Math.Min(512ul, textEnd - target)), target);
                        cache[target] = witness;
                    }
                    if (witness is { } value && value.AllocateException >= text && value.AllocateException < textEnd && value.NativeThrow >= text && value.NativeThrow < textEnd)
                        candidates.Add(target);
                }
            }
            if (candidates.Count != 1) return;
            var candidate = candidates.Single();
            if (agreed != null && candidate != agreed) return;
            agreed = candidate;
        }
        if (agreed is not { } raiser) return;
        il2cpp_vm_exception_raise = raiser;
        Logger.InfoNewline($"Recovered legacy NSO exception raiser at 0x{raiser:X} from three corlib families and a checked C++ exception-wrapper pattern.");
    }

    private void RecoverLegacySingletonAllocation()
    {
        if (il2cpp_object_new != 0 || il2cpp_codegen_object_new != 0 || il2cpp_codegen_initialize_method == 0) return;
        var objectCtor = ReflectionCache.GetType("Object", "System")?.Methods?.FirstOrDefault(m => m.Name == ".ctor")?.MethodPointer ?? 0;
        if (objectCtor == 0) return;
        ulong? agreed = null;
        foreach (var (name, ns) in new[] { ("EventArgs", "System"), ("DBNull", "System"), ("Missing", "System.Reflection") })
        {
            var anchor = ReflectionCache.GetType(name, ns)?.Methods?.FirstOrDefault(m => m.Name == ".cctor");
            if (anchor == null || anchor.MethodPointer == 0) return;
            var next = _appContext.GetAddressOfNextFunctionStart(anchor.MethodPointer);
            if (next <= anchor.MethodPointer || next - anchor.MethodPointer > 512) return;
            var binary = _appContext.Binary;
            if (!binary.TryMapVirtualAddressToRaw(anchor.MethodPointer, out var start) || !binary.TryMapVirtualAddressToRaw(next, out var end)
                || end <= start || end - start > 512) return;
            var bytes = binary.GetRawBinaryContent().Slice((int)start, (int)(end - start));
            var candidate = LegacyArm64AllocationPattern.Match(bytes, anchor.MethodPointer, il2cpp_codegen_initialize_method, objectCtor);
            if (candidate == null || (agreed != null && candidate != agreed)) return;
            agreed = candidate;
        }
        if (agreed is not { } target) return;
        var text = _appContext.Binary.GetVirtualAddressOfPrimaryExecutableSection();
        if (target < text || target - text >= (ulong)_appContext.Binary.GetEntirePrimaryExecutableSection().Length || target % 4 != 0) return;
        il2cpp_codegen_object_new = target;
        Logger.InfoNewline($"Recovered legacy NSO object allocation at 0x{target:X} from three agreeing singleton constructors.");
    }

    private void RecoverLegacyClassInit()
    {
        if (_appContext.MetadataVersion != 24f || il2cpp_runtime_class_init_export != 0 || il2cpp_runtime_class_init_actual != 0 || il2cpp_codegen_runtime_class_init != 0) return;
        ulong? agreed = null;
        foreach (var (name, methodName) in new[] { ("String", "Concat"), ("BitConverter", "ToString"), ("Convert", "ToString") })
        {
            var type = ReflectionCache.GetType(name, "System");
            if (type?.Methods == null) return;
            var candidates = new HashSet<ulong>();
            foreach (var method in type.Methods.Where(m => m.Name == methodName && m.MethodPointer != 0))
            {
                var next = _appContext.GetAddressOfNextFunctionStart(method.MethodPointer);
                if (next <= method.MethodPointer || next - method.MethodPointer > 65536) continue;
                var binary = _appContext.Binary;
                if (!binary.TryMapVirtualAddressToRaw(method.MethodPointer, out var start) || !binary.TryMapVirtualAddressToRaw(next, out var end)
                    || end <= start || end - start > 65536) continue;
                foreach (var candidate in LegacyArm64AllocationPattern.ClassInitTargets(binary.GetRawBinaryContent().Slice((int)start, (int)(end - start)), method.MethodPointer))
                    candidates.Add(candidate);
            }
            if (candidates.Count != 1) return;
            var target = candidates.Single();
            if (agreed != null && target != agreed) return;
            agreed = target;
        }
        if (agreed is not { } initializer) return;
        var text = _appContext.Binary.GetVirtualAddressOfPrimaryExecutableSection();
        if (initializer < text || initializer - text >= (ulong)_appContext.Binary.GetEntirePrimaryExecutableSection().Length || initializer % 4 != 0) return;
        il2cpp_codegen_runtime_class_init = initializer;
        Logger.InfoNewline($"Recovered legacy NSO class initialization at 0x{initializer:X} from three agreeing corlib families.");
    }

    private List<Arm64Instruction>? _cachedDisassembledBytes;

    private List<Arm64Instruction> DisassembleTextSection()
    {
        if (_cachedDisassembledBytes == null)
        {
            var binary = _appContext.Binary;
            var toDisasm = binary.GetEntirePrimaryExecutableSection();
            _cachedDisassembledBytes = Disassembler.Disassemble(toDisasm, binary.GetVirtualAddressOfPrimaryExecutableSection(), new(true, true, false)).ToList();
        }

        return _cachedDisassembledBytes;
    }

    private HashSet<ulong> CallTargets => field ??=
    [
        .. DisassembleTextSection()
            .Where(i => i.Mnemonic == Arm64Mnemonic.BL)
            .Select(i => i.BranchTarget)
    ];

    private bool IsFunctionStart(List<Arm64Instruction> disassembly, int index)
    {
        if (CallTargets.Contains(disassembly[index].Address))
            return true;

        if (index == 0)
            return true;

        // it's a function start if the previous instruction can't fall through into it
        var previous = disassembly[index - 1];
        return previous.Mnemonic is Arm64Mnemonic.RET or Arm64Mnemonic.RETAA or Arm64Mnemonic.RETAB or Arm64Mnemonic.BR or Arm64Mnemonic.BRK or Arm64Mnemonic.INVALID
               || (previous.Mnemonic == Arm64Mnemonic.B && previous.MnemonicConditionCode is Arm64ConditionCode.NONE or Arm64ConditionCode.AL);
    }

    protected override IEnumerable<ulong> FindAllThunkFunctions(ulong addr, uint maxBytesBack = 0, params ulong[] addressesToIgnore)
    {
        if (_appContext.Binary is NsoFile && _appContext.MetadataVersion == 24f)
        {
            // A decoded instruction object for every word of a large NSO can
            // exhaust the bounded research heap. Fixed-width branch witnesses
            // need only a compact set of direct BL targets and two linear scans.
            foreach (var thunk in LegacyArm64ThunkScanner.Find(_appContext.Binary.GetEntirePrimaryExecutableSection(),
                _appContext.Binary.GetVirtualAddressOfPrimaryExecutableSection(), addr, maxBytesBack,
                addressesToIgnore.ToHashSet(), addr == il2cpp_vm_exception_raise))
                yield return thunk;
            yield break;
        }
        //Disassemble .text
        var disassembly = DisassembleTextSection();

        for (var index = 0; index < disassembly.Count; index++)
        {
            var instruction = disassembly[index];

            // a thunk ends by tail-calling the real function
            if (instruction.Mnemonic != Arm64Mnemonic.B || instruction.MnemonicConditionCode is not (Arm64ConditionCode.NONE or Arm64ConditionCode.AL) || instruction.BranchTarget != addr)
                continue;

            if (addressesToIgnore.Contains(instruction.Address))
                continue;

            // walk back over any setup instructions to the start of the function containing the branch,
            // bailing if it's too far away to be a thunk
            var maxInstructionsBack = (int)(maxBytesBack / 4);
            for (var back = 0; back <= maxInstructionsBack && index - back >= 0; back++)
            {
                if (!IsFunctionStart(disassembly, index - back))
                    continue;

                var start = disassembly[index - back].Address;
                if (!addressesToIgnore.Contains(start))
                    yield return start;

                break;
            }
        }
    }

    protected override ulong FindFirstCallTargetInMethod(ulong methodVa)
    {
        var instructions = NewArm64Utils.GetArm64MethodBodyAtVirtualAddress(_appContext, methodVa, false);
        var call = instructions.FirstOrDefault(i => i.Mnemonic == Arm64Mnemonic.BL);
        return call.Mnemonic == Arm64Mnemonic.BL ? call.BranchTarget : 0;
    }

    protected override ulong GetObjectIsInstFromSystemType()
    {
        Logger.Verbose("\tTrying to use System.Type::IsInstanceOfType to find il2cpp::vm::Object::IsInst...");
        var typeIsInstanceOfType = ReflectionCache.GetType("Type", "System")?.Methods?.FirstOrDefault(m => m.Name == "IsInstanceOfType");
        if (typeIsInstanceOfType == null)
        {
            Logger.VerboseNewline("Type or method not found, aborting.");
            return 0;
        }

        //IsInstanceOfType is a very simple ICall, that looks like this:
        //  Il2CppClass* klass = vm::Class::FromIl2CppType(type->type.type);
        //  return il2cpp::vm::Object::IsInst(obj, klass) != NULL;
        //The last call is to Object::IsInst

        Logger.Verbose($"IsInstanceOfType found at 0x{typeIsInstanceOfType.MethodPointer:X}...");
        var instructions = NewArm64Utils.GetArm64MethodBodyAtVirtualAddress(_appContext, typeIsInstanceOfType.MethodPointer, false);

        var lastCall = instructions.LastOrDefault(i => i.Mnemonic == Arm64Mnemonic.BL);

        if (lastCall.Mnemonic == Arm64Mnemonic.INVALID)
        {
            Logger.VerboseNewline("Method does not match expected signature. Aborting.");
            return 0;
        }

        Logger.VerboseNewline($"Success. IsInst found at 0x{lastCall.BranchTarget:X}");
        return lastCall.BranchTarget;
    }

    protected override ulong FindFunctionThisIsAThunkOf(ulong thunkPtr, bool prioritiseCall = false)
    {
        var instructions = NewArm64Utils.GetArm64MethodBodyAtVirtualAddress(_appContext, thunkPtr, false);

        var target = prioritiseCall ? Arm64Mnemonic.BL : Arm64Mnemonic.B;
        var matchingCall = instructions.FirstOrDefault(i => i.Mnemonic == target);

        if (matchingCall.Mnemonic == Arm64Mnemonic.INVALID)
        {
            target = target == Arm64Mnemonic.BL ? Arm64Mnemonic.B : Arm64Mnemonic.BL;
            matchingCall = instructions.FirstOrDefault(i => i.Mnemonic == target);
        }

        return matchingCall.Mnemonic != Arm64Mnemonic.INVALID ? matchingCall.BranchTarget : 0;
    }

    protected override int GetCallerCount(ulong toWhere)
    {
        //Disassemble .text
        var disassembly = DisassembleTextSection();

        //Find all jumps to the target address
        return disassembly.Count(i => i.Mnemonic is Arm64Mnemonic.B or Arm64Mnemonic.BL && i.BranchTarget == toWhere);
    }
}
