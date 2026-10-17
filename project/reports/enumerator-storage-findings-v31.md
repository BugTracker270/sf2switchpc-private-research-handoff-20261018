# Enumerator return storage: bounded v31 investigation

Status: **OBSERVED_RECOVERY_DEFECT; NO PRODUCTION FIX IMPLEMENTED.** Full source compilation remains incomplete.

The selected method is Assembly-CSharp `Nekki.SF2.Core.Fights.Fight.SetStage`, token `0x0600092C`, native RVA `0xC9F3F0`. This investigation separates three boundaries: unchanged native return-buffer ownership, actual recovered CIL storage identities, and isolated BCL diagnostic controls. It does not execute the game method or establish whole-method parity.

## Actual native ownership

`reports/enumerator-native-return-v31.json` records six original-code cases and 36 checks. The unchanged `List<ref>.GetEnumerator` body at `0x1585F60` and its unchanged unboxed constructor at `0x11DD130` execute fully, with a supplied opaque list/version field, MethodInfo/context pointer tables and output memory. No runtime replacement hook runs; the memory-write hook observes writes only.

The caller zeroes exactly 24 bytes at SP+8..SP+0x1F using both the paired zero store at `0xC9F440` and the eight-byte zero store at `0xC9F444`. Immediately before the call at `0xC9F4DC`, X8 contains SP+8. MoveNext, Current and Dispose all receive SP+8 in X0. The native callee writes the list pointer, zero index, original list version and zero current reference into that 24-byte buffer. X0 returns the buffer pointer, rather than aggregate value bits. X8 is clobbered inside the constructor, so recovery must preserve its pre-call address identity.

## Actual recovered CIL and bounded controls

`reports/enumerator-storage-v31.json` records 23 checks across two separately loaded recovery assemblies. Exact assembly/body hashes and original member tokens are retained. Full method CIL stays in ignored `analysis/il2cpp/enumerator-storage-cil-v31.json`.

| Run | GetEnumerator call/store IL | Result local | All consumer receivers | Scalar-zero store |
|---|---|---:|---:|---|
| v29 `nso-native-leaves-v29` | 474 / 479 | 11 | 34 | absent |
| v30 `nso-value-this-box-v30` | 499 / 504 | 12 | 3 | IL460 `ldc.i4 0` -> IL465 local3 |

The result-storage mismatch therefore predates v30. Retaining the original addressed initializer in v30 exposed an additional scalar-to-aggregate source diagnostic.

The BCL-only probe executes isolated selected CIL fragments, preserving original local indices and store/receiver instruction bytes. The explicit generic reference-type substitution is List<Model> -> List<object> at the input, touched local and member-token boundaries; unused local storage is opaque object. No game methods, constructors or helper bindings execute.

- The v30 scalar-zero store followed by its actual receiver/MoveNext slice throws NullReferenceException on the host CLR.
- An explicit initialization-only control using valid initobj still throws NullReferenceException in both versions for lists of 0, 1, 3 and 8 elements: the actual GetEnumerator store still targets a different local.
- A separate counterfactual control explicitly retargets that store to the consumed local and then returns the expected MoveNext result for those inputs. This is a diagnostic control, not a production recovery or inferred whole-method implementation.

The first unused-store experiment assumed InvalidProgramException; the .NET 10 JIT accepted the fragment when its enum local was never consumed. Its failed assertion is preserved in `logs/enumerator-storage-v31-unused-store-assumption-failure.log`. JIT acceptance of an unused store is not a source-compiler success or a valid aggregate recovery. The final probe consumes the original local and records the observed exception.

## Pipeline placement and bounded recommendation

`reports/enumerator-pipeline-v31.json` records actual unmodified conversion, stack normalization, SSA and local allocation using an existing Core binary. No Core source was edited or built. Exact tool/input/source hashes are included; private full graph snapshots stay under analysis. An initial deferred-enumeration snapshot was invalid and is retained separately with that filename; only the eagerly materialized final snapshots are evidence.

- Raw conversion index85 preserves `X8=&stack[8]`, but call86 records destination X0 and arguments X0/X1 only. The hidden buffer has already been omitted from the call semantics before SSA.
- Stack normalization maps this address and the MoveNext/Current/Dispose receiver addresses at indices94/100/134 to `stack_-68`.
- Current SSA preserves all four addresses as `stack_-68_v1`, and local allocation maps them to the same local v38. The call result instead becomes X0_v4/local v89. This actual baseline enum slot does not trigger the independent address-taking SSA version-loss defect, because its consumers take its address rather than reading its plain value.

The first integration point is `Cpp2IL.Core/InstructionSets/NewArmV8InstructionSet.cs`, `AddCallAt` around lines323–361: capture the verified pre-call hidden-buffer identity while converting the native call. The caller pipeline in `Model/Contexts/MethodAnalysisContext.cs` then normalizes stack storage at line374 and builds SSA/locals at lines381–382. For a narrowly proved direct SP+constant return buffer, represent the call's aggregate result as a definition of that normalized storage before SSA; preserve native X0 pointer uses separately if they are live. Reject unproved aliasing, unknown layout, HFA/other ABI shapes, multiple ambiguous pointer definitions and escaping/overlapping buffers.

A generic synthetic store through `MemoryOperand(AddressOf(stack))` is not supported by current normalization: `Analysis/StackAnalyzer.cs` handles top-level register-based frame operands and AddressOf(StackOffset), while `Analysis/LocalVariables.cs` around lines184–207 and 50–62 casts MemoryOperand bases to Register. Introducing that operand shape without its own support would cause another recovery error. The existing exact same-stack-slot path should be proved in a fixture before using it.

Zeroing is a separate issue. A single eight-byte zero store cannot become a whole 24-byte default initializer. Either prove complete byte coverage, ordering and absence of intervening observations for a typed aggregate initialization, or prove a full typed call result overwrites the region before every observable read before eliminating dead zero stores. Do not replace source casts with default expressions merely to reduce compiler counts.

The independently tested `SsaForm.FindClobberingAddressTakes`/Rename behavior remains relevant for recovery that introduces later plain storage reads: a pure address-take can create a fresh SSA version without any call/write. See `reports/address-take-ssa-version-loss-v31.json`. Any broader mutable address-taken storage model must preserve identity through calls and loops and must be verified against the actual resulting CIL; changing this rule globally is outside this read-only investigation.

No default initializer, synthetic game helper, native-call retarget, compiler suppression, or source-text replacement was added to recovered production output.
