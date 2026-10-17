# Bounded UnloadDependencies exception recovery

READ_ONLY_BOUNDED_EXCEPTION_CONTRACT_IDENTIFIED_IMPLEMENTATION_NOT_STARTED

Cpp2IL currently cannot represent or emit this exception region. AsmResolver can emit it; the recovery IR and pipeline contracts are missing. No production code changed.

The reusable metadata parser has passed 38 synthetic tests and 15 original-evidence checks. Its CFI results are per-instruction observations, including same-PC intermediate states; finalized unwind rows and context installation remain unimplemented. See `reports/exception-metadata-parser-v35.json` for exact hashes and results.

| Original protected call | Native half-open range | Landing entry |
|---|---|---|
| MoveNext at 0x4a8438 | 0x4a8434..0x4a843c | 0x4a8498 |
| Current at 0x4a8448 | 0x4a8444..0x4a844c | 0x4a848c |
| AssetBundle.Unload at 0x4a8454 | 0x4a844c..0x4a8458 | 0x4a8480 |

All three action 3 entries select the original Il2CppExceptionWrapper RTTI (filter 1) followed by cleanup 0. Its RTTI object is identical to the original managed exception raiser. Selector 1 enters begin-catch/end-catch, extracts the managed pointer, disposes the same Enumerator storage, and raises that pointer when non-null. Other selectors reach _Unwind_Resume without this Dispose. This does not justify a fabricated System.Exception catch type or foreign-exception finally.

CFI gives CFA=X29+16. The prologue establishes X29=SP+64, so the 80-byte frame keeps its Enumerator at CFA-72..CFA-49. Handler entry must define new X0/W1 exception data and preserve the appropriate frame state; ordinary call-return/MethodInfo SSA values cannot stand in for it.

Smallest future slice:

1. First complete an immutable descriptor/proof fixture for only this original 384-byte method: whole-body/FDE/LSDA/action/RTTI/import/CFI hashes, typed field and five List/AssetBundle APIs, exact normal and cleanup orders. Unsupported actions/layouts/aliases/entry states reject atomically.
2. Run unchanged original landing fragments from each of the three entries with explicit unwind-token/selector/frame and C++ runtime boundaries. Prove selector1 with a non-null managed payload performs begin-catch, end-catch, Dispose once and the same-pointer raise; selectors0/other must reach the original resume boundary without Dispose. This is not yet actual unwinding.
3. Then validate a disjoint managed region fixture with one Finally clause: acquisition outside try; MoveNext/Current/Unload protected; Dispose only in finally; the second initialization request and Clear only after normal completion. Finally has no catch type. Compare event traces and exception identity under normal/throwing boundaries before production recovery.
4. If those gates pass, the smallest production candidate is an exact complete-method native-equivalence descriptor/emitter at FillMethodBody, analogous in placement only to the existing exact aggregate-leaf hook. It would emit one structured Finally using original typed members, without routing exceptional control through ordinary CFG/SSA. This is proposed, not implemented or accepted, and must carry explicit inferred-equivalence provenance.
5. A general EH pipeline is a later larger change: method region sidecars, typed exceptional transfers/entry states, EH-aware reachability, dataflow/alias lifetime, structured CIL layout and verification. Do not broaden normal successors to approximate it.

Missing implementation contracts:

- **Native region provenance:** No method-level LSDA/actions/types/CFI region descriptor survives conversion. Preserve exact native interval boundaries and original landing roots before reachability pruning.
- **Exception-entry state:** Define opaque unwind-token X0 and selector W1 at each landing entry; they are not normal call results/MethodInfo values. Seed frame/CFA and preserved values from the unwind contract; volatile registers become unknown. Do not insert exception edges as ordinary successors.
- **Reachability and SSA:** Handler roots require separate reachability. Exceptional state is from the throwing instruction, before any normal return destination, with conservative byref/memory effects. Ordinary phi-edge copy insertion cannot model that transfer. Address-taken Enumerator storage must retain one correct live identity across protected calls and cleanup.
- **Managed region semantics:** Represent typed region membership, normal leave, finally entry/exit and propagation. A handler condition is native C++ wrapper RTTI/selector, not an invented System.Exception catch type. A managed finally is a bridge-domain equivalence requiring proof.
- **CIL layout/emission:** AsmResolver supports CilExceptionHandler with Finally, inclusive starts/exclusive ends and labels, but current generator never fills the table and always emits ordinary br bridges. Emit leave for normal protected exits, endfinally for handler completion, no br/ret into/out of protected regions, and an empty finally evaluation stack.
- **Validation:** Assert serialized EH table/type/bounds and legal transfers, not just MaxStack. Execute original native landing fragments at stated runtime boundaries and then actual emitted recovered CIL; verify side-effect order, exception identity/trace, cleanup once and Clear suppression.

Unresolved before production acceptance:

- Actual SDK personality/unwinder installation has not executed. X0/W1 and CFI facts are supported by original pad code, relocations and ABI references; preservation of the installed frame/register state still needs an execution witness.
- The three protected callees, exact BundlesUtil static-field binding, all MethodInfo identities and frame-buffer live interval need a complete typed metadata descriptor. The separate SRET survey already proves the GetEnumerator family; it is not a full Unload descriptor.
- Selector1 carries the original C++ Il2CppExceptionWrapper. The code extracts a managed pointer, ends catch, disposes, then invokes the original managed raiser when non-null. Other selectors resume without this Dispose; translating them as a catch-all managed finally would exceed the proof.
- The native null managed-payload branch reaches the common Clear path. A managed-finally equivalence needs an explicit non-null managed-exception invariant or must preserve/reject this state; the proposal does not silently discard it.
- The prior raiser witness covers an existing non-null trace and supplied C++ allocation/throw boundaries. Stack-trace behavior for absent traces, actual C++ unwinding, foreign exceptions, forced unwind and destructor/termination cases remains unproved.
- Exact ordinary entry state, the 24-byte Enumerator return/storage identity, post-constructor field reloads and both class-initialization requests must be preserved. Existing v33 Unload CIL is not an execution oracle because EH and its SRET identity are incomplete.

Fail-closed tests are proposed, not run:

- **Native descriptor negatives:** Truncated/overlapping call-site ranges; Changed landing or action offset/cycle; Different RTTI/relocation/personality; Unresolved/foreign action type; Changed CFI/frame/selector register; Changed cleanup/raise/resume/normal Clear order.
- **Storage/member negatives:** Different enum slot or partial/overlapping/escaping region; Value/open T or non-unique registered MethodInfo; Wrong static field/AssetBundle bool API; GetEnumerator inside protected range; Dispose or Clear spuriously protected; Class-init or field reload reordered.
- **Native landing witness:** All3 original entries with selector1/non-null distinct exception identities; Selector0 and unmatched selector resume unchanged; Null managed payload explicitly remains unsupported or tested as its original separate branch.
- **CIL region behavior:** Empty and1/3/8 element normal iteration; Acquisition throws: no Dispose/Clear; MoveNext/Current/Unload throw: Dispose once, Clear absent, same exception; Dispose throws: replacement exception propagates, Clear absent; Post-finally initializer/Clear throws: no duplicate Dispose; Forbidden branch into handler, missing endfinally or invalid EH bounds rejected.

Inspected upstream locations:

- opcode_model: `refs/Cpp2IL/Cpp2IL.Core/ISIL/OpCode.cs:8` (exact file hash in JSON).
- ordinary_block_edges: `refs/Cpp2IL/Cpp2IL.Core/Graphs/Block.cs:12` (exact file hash in JSON).
- entry_only_instruction_enumeration: `refs/Cpp2IL/Cpp2IL.Core/Graphs/ISILControlFlowGraph.cs:15` (exact file hash in JSON).
- entry_only_reachability: `refs/Cpp2IL/Cpp2IL.Core/Graphs/ISILControlFlowGraph.cs:87` (exact file hash in JSON).
- normal_call_fallthrough: `refs/Cpp2IL/Cpp2IL.Core/Graphs/ISILControlFlowGraph.cs:376` (exact file hash in JSON).
- analysis_pipeline: `refs/Cpp2IL/Cpp2IL.Core/Model/Contexts/MethodAnalysisContext.cs:370` (exact file hash in JSON).
- stack_handler_pruning: `refs/Cpp2IL/Cpp2IL.Core/Analysis/StackAnalyzer.cs:33` (exact file hash in JSON).
- ssa_entry_contract: `refs/Cpp2IL/Cpp2IL.Core/Analysis/SsaForm.cs:31` (exact file hash in JSON).
- emitter_new_body: `refs/Cpp2IL/Cpp2IL.Core/IlGenerator.cs:62` (exact file hash in JSON).
- ordinary_branch_bridge: `refs/Cpp2IL/Cpp2IL.Core/IlGenerator.cs:160` (exact file hash in JSON).
- existing_direct_leaf_integration: `refs/Cpp2IL/Cpp2IL.Core/OutputFormats/AsmResolverDllOutputFormatIlRecovery.cs:68` (exact file hash in JSON).

Primary references:

- [Action offsets, type indices and runtime landing parameters; reference model, not a claim that the supplied SDK is this revision.](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/libcxxabi/src/cxa_personality.cpp)
- [AArch64 exception-data register convention corroborates original X0/W1 pad use.](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/llvm/lib/Target/AArch64/AArch64ISelLowering.h)
- [Personality/landing-pad and resume distinction.](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html)
- [Managed finally, leave, endfinally and region/stack constraints.](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
- [Output-library handler table and label APIs; installed6.0.1 XML separately inspected.](https://docs.washi.dev/asmresolver/guides/dotnet/managed-method-bodies.html)

Original native exception metadata/action/RTTI/CFI and current upstream pipeline inspection only. No exception edges were added, no catch type guessed, no game/native unwind/managed body executed and no production recovery built. A managed finally remains a conditional native-equivalence proposal in the managed-wrapper/non-null exception domain until typed storage, entry-state and behavior fixtures pass.
