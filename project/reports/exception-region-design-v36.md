# Exception region design foundation

PASS_STANDALONE_REGION_DESIGN_FOUNDATION

32 structural model tests; 13 actual existing-Core graph checks; 0 design-evidence failures.

The standalone immutable model keeps normal leave continuation, finally invocation and exceptional entry separate. Handler-only roots remain retained without ordinary predecessor edges. It accepts explicitly synthetic single-finally void plans and always reports production readiness false.

Actual v35 Core evidence confirms that entry-only enumeration/pruning loses disconnected handler-shaped blocks. Building a CFG from a shallow list copy mutates shared branch instructions; remapping cloned fixture branch identities preserves the original. The probe does not establish general mutable-operand cloning.

Required integration contracts:

- **Lifting/provenance:** MethodRegionPlan sidecar on MethodAnalysisContext; stable boundary labels and NativeInstructionSpan(original method/body hash, RVA, lift ordinal). Keep 1-to-many native/ISIL mapping and explicit synthetic origins. Bind every protected throwpoint before native-address data is discarded.
- **Typed entry:** Separate NativeLandingEntry(X0 opaque unwind token, W1 selector, independently validated frame/storage and unknown volatile registers) from ManagedFinallyEntry(empty evaluation stack, runtime-owned pending dispatch). Fresh handler-entry values cannot reuse normal call destinations or MethodInfo registers. CFI parser observations alone cannot authorize frame installation.
- **IR terminators:** Leave(continuation, region), EndFinally(region), and Rethrow(catch region) require explicit IsFallThrough/use/definition/terminator handling. Rethrow is rejected until an actual managed catch scope is proved; it is not needed in a finally. Keep native Resume unsupported and distinct from managed Throw/Rethrow.
- **CFG roots and partitions:** Split at protected/handler boundaries and exceptional throwpoints. Keep normal successors/predecessors separate from instruction-specific exceptional transfers. Structural retention includes anchored handler roots; it must not fabricate normal flow into handlers. Do not merge across region partitions or delete boundary NOP/empty blocks without remapping all anchors.
- **Stack and memory:** Seed handler physical-frame state independently at a proved entry boundary. Preserve one typed live 24-byte Enumerator storage identity across acquisition, protected byref calls and cleanup; memory state is from the throwpoint after possible callee effects, not an unconditional pre-call snapshot. Unknown alias/overlap/escape/frame states reject.
- **SSA/dataflow:** Use a normal-flow forest plus explicit exceptional entry parameters/state joins, or initially bypass general SSA only for an exact complete typed method descriptor after all equivalence gates. Ordinary phi predecessor copies are not exceptional argument transfers. Calls produce a normal result only on their normal edge; exception-entry registers are fresh and byref storage effects remain conservative.
- **Clone/rewrite contract:** Clone instruction instances, remap every branch and region anchor to cloned identities, and clone mutable AddressOf/FieldReference/LocalVariable operand graphs when applicable. Current tiny probe validates only primitive/branch fixture cloning, not a general deep clone. Every rewrite must preserve region membership, labels and ordered side effects atomically.
- **CIL layout:** Emit acquisition outside try; one structured protected loop; leave to normal continuation; a separate Finally clause with Dispose and endfinally; post-finally class initialization/Clear only on normal completion. Finally has no catch type. Instruction-backed boundary labels must survive zero-IL nodes; do not use arbitrary original block order or normal br across region boundaries.
- **Validation and failure:** Validate serialized EH kind/bounds/labels and all control transfers, evaluation stack and exact typed operands in addition to MaxStack. Unsupported aliases, foreign dispatch, nested regions, changed native evidence, unresolved labels or inconsistent storage reject the whole method with preserved diagnostic evidence.

Original behavior still unresolved:

- No native LSDA/RTTI action is converted into a managed finally or catch. Original selector 1/non-null managed-wrapper cleanup and foreign/unmatched-selector _Unwind_Resume have different behavior; foreign-exception cleanup stays unresolved.
- The v35 CFI API supplies ordered instruction-state observations, including intermediate states at one PC. It does not provide completed PC ranges or an executed SDK personality/unwinder context.
- The original null managed-payload branch and trace/raise semantics remain separate proof obligations. A finally propagates runtime-owned pending dispatch; an explicit managed Throw or Rethrow must not be substituted to guess native trace behavior.
- The original protected native table has three bounded call intervals. A future contiguous managed try must prove every additional included instruction is non-throwing or has equivalent handling; no action is widened from address proximity.
- Exact typed static fields, List/AssetBundle member identities, the 24-byte frame-storage lifetime and normal/cleanup initialization ordering must all be validated before a complete original method can be emitted.

Future behavior/serialization gates are proposed, not run:

- **Native landing/context witnesses:** All three unchanged landing entries with selector 1 and distinct non-null managed payloads; Original begin/end catch order, one Dispose and same-pointer raise; Selector 0/other reaches original resume boundary without fabricated Dispose; Separate null-payload behavior and actual installed unwind/frame context.
- **Serialized CIL structure:** Exactly one Finally, no catch type, correct half-open instruction boundaries; Normal protected exits use leave, handler completes with endfinally; Empty finally entry stack and no branch/ret across region boundaries; Malformed/foreign/nested/changed descriptor rejects atomically.
- **Runtime side-effect/exception behavior:** Empty/1/3/8 element normal loop and repeated invocation; Acquisition throws: no Dispose or Clear; MoveNext/Current/Unload throws: Dispose once, Clear absent, same exception identity; Dispose throws: replacement exception propagates, no Clear; Post-finally initialization/Clear throws: no duplicate Dispose; Trace and normal-result visibility checked independently.

Inspected upstream locations:

- `refs\Cpp2IL\Cpp2IL.Core\InstructionSets\NewArmV8InstructionSet.cs:177`: Native address mapping is a local parallel list; one native instruction may lift to multiple ISIL operations. Synthetic entries use ulong.MaxValue. Bare instructions leave this method, so a persistent region/provenance sidecar is missing.
- `refs\Cpp2IL\Cpp2IL.Core\ISIL\Instruction.cs:40`: Instruction instances and operands are mutable identity objects. The terminator/use/definition model has no Leave, EndFinally or Rethrow semantics.
- `refs\Cpp2IL\Cpp2IL.Core\ISIL\Instruction.cs:241`: Instruction identity is deliberately distinct from structural equality; indices are not safe persistent region anchors, and synthetic phi copies can share index -1.
- `refs\Cpp2IL\Cpp2IL.Core\Graphs\ISILControlFlowGraph.cs:424`: CFG construction mutates instruction operands from instruction targets to Block identities; shallow list copies do not isolate analysis.
- `refs\Cpp2IL\Cpp2IL.Core\Graphs\ISILControlFlowGraph.cs:24`: Instruction enumeration starts only at ordinary method entry, omitting disconnected handler roots.
- `refs\Cpp2IL\Cpp2IL.Core\Graphs\ISILControlFlowGraph.cs:87`: Reachability uses only ordinary successor lists; no exception-region root or typed exceptional transfer is represented.
- `refs\Cpp2IL\Cpp2IL.Core\Graphs\ISILControlFlowGraph.cs:136`: Branch targets protect NOPs; protected/handler boundary anchors are not considered.
- `refs\Cpp2IL\Cpp2IL.Core\Graphs\ISILControlFlowGraph.cs:193`: Empty-block rewrites update normal predecessor/successor references only; region anchors would also require atomic remapping.
- `refs\Cpp2IL\Cpp2IL.Core\Graphs\ISILControlFlowGraph.cs:281`: Call blocks merge without region membership or handler-root checks. MetadataResolver invokes this pass.
- `refs\Cpp2IL\Cpp2IL.Core\Model\Contexts\MethodAnalysisContext.cs:370`: Attach and validate native region/provenance data before this CFG construction and before StackAnalyzer pruning.
- `refs\Cpp2IL\Cpp2IL.Core\Analysis\StackAnalyzer.cs:33`: Stack analysis immediately prunes ordinary-unreachable handlers, then seeds only EntryBlock with stack delta zero.
- `refs\Cpp2IL\Cpp2IL.Core\Analysis\StackAnalyzer.cs:99`: Stack offsets rely on a per-instruction ordinary stack state. Handler frames need independently validated entry/storage state, not a borrowed normal call-return state.
- `refs\Cpp2IL\Cpp2IL.Core\Analysis\SsaForm.cs:40`: SSA rename has one ordinary entry and positional normal predecessors; no fresh exception-entry definitions or exceptional memory state.
- `refs\Cpp2IL\Cpp2IL.Core\Analysis\SsaForm.cs:423`: Phi removal emits normal predecessor copies. A thrown call cannot execute copies appended after its normal return; exceptional state requires a separate transfer contract.
- `refs\Cpp2IL\Cpp2IL.Core\IlGenerator.cs:52`: Emitter mutates Block operands back to instruction targets; region anchors must survive this identity conversion.
- `refs\Cpp2IL\Cpp2IL.Core\IlGenerator.cs:160`: Ordinary bridges use br; region exits need explicit leave, and finally completion needs endfinally with an empty stack.
- `refs\Cpp2IL\Cpp2IL.Core\IlGenerator.cs:389`: Current Throw can throw an existing managed object or construct one; it is not Rethrow or native _Unwind_Resume.
- `refs\Cpp2IL\Cpp2IL.Core\IlGenerator.cs:187`: Unresolved normal branch targets currently degrade to warnings/NOP. Region boundaries and illegal EH transfers must instead fail the entire candidate atomically.
- `refs\Cpp2IL\Cpp2IL.Core\OutputFormats\AsmResolverDllOutputFormatIlRecovery.cs:68`: A future exact whole-method descriptor/emitter could isolate one proved cleanup case here; this is a placement proposal, not implementation or permission to bypass missing native/typed evidence.
- `refs\Cpp2IL\Cpp2IL.Core\Model\Contexts\MethodAnalysisContext.cs:465`: Any future region sidecar needs explicit lifecycle handling and evidence export before analysis data is released.

Primary references:

- [Ordinary branch cannot enter/leave protected and handler blocks.](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.br?view=net-10.0)
- [Leave clears the stack and executes surrounding finally blocks; it cannot exit finally.](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.leave?view=net-10.0)
- [Rethrow belongs only to a catch body, not a finally.](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.rethrow?view=net-10.0)
- [CLI exception-region and instruction semantics; the standalone checker is a conservative subset, not full CIL verification.](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

No Core edits/builds, original game execution, native unwinding or EH emission occurred. The complete decompile remains incomplete.
