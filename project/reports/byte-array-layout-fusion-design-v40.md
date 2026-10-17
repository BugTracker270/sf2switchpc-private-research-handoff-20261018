# Byte-array layout/allocation fusion design

DESIGN_ONLY_DUPLICATE_METADATA_INIT_FUSION_WITH_PRODUCTION_BLOCKERS

Prefer exact duplicate-init/allocation fusion over a standalone TypeHandle-or-true Class::Init adapter. Initial production scope should be only the three proved constant Byte[] windows after all listed proof and EH gates exist.

Array::NewSpecific itself invokes the same Class::Init before checks/allocation. On a valid exact class, the outer call makes the nested call take the initialized fast path. If the result is dead, only nonthrowing register preparation intervenes and EH scope agrees, the composed operation can retain one metadata initialization inside allocation. This is a conditional composition argument, not evidence that initialization has no effects.

Observed original caller windows:

| Init call | Allocation call | Length | Initial candidate |
|---|---|---|---|
| 0x4a0e1c | 0x4a0e28 | 2 | yes |
| 0x4a0ed0 | 0x4a0edc | 8 | yes |
| 0x4a0f8c | 0x4a0f98 | 4 | yes |
| 0x4a1000 | 0x4a100c | original low32 mask | deferred |

Exact allocator B5FE50..B5FFA4 (340 bytes) invokes B04F60 at B5FE68 before rank/initialized/length checks. The exact official 2018.1.9f1 Array.cpp agrees. Caller Boolean results are overwritten, and only two register instructions intervene. The original reader and allocator both have exact zR CIEs, empty FDE augmentation and no LSDA/personality; the metadata helper retains its own exception cleanup. Native code/source remain private and unchanged.

The host [NewArr contract](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.newarr?view=net-10.0) and [ECMA-335 III.4.20](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) provide managed array allocation and zeroing semantics. They do not prove IL2CPP cold metadata behavior.

Required proof scope:

- NSO metadata24 opt-in, exact reviewed loaded-image identity and original helper/allocator FDE hashes; never resolve by helper name alone.
- Use actual app-owned System.Byte metadata identity from original mscorlib, exact SZARRAY shape/rank1, element size1 and absent original array/element .cctor. FullName alone is insufficient.
- The layout call must retain its reviewed ABI carrier and exactly one valid non-null class operand; allocation must be the original B5FE50 call already destined for NewArr on the same exact class origin.
- Prove the Boolean result unused by every deep operand, Phi, return, address, exceptional successor and copy; do not materialize true, null or a default result.
- Start with length2/8/4 windows. Preserve original length operand and every allocation-result use; exclude variable/truncated/negative/large lengths until separate allocation-width and overflow proof.
- Require unique available class definitions and exact same captured native klass value. Reject different metadata identities, mutable reloads, unknown origins, duplicate definitions and escapes.
- Validate original local CFG and native call ordering, unique straight-line path and no interior incoming edge. Only the two observed nonthrowing register preparations may lie between calls.
- Require equivalent native exception landing-pad/action scope for both outer-init and allocation sites, or an exact proof that neither has a caller cleanup/action. Preserve unrelated throw branches and do not infer this from missing recovered CIL EH.
- Capture proof while SSA and original native-call identity exist, before SsaForm.Remove. Consume it only for the unchanged matching allocation after ArrayRecovery produces NewArr; late emission must reject stale owner/type/result/length/call identity.
- Only remove the duplicate outer metadata-init operation as part of the exact matched allocation. No standalone helper replacement, global call deletion, RunClassConstructor, synthetic success or diagnostic suppression.
- Preserve original allocation fault propagation and postallocation effects. Do not catch OutOfMemory/Overflow/TypeLoad failures, return an empty array, substitute cached arrays or merge two allocations.
- Keep initialized/cold class evidence, host runtime array contract and managed constructor behavior separately measured. Runtime metadata statistics/GC/profiler/native stack traces are platform boundaries, not claimed identical implementations.

Production blockers:

- No production fusion/proof carrier exists. The three constant sites are static candidates, not accepted recoveries or runtime coverage.
- Actual v38 metadata class identity, complete deep-use/availability and matching allocation identity must be checked in production SSA and revalidated at emission; historical v36 text is corroboration only.
- The exact reader and allocator are now independently proved plain zR/empty-FDE-augmentation/no-LSDA frames. A production proof must bind those exact facts; other EH-bearing callers remain rejected. The nested layout helper has real cleanup, retained conceptually inside the allocation composition.
- Existing 512-case layout witness covers initialized path only. Existing 582-case array witness supplies initialized class, allocator and exception boundaries. Neither executes actual cold InitLocked or native cleanup.
- The prior TypeHandle canary witness is metadata observation, not NewArr execution. A separate host typed-byte-array/constructor-negative/failure-order contract is required; no build or runtime was run for this design.
- Original native allocator/GC/OOM/profiler behavior is outside current executable parity. NewArr is a host-runtime abstraction with specified allocation failure, not a promise to reproduce native process assertions or C++ stack traces.

25 static evidence assertions passed. 23 negative fixture families are proposed; none were executed. No Core edit/build, helper suppression, runtime substitution or native/game execution occurred. Full clean source and portability remain false.
