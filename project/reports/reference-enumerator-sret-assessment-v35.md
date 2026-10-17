# Reference Enumerator SRET assessment

NO_NEW_ELIGIBLE_CALLERS_UNDER_EH_FREE_RECEIVER_ONLY_CONTRACT

No generalized production adapter was implemented. There are zero new eligible game callers under the first EH-free receiver-only contract.

| Actual caller assembly | Native calls | Typed adjacent buffers | Typed adjacent, normal-CFG registers dead | Typed adjacent, EH-free | EH-free receiver-only shape |
|---|---:|---:|---:|---:|---:|
| Assembly-CSharp | 1014 | 744 | 292 | 0 | 0 |
| Assembly-CSharp-firstpass | 47 | 35 | 25 | 4 | 0 |
| Other actual assemblies | 51 | 39 | 30 | 5 | 0 |

The exact native scan found 1,112 calls. Of 869 adjacent X8/SP shapes, 860 have exception-bearing zPLR frames and only nine have zR. All nine are interface/boxing wrappers; four are third-party classes inside firstpass. They fail the receiver-only shape. At 1,047 static call sites, the MethodInfo candidate resolves to one unique registered closed-reference alias per call; these are call sites, not unique aliases or recovered methods.

Concrete rejection evidence:

- HttpListenerPrefixCollection at 0x33EBBC passes buffer/register filters but loads SP+24/+32/+40 and invokes the original boxing helper.
- AchievCounters.GetAchievement reuses SP+8 for Enumerator<AchievCounter> at 0xF58BBC and Enumerator<Achievement> at 0xF58C34. Equal layout does not establish equal typed lifetime.

Required before expansion:

1. Keep the verified exact callee/constructor FDE+code+canonical metadata-family descriptor. Resolve each call MethodInfo to one identical registered closed-reference alias and the exact substituted ref/int/int/ref declaration; do not use target address or a guessed generic size alone.
2. For an initial reusable receiver-only contract, require an exact unique caller/frame and CIE zR with no exception-bearing LSDA contract. Reject unknown, shared-signature or exception-bearing callers until independently supported.
3. Normalize all original frame addresses through SP/CFA/FP, including dynamic adjustment and derived pointers. Prove the whole aligned 24-byte result region is allocated, nonoverlapping and nonescaping throughout its live interval, with no unsupported interior pointers, raw field copies, boxing or address consumers.
4. Initially reject multiple GetEnumerator definitions sharing a physical region. A later lifetime extension must prove all-path ordering, dominance, consumers and closed generic type for each definition, including same-slot reuse by different T.
5. Prove native X0 buffer-pointer and X8 uses dead using the complete relevant CFG and typed call ABI, not merely a target match. Preserve exact pre-SSA native-address/ISIL correspondence and clone branch targets without mutating originals on rejection.
6. Require unchanged actual recovered CIL to store the aggregate into the same correctly typed local consumed by MoveNext/Current/Dispose, with no scalar aggregate initialization, retarget controls or added defaults. Validate actual native/CIL fragments and existing regressions before any production extension.
7. Before admitting exception-bearing callers, decode exact FDE/CIE LSDA encodings, call-site ranges, landing pads and cleanup/action/type chains. Include exception paths and their buffer consumers/aliases in lifetime and escape proofs; recover the corresponding CLR EH/rethrow behavior. Ordinary reachable CFG omission cannot prove cleanup dead.

Read-only static candidate assessment and actual metadata resolution only. The current contract has zero eligible new game callers, so no generalized adapter or acceptance prototype was attempted. This does not prove full storage ownership for rejected candidates or count recovered methods/runtime coverage. The existing pinned SetStage recovery retains its previously documented EH boundary. Full exception recovery is a confirmed prerequisite for expanding this receiver-only family safely.
