# Ordinary class guards: bounded proposal, not production recovery

Richer SSA metadata-origin proof establishes which class a constructor request addresses. It does not establish the native guard predicate semantics, preservation of field reloads, or exception-control-flow coverage. The v34 identity change can recover the exact `RunClassConstructor` target while leaving those independent raw-flag problems explicit.

The next conservative extension should use the existing bounded native CFG matcher only for exact FDEs whose original CIE is `zR`, with omitted LSDA encoding and no personality. Every exception-bearing, unknown, ambiguous or malformed range must remain outside this extension. The existing bounds-only API currently skips FDE augmentation; returning an exact byte size alone does not prove this eligibility condition. A future bounds/eligibility API must retain and verify the original CIE contract without changing method identities, registered pointers, or unrelated body selection.

Use the existing native CFG matcher's known initializer identity, stable metadata-slot witness, interior-entry checks, flag liveness, branch equivalence, exact instruction widths and side-effect restrictions. Do not extend acceptance merely because both flag loads are based on a local typed `Il2CppClass<T>`. If the later bounded Move/Phi provenance proof cannot establish exact original type identity, the constructor request must remain unresolved rather than acquire a guessed managed type or become a no-op.

## Original witnesses

`class-guard-cfg-native-witness-v35.json` records sanitized hashes, exact ranges, counts and exception findings. Full unchanged disassembly, direct-branch CFGs and references to immutable v33 typed snapshots remain in ignored local `analysis/reconstruction/class-guard-cfg-v35/native-witness.json`. GOT `0x3982F58` points to metadata slot `0x3B34FB8`, identified as `BundlesUtil_TypeInfo`. These observations do not execute guest code or establish runtime equivalence.

`GetAssetBundleSafe` is the plain `zR` frame `0x4A8920..0x4A8A20`, 256 bytes, SHA-256 `07369c1cddf45700ee6c60c559312bc29ed5debc2c953755d9ac7d7c1414991c`.

- The first guard loads the class at `0x4A8960`, reads byte flag `+0x122`, then reads 32-bit finished flag `+0xD4`. A zero finished flag branches from `0x4A8970` to cold helper call `0x4A89F8`. The fast path reads class static storage/currentConfig at `0x4A8974/78` and tests it at `0x4A897C`; the cold path reloads the class and currentConfig at `0x4A89FC/4A8A00/04`, then tests it at `0x4A8A08`. Their nonnull successors meet at `0x4A8980`. A normalization would require an independently proven equal-field-load/branch relation; the existing matcher intentionally rejects these extra reloads. Plain-frame eligibility alone must not change that rejection.
- The second guard at `0x4A8980` receives the exact class through the Phi examined in v34. If the helper at `0x4A8990` executes, it reloads the class/static storage/currentConfig at `0x4A8994/98/9C` before joining `0x4A89A0`. Jumping directly to that join with the old X8 would skip the reload. Type identity alone does not justify that. A future stronger proof would need either the full conditional reload semantics or a separate definite-initialization fact on every incoming path; neither is implemented or claimed here.
- The already recognized final sequential guard starts at `0x4A89D0`, invokes the helper at `0x4A89E0`, and joins at `0x4A89E4`. The original `AssetsData.BundleName` load at `0x4A89CC` precedes the request and must stay before it. Later `GetAssetBundle`, the `AssetsData.Path` load and the write through the original ref-string argument must retain their order and conditional reachability.

`UnloadDependencies` is the exception-bearing `zPLR` frame `0x4A83A0..0x4A8520`, 384 bytes, SHA-256 `0fd52a9b449be83e29a7424dab0003da060929dbe574320d54ecfac5121483f2`. It is explicitly excluded from the proposed ordinary-method extension.

- The normal post-Dispose path loads a class flag at `0x4A8474`; its `TBNZ` at `0x4A8478` enters the shared finished check at `0x4A84E0`, inside a separately recognized cold guard starting at `0x4A84D8`. The cold route reaches the same finished check from `0x4A84DC`. Both can reach the original helper at `0x4A84E8`, followed by class reload `0x4A84EC` and the dependencies static-field load/Clear sequence at `0x4A84F0..0x4A8504`.
- Original LSDA at `0x2FE4DA8` has a bounded call-site table `0x2FE4DAF..0x2FE4DF0`, SHA-256 `4f4ce0131150d04463d410507771aabe06d5948f00c55e8a3244c3ab8d449b41`. The protected MoveNext range lands at `0x4A8498`, Current at `0x4A848C`, and AssetBundle.Unload at `0x4A8480`. Those landing paths execute cleanup and can reach `0x4A84D4/D8`. Absence of those predecessors from the existing ordinary reachable ISIL does not prove they are unreachable in the original game.
- The read-only inventory decodes call-site extents and landing addresses only. It does not implement action chains, type matching, personalities, stack unwinding, CLR catch/finally generation or exception parity. Whole-method recovery requires that independent work, plus the separately known Enumerator indirect-return gap.

## Required acceptance boundaries

Before extending production, verify plain `zR` eligibility against positive, `zPLR`, unknown-CIE, nonempty-augmentation, missing-range and ambiguous-range fixtures. Retain the existing native matcher unchanged for initial coverage. Reject unsupported cold/reload shapes and external or interior alternate entries rather than weakening branch or liveness checks.

Then validate accepted emitted constructor requests against original code with explicit runtime-state fixtures, and separately validate real CLR constructor effects, once-only behavior and exception timing at disclosed host boundaries. Preserve every original game-field load/store and semantic call that the accepted matcher does not prove to be compiler scaffolding. No initializer stub, fabricated flag constant, default substitution or broad `System.Type` pointer conversion should count as recovered logic.

The companion `class-guard-eh-eligibility-inventory-v35.json` groups static known-helper candidates by original CIE and inventories actual emitted CIL exception regions. Its native frames and managed method bodies have different sharing/ownership denominators; it does not report a global EH recovery percentage or authorize any class-guard rewrite.

| Original CIE | Exact native frames | Static candidate callers | Static candidate sites | Future eligibility |
| --- | ---: | ---: | ---: | --- |
| `zR` | 145,335 | 14,657 | 30,418 | Plain-range precondition only; all existing matcher/provenance/effect gates still required |
| `zPLR` | 7,569 | 3,144 | 9,457 | Excluded |

The unchanged v33 output contains 60,744 method bodies in 44 DLLs, with zero emitted CIL exception regions and zero PE parse errors. In particular, actual emitted `BundlesUtil.UnloadDependencies` has zero regions despite the verified original native landing entries. This is an explicit unresolved exception-handling gap; native `zPLR` frames are not assumed to map one-to-one to managed catch/finally constructs.

The proposed API is `TryGetExactPlainBodyRange(MethodAnalysisContext method, out int size)`, alongside the existing bounds-only APIs. Internally retain the CIE description and FDE augmentation extent under the existing frame-cache lock. Accept only exact `zR`, expected `0x1B` frame pointer encoding, no personality/LSDA augmentation and an empty FDE augmentation. Reject other CIEs and malformed/unknown ranges. Preserve the general bounds API, selected value-this bodies, aliases and registered pointers. This API is a conservative ordinary-method selection prerequisite, not an interpreter or verifier of exception semantics.
