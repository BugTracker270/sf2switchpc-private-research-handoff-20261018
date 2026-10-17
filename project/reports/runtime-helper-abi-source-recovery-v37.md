# Native runtime helper ABI checkpoint

SCOPED_NATIVE_HELPER_ABIS_VALIDATED_HELPER_SEMANTICS_UNRESOLVED

Two native helper signatures now retain their real X0 inputs/results without phantom MethodInfo arguments. Both semantic helper calls remain unresolved diagnostics; full clean decompilation and portable source remain incomplete.

| Complete matching-reference source check | Firstpass diagnostics | Main diagnostics |
|---|---:|---:|
| nso-virtual-dispatch-v36 | 20843 | 32879 |
| nso-runtime-helper-abi-v37 | 20733 | 32724 |

Required evidence gates: 49/49. Failed gates: none.

Independent scopes: initial class-only51 checks retained separately; final dual-helper96 contract checks; actual production51 checks; exact native initialized-layout512 cases/3,584 checks. These counts do not certify cold helper effects.

Read-only prefix inspection: two callvirt sites; eligibility `True`; runtime performed `False`; cases `0`.

Separate isolated prefix execution: 802 cases / 7218 comparisons. One clone retains47 original instructions and95 locals, remaps6 exact-member sites/one branch and adds one return at the Length-store fence. Host MemoryStream and private-field access are explicit boundaries. Complete Read invocations: 0.

Only signatures/liveness and original input/result identities are recovered for these two helpers. Numeric diagnostics, factory result/throw, cold metadata setup, native message conversion/construction, locks, cleanup and unwind remain unresolved. Prefix inspection, native initialized-path fixtures, authored emitter/host contracts and established recovered-code probes are separate scopes. No complete reader/game execution or full clean source is claimed.

Unpromoted candidate: `src\re\tool-patches\cpp2il-sf2-hfa-experimental-runtime-helper-abi-v37-complete.patch`; SHA-256 `b1464e78b1050c413a0be732bf35db5ef4d72ad79e776853a7cc7fbe08e9136c`;40 files. Initial codec/batch failures remain preserved separately.
