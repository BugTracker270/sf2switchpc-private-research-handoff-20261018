# Class layout helper ABI-only proposal

Status: DESIGN_ONLY; production changes and managed translation are unimplemented.

The exact original helper at `0xB04F60` takes one `Il2CppClass*` in X0 and returns Boolean in W0. Incoming X1 is not an argument: the helper constructs its internal lock argument at `0xB04F8C`. Correcting its captured signature can remove false MethodInfo liveness without implementing or suppressing its cold metadata/layout effects.

## Exact recognition boundary

Require the existing explicit experimental opt-in, NSO metadata version 24, original uncompressed image SHA-256 `bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968`, exact original FDE `[0xB04F60, 0xB04FEC)` and complete 140-byte SHA-256 `496575374643a8ca7a9f1181d685de0fa4ac68574a3cc50c315d52d74a4d7dd3`. Cache only per application identity, with thread-safe initialization. Accept only this direct target; arbitrary thunks, other addresses, changed ranges/bytes and the distinct managed `.cctor` helper `0xB2E720` are outside this proposal.

The official source and native evidence are frozen in `reports/class-layout-runtime-source-v37.json` (SHA-256 `2541a8779be99b5a8eb1adbb5987a58d0ec96520d8dbfdcbf271de87c84ba594`) and `reports/native-class-layout-bool-v37.json` (`4cde7bdd4c52d92cd7c41c2f5295e4cd8fc4bb83f9934ac5058ead97d9ac3258`). Initialized-path tests do not execute cold layout initialization, locking or unwind cleanup.

## Minimal pipeline change

1. In `NewArmV8InstructionSet.AddCallAt` (line 356), recognize this target **before** `MethodsByAddress`. Keep `OpCode.Call`, the numeric target, the original X0 destination and the original X0 class argument; capture no X1-X7/V0-V7 inputs. This is earlier than CFG/SSA and prevents false uses from creating unnecessary phis or keeping MethodInfo loads live. It changes neither call ordering nor native source-address mapping.
2. After `LocalVariables.CreateAll` (`MethodAnalysisContext.cs`, line 382), before `MetadataResolver.ResolveAll` (line 393), validate the exact recognized three-operand call shape and assign only its existing SSA result the canonical `System.Boolean` type. Reject any conflicting pre-existing result type. Keep the original result identity, including every real consumer; do not change it to a void call, a constant or a new local.
3. Use the same exact target recognizer to exclude this call from `ResolveStringLiteralAccessors`, `ResolveCalls`, `ResolveCallsViaMethodInfo`, `ResolveAmbiguousCalls` and `ResolveConstructorCalls`. Neither coincident managed aliases nor an old MethodInfo value may determine its signature. A shared target predicate remains applicable to copied instructions without introducing synthetic managed metadata identities.
4. Retain the numeric unresolved target through the emitter. `IlGenerator.cs` lines 406-416 currently emits `Method not found @B04F60`; this diagnostic must remain. `DeadCodeEliminator` excludes calls, so dropping false argument reads does not remove the helper effect. Do not implement `true`, `RunClassConstructor`, `CallVoid` or an ordinary managed stand-in. Emission remains intentionally non-executable until its semantic boundary is separately recovered.

Expected narrowly scoped checks: exact target/range/hash accepts and changed-image/target/range negatives; original destination and sole X0 source identity preserved across SSA; live Boolean return preserved; stale X1 MethodInfo cannot resolve an alias; the helper diagnostic and cold-effect limitation survive. Correcting a signature does not prove a recovered method executable.

## Read-only source baseline

| Source under `refs/Cpp2IL/Cpp2IL.Core` | SHA-256 |
|---|---|
| `InstructionSets/NewArmV8InstructionSet.cs` | `b463b461da33a0359254813552777d96b4b718bdf195144f418506cea38f3d8b` |
| `Model/Contexts/MethodAnalysisContext.cs` | `3630c47dbb88e1ef06fb1e9fe41a4ab491243ac4bb03c7c1d0ea6f58d5fe8c37` |
| `Analysis/LocalVariables.cs` | `19a5e9330da015c80b0891f772ce9d6949f9010c0dfde3d895aac44da59791af` |
| `Analysis/MetadataResolver.cs` | `f478e416fc3bcb7542cdb1d12c5b47a9cea2f5288a0271055114f0e812ea558b` |
| `Utils/BaseCallingConventionResolver.cs` | `c5489016f9d9368ebf0a92849e099e78ec3e82e2ae71f095ec2dd0eb4be8b715` |
| `IlGenerator.cs` | `26d820b2c81b00d374f57f099cc326f4c2bc9032deb9d2a8759ae4034af08266` |

This proposal contains original analysis only. Licensed runtime source remains local and ignored. No Core file, reconstructed game body, key or platform SDK was modified or copied here.
