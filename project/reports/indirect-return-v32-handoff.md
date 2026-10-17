# v32 exact indirect-return recovery

Status: **PRODUCTION_ADAPTER_GATE_PASS_23_OF_23; WHOLE_GAME_DECOMPILE_INCOMPLETE.** The v32 full recovery finished and the independent recovered Enumerator fragment passed five runtime cases. Full source export and matching compiler checks finished; both complete game assemblies still fail compilation.

The exact reviewed Fight.SetStage correction is implemented in `refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64IndirectReturns.cs`, API `Apply(caller, instructions, nativeAddresses)`. Parent integrated it after raw branch targets resolve. All guards precede the sole mutation: the GetEnumerator call destination changes from native X0 to its original StackOffset(8). The helper does not alter TypeSizes, generated source text, output CIL, visibility, or game metadata.

The helper requires NSO metadata 24 opt-in, exact caller/callee/constructor FDE extents of 552/36/16 bytes and hashes, the canonical generic alias set, known reference T, sequential ref/int/int/ref fields spanning 24 bytes, exact MethodInfo identity matched to one registered alias, adjacent X8 buffer setup, reviewed raw storage sites, remapped clone-CFG branch identities, and dead native X0/X8 uses before overwrite. Missing or unsupported evidence fails closed. These restrictions apply to the single reviewed caller and are not a general generic-ABI recovery rule.

`reports/indirect-return-helper-v32.json` passes **23 of 23 checks**. Actual production GetIsil returns a call destination of **stack[8]**. Negative cases reject wrong callers/targets/buffers, disabled opt-in, incomplete or duplicate native addresses, escaping or overlapping storage, live X0/X8, malformed branches and consumers, unproved cleanup targets, and incomplete or nonzero initialization. They check rejection without mutation.

Two failures were resolved without weakening the guard. First, complete native enumeration exposed a fifth SP+8 address-take in cleanup at 0xC9F5DC, followed by the same Dispose target at 0xC9F5E0. Parent approved precisely that reviewed site; `reports/indirect-return-tail-provenance-v32.json` passes five static checks. Second, production metadata-neighbor decoding spans 560 bytes, while the caller FDE is 552 bytes. Trailing UDF padding caused a fallback synthetic Return, but the converter had not added a corresponding native-address entry. Parent paired each fallback void Return, HFA return copy and nonvoid Return with `ulong.MaxValue`. The helper's strict instruction/address count guard remains unchanged. The original canonical raw conversion already accepted; the production path accepted only after this correction. Earlier CS0165 was fixed by initializing the parent-owned local before its out assignment; the final Core build passed with zero warnings/errors.

The original negative observations are preserved in `indirect-return-helper-v32-initial-rejection.json`, `indirect-return-helper-v32-fifth-site-rejection.json` and `indirect-return-helper-v32-production-shape-failure.json`. Earlier reachable-CFG snapshots omitted the cleanup tail; that observation does not establish that StackAnalyzer alone removed it.

Independent recovered-CIL validation passed all five Enumerator composites using the actual call/store/consumer storage identities. It complements native and metadata checks; it does not establish complete SetStage behavior, exception regions, LSDA, unwind semantics or whole-game parity. The earlier v31b baseline accepted zero of five composites.

The exact experimental v32 patch contains 34 files, SHA256 `effbf13b420f98e3687780b7c0e78b39cfd3420068ca8802c1208be6ab92991a`. Reverse applicability passed. It is saved as experimental, not promoted. Its pinned source was reconstructed from the patch plus the upstream commit in `reports/cpp2il-hfa-experimental-lock.json`, independently of later v33 edits. The reconstruction matched the recorded raw UTF-8 CRLF source hash.

`reports/indirect-return-synthetic-parity-v32.json` passes **9 of 9 checks**. The exact production acceptance retains the strict instruction/address count guard for 184 ISIL rows. The address count was not separately exposed; equality follows from that unchanged guard passing. The audit also covers all three synthetic-emission sites in the locked converter source. HFA/nonvoid fallback paths were statically checked here and are not claimed as dynamically exercised.

Accepted gate hashes:

- Helper source: `8c89942388dd92070a024e2238754d40aa83c1d7448c302e1e51209b526a2365`
- IndirectReturnProbe Program.cs: `fbbadb3a2714d837dc02a36235152d44a0b843989cfb70dc1373d09363e240ca`
- Tested Core DLL: `341daafcadf39c4f62f75e9769f00deb5275ad198f9f194382ac175da8677669`
- Tail provenance script: `23a50c11211ecb43218ab8ceaba044dba8258ae440fc46b71a9aac44fd910b44`

Infrastructure checks passed: 69 Python unit tests, 65 USB boundary cases, 123 Python AST files and 22 PowerShell syntax files. Exact logs are under `logs/v32-infrastructure-*`; syntax inventories contain per-file hashes under `reports/v32-infrastructure-*-syntax.json`.

Both source exports and restores returned zero. Ordinary exported-project builds failed with 1 unique diagnostic line for firstpass and 10 for main. Matching legacy-reference builds also failed: **19,263 unique diagnostic lines for Assembly-CSharp-firstpass and 30,155 for Assembly-CSharp**. See `reports/recovered-source-profile-legacy-reference-check-nso-enumerator-return-v32.json` and the recorded per-assembly full compiler logs. Counts describe deduplicated diagnostic lines, not independent root causes or completeness percentages.

No Windows or PS5 port is implemented or claimed by this work.
