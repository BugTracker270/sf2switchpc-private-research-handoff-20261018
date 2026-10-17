# Shadow Fight 2 Switch — full decompilation handoff

Prepared on **17 October 2026, Asia/Riyadh**, from the actual project at `F:\SF2SwitchPC`.

## To the incoming AI

Your independent reverse-engineering expertise is being trusted with the difficult part of this project. Please bring your strongest technical judgment, investigate the failures directly, and improve or replace the inherited approach when the evidence supports it. The user wants you to carry this through to **correct, buildable recovered game logic suitable for a later complete OS port**. A new plan, metadata shells, a compiling collection of empty methods, or optimistic tool counters will not satisfy that request.

This document tells you exactly where the previous implementation stopped, including its uncomfortable findings and unfinished code. You have a substantial private evidence corpus to work from. You do **not** have a finished decompile. No capability claim about any AI guarantees that the remaining recovery is automatic.

**Current assignment:** finish the full clean decompile, then stop and return the complete project and evidence to the user. Windows 10 / PS5 homebrew port implementation is a later phase. Do not start a replacement fighting game, substitute the Android release, or deliver an emulator wrapper.

## 1. Read this state correctly before executing anything

There are three different states on disk:

| State | What it actually represents |
|---|---|
| Last local Git checkpoint, v39 | `f51919b11eba685c83f25fe755cd1d8c827caa87`; scoped getter recovery accepted, full game source still fails |
| Latest completed recovery/compiler run, v40 | `nso-object-isinst-abi-v40`; 44 DLLs generated, source exported, both complete source builds fail, 18 bounded regressions pass |
| Current upstream working-tree source, proposed v41 | Seven carrier edits plus one new origin helper; **never built, never contract-tested, no production recovery hook** |

**Do not run the ordinary recovery wrapper assuming it will reproduce v40. It first builds the current working tree, which contains unvalidated v41 edits.** The compiled Core left on disk is still v40, whereas some live `.cs` files are newer.

The latest v40 evidence summary is:

- `reports/object-isinst-abi-source-recovery-v40.json`
- Status: `OBJECT_ISINST_ABI_ADDED_DIAGNOSTIC_REVIEW_PENDING`
- **37 evidence gates PASS, 1 PENDING**. The pending gate is attribution of eight added compiler diagnostics.
- `full_clean_decompile_ready = false`, `whole_game_source_ready = false`, `portable_game_ready = false`.

Latest authoritative complete matching-reference source compiler:

| Assembly | v39 | v40 | Change | Full build |
|---|---:|---:|---:|---|
| Assembly-CSharp-firstpass | 20,534 | **20,393** | −141 | FAIL, exit 1 |
| Assembly-CSharp | 32,710 | **32,399** | −311 | FAIL, exit 1 |
| Combined | 53,244 | **52,792** | **−452** | Both fail |

These are canonical compiler diagnostic-line counts, including cascades. They are not independent defects, recovered-method counts, or a completion percentage.

The most important newly confirmed limitation is larger than the eight diagnostics:

> All 44 actual injected `NoteDecompilerIssue` methods are a bare `ret`. They do not log or throw. The two game assemblies contain **61,133 diagnostic-helper call sites across 10,834 methods**. In a sampled constructor, 28 unresolved helper results have no emitted assignment and can read as implicit null through `InitLocals`. A successful build would therefore be insufficient evidence of correct recovered behavior.

Source: `reports/diagnostic-scaffolds-nso-object-isinst-abi-v40.json`. Its census inspects 28,119 method bodies in the two game assemblies, including injected infrastructure. Bodies without diagnostic calls and minimal bodies remain **semantically unclassified**; do not count them as recovered by subtraction.

## 2. User intent, authorization, and the cloud change

The original master specification is `input/reference/SF2_Switch_to_Windows10_Codex_Master_Prompt.md`. Read it completely, along with `AGENTS.md` and `reports/decompilation-acceptance.json`.

Several original statements are historical. Its opening says no binary has been inspected; that is no longer true. Its original end goal includes a native Windows port and hardware FPS measurements. Later direct user instructions narrowed the present phase to **full clean decompilation first, then stop before porting**. Those later instructions control this phase.

The user has now explicitly chosen to give another AI the **full project/USB folder in that AI's cloud environment**. This supersedes the original local-only execution requirement for that user-selected private cloud handoff. It does not authorize public redistribution, public repository uploads, sending inputs to unrelated analysis services, or disclosure of keys. The outgoing agent has not uploaded the project anywhere; the user will provide it.

On receipt of the user's folder and this handoff, ordinary implementation/research inside the designated private workspace is the intended authorized work. Do not manufacture another approval gate for each reversible local change. Respect the actual receiving environment's permissions and ask only for a genuinely missing input, material scope decision, or an action requiring separate authorization.

The user authorized work on their supplied material. Do not fetch commercial game copies, Nintendo keys, leaked SDKs or bundled third-party Nekki assets. Existing key material is private and must never be printed. Keep proprietary inputs, recovered source and assets out of public Git/remotes, issue reports, telemetry attachments and online decompilers. Public upstream tool downloads can be researched without transmitting private inputs.

Preserve the Switch edition: its actual 1.1.0 content, story rebalance, Sensei story, equipment/UI, offline behavior, local two-player Sparring and four save slots per profile. Mobile/raid class names remaining in an assembly do not establish that those modes are reachable in the Switch release. Do not infer active features from names alone.

## 3. Folder to transfer and cloud adaptation

The canonical project is **`F:\SF2SwitchPC`**, on a verified SanDisk USB disk, BusType USB, exFAT. `F:\Reverse engineering shadow fight 2` was the chat's starting directory, not the canonical project output root.

Transfer the entire canonical directory, including hidden files, nested `.git`, ignored folders and raw evidence. **A Git clone or Git bundle alone is insufficient.** Most essential game inputs, extracted assets, binaries, databases, logs and tool builds are deliberately ignored.

Important directories:

| Directory | Contents |
|---|---|
| `input/` | Authorized original NSPs, key files and master specification; originals read-only by policy |
| `unpacked/effective/` | Verified patch-aware ExeFS/RomFS view already ready for analysis |
| `analysis/nso/` | Original decompressed NSO, Ghidra projects, native corpora, unwind inventory, SQLite index |
| `analysis/il2cpp/` | Dumper mappings, recovered DLL runs, source exports, compiler projects, immutable tool snapshots |
| `analysis/assets/` | Raw/typed asset catalogs, AssetRipper output, decoded content/audio |
| `analysis/reconstruction/`, `analysis/reference/` | Private CIL/IR/native experiments and source comparisons |
| `refs/` | Pinned upstream source checkouts, including locally modified Cpp2IL |
| `tools/`, `cache/` | Downloaded tools, runtime packages and redirected caches |
| `src/`, `tests/` | Original infrastructure, converters, analysis programs and bounded probes |
| `reports/`, `logs/` | Evidence, exact failures, compiler logs and manifests |
| `backups/` | Git bundles and byte-exact evidence/source snapshots |

### 3.1 Do not pretend a cloud directory is a USB volume

`src/tools/UsbBoundary.ps1` deliberately requires a writable physical USB disk at `<drive>:\SF2SwitchPC`, using Windows `Get-Partition` / `Get-Disk`. It will fail in an ordinary cloud directory. This is expected, not missing game data.

For cloud execution, choose one canonical private workspace root, e.g. a user-provided `/workspace/SF2SwitchPC`, and implement a **separate documented cloud adapter** with equivalent resolved-path containment, no traversal/symlink escape, cache redirection, read-only inputs and free-space checks. Preserve the original Windows guards and receipts. Do not silently make USB verification return true.

`src/tools/usb_boundary.py` already performs filesystem containment without proving physical USB. Most Python tools derive `ROOT` from `Path(__file__).resolve().parents[3]`, so their source-relative root can survive relocation. Windows path values embedded in their inputs may still need adaptation.

### 3.2 Cross-host traps

- Existing reports/logs contain absolute `F:\SF2SwitchPC` paths. Preserve their bytes; use an explicit old-root → new-root mapping in new working artifacts.
- Generated `.csproj` files contain absolute Windows HintPaths and compile globs. Regenerate equivalent infrastructure projects for the new host while keeping original exported `.cs` bytes unchanged for comparisons.
- On Linux, a backslash in a historical JSON path is not a normal separator. Normalize with explicit Windows-path parsing, such as `PureWindowsPath(...).parts`, rather than accidentally creating filenames containing backslashes.
- The canonical compiler comparator parses historical Windows log paths. Port that parsing deliberately before rerunning against old logs on Linux. Do not rewrite old logs to make it pass.
- Preserve filename case and byte hashes. Avoid text-mode transfer, line-ending conversion, automatic Git checkout over raw evidence, or wholesale search-and-replace in the only copy.
- The tool/probes use **.NET 10 / C# 14**. Host-installed Windows SDKs, Python, Java, PowerShell and virtual environments are not made portable merely by copying the USB.
- Portable managed DLLs still need compatible dependencies and runtime configuration. The frozen three-DLL snapshot alone is not a self-contained runnable CLI. Preserve the full existing `bin/Release/net10.0` directories, `.deps.json`, `.runtimeconfig.json` and dependency DLLs, or rebuild a pinned source state in an isolated workspace.
- Windows `.exe` launchers and native `.dll` packages may need host-native upstream equivalents. Check architecture and dependencies; do not assume Wine is required or sufficient.
- NuGet/Python caches may contain useful packages but do not guarantee all host-native artifacts are usable. Use verified official dependencies inside the workspace, with versions/hashes recorded.
- A cloud build can produce a different tool binary hash because the toolchain/build environment differs. Preserve historical hashes and record a **new** build identity; do not edit pinned probe constants merely to report PASS.
- Source tools can rely on neighboring probe `bin` directories as dependency sources. Read each `.csproj`; retained binaries and the source that produced them both matter.
- Direct probe DLL invocation should target a deliberate immutable Core/dependency set. Serialize Core builds and shared initializer writes.
- Keep a free-space reserve. Windows was around 62 GiB free at the last full pass; the project has many small files and large analysis artifacts. Measure the cloud copy instead of guessing capacity.

The original Windows cache initializer is `src/tools/Initialize-UsbWorkspace.ps1`. It sets process-scoped `TEMP/TMP/TMPDIR`, pip, NuGet, npm, cargo, Gradle, dotnet, Java and XDG paths. Do not replace `HOME`, `USERPROFILE` or account configuration globally. Apply an equivalent explicit cache policy in the cloud workspace.

The companion read-only verifier is portable Python 3.11+:

```text
python src/tools/verify_ai_handoff.py --root /your/private/SF2SwitchPC
```

It verifies the selected critical files in `AI_HANDOFF_EVIDENCE_MANIFEST.json`, including these handoff documents, frozen evidence and the exact unbuilt source. It does not modify the folder, read keys or certify recovery. Add `--include-game-inputs` only when you want to rehash the listed large game inputs. The default manifest checks are not a complete inventory of the entire project. This original verifier is documentation/transfer infrastructure, not an additional decompilation change.

## 4. Proven source identity — extraction is already finished

The target was empirically identified as:

- Game: **Shadow Fight 2 Nintendo Switch Edition 1.1.0**.
- Unity: **2018.1.9f1**, IL2CPP metadata **24.0**, native **ARM64**.
- Base title: `0100AB000ABFE000`, CNMT version 0.
- Patch title: `0100AB000ABFE800`, CNMT version 131072.
- All 12 observed NCA filename IDs match content hashes; CNMT content hashes were checked.

| Input | Relative location / SHA-256 |
|---|---|
| Base NSP | `input/base/Shadow Fight 2 [0100AB000ABFE000][v0][Base].nsp` — `98d2d44f224321a174ce672826c5ece77d4f98350da336a21ffefc247e36cba5` |
| Update NSP | `input/update/Shadow Fight 2 [0100AB000ABFE800][v131072][Up v1.1.0].nsp` — `21831c39c058b815d838a7543678685ef89e1e95778753e71091ae3b8415b8f8` |
| Effective compressed main | `unpacked/effective/exefs/main` — `94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238` |
| Decompressed original NSO | `analysis/nso/main-uncompressed.nso` — `bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968` |
| Metadata | `unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat` — `f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85` |

The Cpp2IL loader also creates a **derived relocated/expanded loaded image**, 74,363,922 bytes, SHA-256 `b84d5b3eb4a3a12d3260b06840414445fb2d2deff54d1ba84876e8fa28549449`. That is a different hash domain from the original decompressed NSO. Do not “repair” either hash to match the other. Native RVAs are not raw NSO file offsets; a previous alternative tool had a proven 0x100 mapping error.

Read `originals_manifest/inputs.json`, `reports/extract-manifest.json`, `reports/engine-fingerprint.md`, and the registration-integrity reports. Do not repeat extraction just because the receiving host lacks Nintendo key tooling. The effective data and metadata already exist.

User-supplied keys are under `input/keys/`, with a tool-profile copy under `input/hactool-key-profile/switch/`. Their contents are not in this handoff or evidence manifest. They are unnecessary for the next method-recovery steps on already extracted inputs. Never print or publish them.

## 5. What has actually been recovered and where to find it

### 5.1 Metadata and native code

- `analysis/il2cpp/effective-main/`: Dumper output (`dump.cs`, `script.json`, type headers and DummyDll shells). Approximately 90,105 method records at 83,673 distinct metadata addresses. **DummyDll does not contain original method implementations.**
- `analysis/il2cpp/research.sqlite`: searchable metadata/evidence index.
- `analysis/nso/SF2-effective.gpr` and associated project directory: real Ghidra ARM64 project.
- `analysis/nso/corpus.sqlite`: indexed native exports. Inspect its schema before querying.
- `analysis/nso/native-corpus*`, typed feature overlays and repair folders: JSONL disassembly/pseudocode evidence. Prefer indexed bounded retrieval over dumping entire corpora into context.
- `analysis/nso/unwind-inventory-v1/frames.jsonl`: 152,904 validated nonoverlapping original frame ranges. Every managed metadata address occurs at an exact frame start. Range export success is not semantic recovery.
- Complete validated-range exports were produced for main (152,904 ranges), SDK (24,032), subsdk0 (9,774), rtld (23). Auxiliary modules remain separate corpora.
- `analysis/il2cpp/sf2-arm64-types-layout-v2.gdt`: 120,969 parsed Ghidra types. Independently checked layout anchors include static fields +0xB8, vtable +0x128 and array elements +0x20. The earlier stock runtime header was superseded.
- Registration integrity checks match all 83,673 distinct metadata method addresses to native pointer tables; this establishes membership, not every alias's exact behavior.

Useful index source programs: `src/re/tools/build_research_index.py`, `native_corpus_index.py`, `native_unwind_inventory.py`, `select_unwind_native.py`.

### 5.2 Assets and content

These are valuable recovered data, not a finished Unity source project:

- `analysis/assets/unity-export/`: AssetRipper output.
- 22,512 original serialized objects; `analysis/assets/source-objects.jsonl` records offsets/hashes.
- All 2,664 TextAsset payloads matched exports byte-for-byte.
- `analysis/assets/content-v2/`: 932 moves, 114 templates, 22 triggers, 559 custom point-frame animations. Version 1 misclassified two binary headers as XML; use v2.
- `analysis/assets/typed-components/`: 3,344 decoded component records. This is staging/layout recovery, not proof of complete scene behavior.
- 10 scene records, 232 decoded FSB5 audio banks, metadata-checked rates/channels/sample counts.
- `analysis/assets/ai-tables-v1/`: 1,578 AI archives, 6,084 validated blocks, including pools and 531 node-shift animations.
- Native-guided move/template resolution explains inherited/physics/no-animation filenames.
- Quest Include traversal reaches 165 initial definitions, including 30 Sensei quests; larger candidate action attachments are not complete scheduling/reward semantics.
- Four serialized save-slot bindings (0–3) were found. Complete save schema/durable persistence is unfinished.

### 5.3 Bounded behavior evidence

There are many real but limited tests: AI evaluator/native leaf comparisons, physics node integration, geometry/capsule/strike/damage slices, animation Bezier and node application, quest lookup, currency codecs/wallet arithmetic, save timer scheduling, scalar/HFA/accessor/boxing/constructor/enumerator slices. Reports state their exact initialized state, synthetic memory, allocator, host framework or runtime-call boundaries.

Examples: 8,704 original node ticks / 53,248 float-bit checks; 4,186 capsule cases / 29,302 comparisons; 704 Bezier cases / 54,336 comparisons; 1,019 quest lookup comparisons; save scheduling 5,120 comparisons. These are not complete game execution or proof of every caller.

The v38 unchanged complete `XmlExtensions.TryGetAttribute` helper passed 26 host `System.Xml` cases / 104 comparisons, with five observed virtual getter calls. Native XML parity remains unproved. The v37 reader test executed a separate cloned 47-instruction prefix over 802 cases / 7,218 comparisons; **whole `Read` execution was zero**.

Read `STATUS.md`, `reports/analysis-coverage.json`, feature reports, `reports/native-regression.json`, `reports/local-sparring.md`, `reports/save-research.md`, and `reports/platform-dependency-matrix.csv`. Their scopes matter more than their large counters.

No Windows game executable, full startup/fight loop, original-game playback parity or measured 120 FPS result has been achieved. A playable original reference/recording was discussed but not established as supplied. It is not a blocker for current static/native method work. The user mentioned a PS5 SDK on the original host; its installation/license/version was not verified, it need not be present in the cloud copy, and it is unnecessary for this decompilation phase.

## 6. The main hurdle, accurately stated

**Recover correct typed executable method bodies from optimized ARM64 IL2CPP code, with original control flow, runtime contracts and exception semantics.**

The file formats, keys, engine and basic symbols are no longer the central problem. Current tools can produce plausible structures and C-like/CIL output while losing the semantics needed to compile and execute it correctly.

The current pipeline still has important failures in:

1. Native runtime helper semantics, dynamic class/type metadata expressions and pointer-versus-managed-object handling.
2. Correct call argument/result ABI beyond the tested bounded HFA/value-type/indirect/virtual shapes.
3. General virtual/interface/generic/delegate calls and receiver provenance.
4. Optimized/inlined code, copies/joins, unsafe/interior pointer expressions and exact managed operation recovery.
5. Production exception handlers, cleanup, exception-entry roots/SSA and unwind translation.
6. Behavior-relevant original attributes and complete serialized Unity project reconstruction.

There is **no demonstrated single missing tool or helper fix** that makes the rest automatic. A broadly reliable IL2CPP-aware ARM64 typed/control-flow/exception recovery pipeline would materially change the outlook. Access to the authorized original Unity/C# project would be the biggest shortcut, but no such source has been supplied.

You are free to identify a better approach. Evaluate it on unchanged real outputs and execution evidence. Do not assume prior conservative heuristics are optimal, and do not remove unresolved behavior merely to improve compiler counts.

### 6.1 Critical diagnostic-scaffold discovery

`IlGenerator` handles an unresolved numeric call by emitting a diagnostic string and calling the injected issue helper. It does not evaluate that call's original arguments or assign its result. The actual injected issue helper body is byte `2A` (`ret`), SHA-256:

`684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1`

Thus “diagnostics retained” means retained evidence of missing recovery, **not retained runtime effects or a failure trap**. Some standalone emitter fixtures instead used a `Console.WriteLine` fallback because no injected helper was attached. That fixture behavior is not the actual complete output's behavior.

The sampled `InControl.PlayStation4MacBTProfile::.ctor` has 28 Object::IsInst issue sites, 32 total issue-helper calls and 28 unassigned Object result locals. `InitLocals` can supply implicit null if reads are reached. The method was not executed or JIT-validated.

Five sampled `System.Array` methods (`get_swapper`, `int_swapper`, `obj_swapper`, `double_swapper`, `compare`) still have unchanged default exported bodies of 2/1/1/1/2 CIL rows. Their nine native helper calls were observed only in separately forced analysis. They get **no emitted-body recovery credit**.

`reports/unknown-operation-emitter-contract-design.md` proposes a separate fail-loud contract. It is **not implemented**. Making unsupported operations throw would expose incompleteness, not reconstruct their effects. Ultimately the full-source acceptance gate requires resolving the missing behavior, not just trapping it.

### 6.2 Exception handling is a separate major blocker

All 44 DLLs inspected at v33 had zero CIL exception regions, while original `UnloadDependencies` LSDA has three landing entries. The bounded metadata parser and standalone region validator recover/check structure only. They do not emit production handlers, establish exception-entry SSA, perform cleanup translation or execute unwinding.

Reports: `class-guard-eh-eligibility-inventory-v35.json`, `exception-metadata-parser-v35.json`, `exception-metadata-independent-review-v35.json`, `exception-region-design-v36.json`, `exception-region-independent-review-v36.json`.

The ordinary CFG route added at v35 requires exact zR frames with empty augmentation. An older selected route still includes twelve zPLR bodies with unverified exception semantics. Do not silently treat ordinary reachability as exception-aware control flow.

## 7. Toolchain already investigated

Primary corrected tool: `refs/Cpp2IL`, MIT, pinned upstream commit:

`b5ad444b82267cb1e4b88b8b373c008105bdea52`

The local experimental patch is extensive and opt-in through `CPP2IL_LEGACY_HFA=1`. Despite that name, it contains many later recovery corrections in addition to HFA work.

Other installed/researched tools include hactool 1.4.0, Ghidra 12.1.2 plus compatible Switch Loader, Il2CppDumper 6.7.46, AssetRipper 2.0.0, ILSpy command line 11.1.0.9782, Unicorn 2.1.4 and native-analysis Python libraries. Use `reports/toolchain-lock.json`, `repo-triage.md`, and per-tool locks for exact pins/licenses/platforms. Do not execute arbitrary new downloads without provenance review.

REA 6.5 setup was blocked on this machine by its fixed-NTFS requirement against the exFAT USB. Host agent configuration was not changed. Ghidra headless work succeeded as the fallback. The old Windows-specific block need not apply to a new host, but REA is an analysis interface, not a complete source recovery engine.

The verified official Unity 2018.1.9f1 archive was used only for selected common runtime source, not as an installed/executed editor:

- Revision `24bbd83e8b9e`.
- Archive SHA-256 `ce666b2de60716cb5564b53317b56f0b82eddbea7afb3462ef51d5e121833c96`.
- Official MD5 `2b59d01b17b0f7acf2ff36a083bdd0d2` matched; the local/API size discrepancy of 272 bytes was explicitly recorded.
- Source and license artifacts remain private under `tools/` / `analysis/`.

### 7.1 Avoid repeating tool marketing as a solution

`reports/tool-survey-20261017.md` records actual trials and upstream evidence as of that date:

- BetterCpp2IL built and ran, but its unchanged output contained empty/auto-property/unresolved bodies; all nonempty sampled source assemblies failed compilation. Its success counters were not recovery proof.
- `rodroidmods/il2cpp-dumper-rs` produced 44 assemblies after mapping work, but strict type-load tests still failed; cross-assembly `__External_<index>` placeholders and native absolute-memory expressions remain. Mapping correction did not solve semantic recovery. Preserve the GPL/MIT licensing discrepancy described in the report.
- The reviewed UREngine repository provided docs/images and a network closed-beta description targeting Unity 2022 Android ARM64. It did not establish a usable local Unity 2018 Switch pipeline. No proprietary inputs were submitted.
- Il2CppInspectorRedux offers metadata/stubs/C++ scaffolding; no demonstrated complete method-body recovery here.
- Il2CppInterop/unhollowing calls the existing native runtime and is not independent portable source reconstruction.
- Another native decompiler can help specific functions, but C-like pseudocode is not a rebuilt managed game.

You may investigate newer or more suitable approaches. Record what actually improves this exact target instead of assuming names such as “full decompiler” imply success.

## 8. Recent validated history and immutable checkpoints

| Version / run | Narrow change / result | Full source diagnostics firstpass / main |
|---|---|---|
| v36 `nso-virtual-dispatch-v36` | Bounded native virtual dispatch; actual full reader prefix still unresolved | 20,843 / 32,879 |
| v37 `nso-runtime-helper-abi-v37` | Exact Class::Init / overflow-factory ABI; prefix clone tested, whole reader not executed | 20,733 / 32,724 |
| v38 `nso-virtual-companion-copy-v38` | Paired companion copies; one unchanged whole XML helper tested at host boundary | 20,728 / 32,710 |
| v39 `nso-assembly-leaf-getter-v39` | Existing same-assembly internal getters recover private reads without changing visibility | 20,534 / 32,710 |
| v40 `nso-object-isinst-abi-v40` | Exact Object::IsInst raw signature and nominal result; helper behavior still absent | 20,393 / 32,399 |

Counts can rise after a more accurate correction exposes existing invalid operations. Do not select a less accurate old run just because its diagnostic count is lower.

v39 is the latest Git checkpoint, not v40. It passed 36 scoped evidence gates, 78 contract checks, 15 original constructor-pipeline checks, 118 fresh-output checks, separate native getter 128 cases / 384 checks plus null fault, and 18 bounded regressions. Ninety-nine Serializer reads use the existing internal property; two private constructor stores remain errors. Six added diagnostics were traced through 275 checks to prior unchanged invalid arithmetic/cast operations. Those operations remain unresolved.

Useful v39 artifacts:

- `reports/assembly-leaf-getter-source-recovery-v39.json` — SHA `31eea7052d086fd9b758341692323597de250de76db2f3c71a1f5276a44b4b07`.
- `backups/research-assembly-leaf-v39.bundle` — verified local Git bundle.
- `backups/assembly-leaf-getter-v39-raw-evidence.zip` — SHA `b26d99b68360e4c483e32544f05efb2fb7c2ef7d815b7b0adecae6c73f19eb43`; 943 files / 223,472,392 raw bytes, per-entry hashes verified.

The final in-progress save before this handoff is:

- `backups/in-progress-v40-v41-20261017T191744Z.zip`
- SHA `4b2765b6b97ddd780f5b59dbbe0ad0140062f1d7f6ee98c5e2234a19efca4e5e`
- 199 files, each entry byte-verified; includes uncommitted infrastructure/reports, modified upstream source and frozen v40 sources/tool binaries.
- Receipt: `reports/in-progress-save-v40-v41.json`.

This save is supplemental. It does not replace the complete ignored project data and logs. Git normalizes some line endings; raw evidence ZIPs preserve the bytes whose hashes the reports cite.

Earlier v37 packaging had a real omission: a nominally successful reverse check did not prove all changed files were packaged. The repaired complete candidate has 40 paths and includes `MethodAnalysisContext.cs`. Use `cpp2il-sf2-hfa-experimental-runtime-helper-abi-v37-complete.patch` if reproducing v37, not its older incomplete namesake. Current packager rejects omitted modified/untracked paths.

## 9. Latest v40 artifacts, exact identities, and pending eight diagnostics

### 9.1 Paths

| Purpose | Relative path |
|---|---|
| 44 generated DLLs | `analysis/il2cpp/cpp2il-recovery-nso-object-isinst-abi-v40/` |
| Complete C# exports | `analysis/il2cpp/source-profile-project-build-nso-object-isinst-abi-v40/Assembly-CSharp{,-firstpass}/` |
| Legacy decompiler resolution view | `analysis/il2cpp/decompiler-reference-view-nso-object-isinst-abi-v40/` |
| Authoritative compiler projects | `analysis/il2cpp/source-profile-legacy-reference-check-nso-object-isinst-abi-v40/<assembly>/MatchingReferences.csproj` |
| Exact invocation | `logs/cpp2il-nso-object-isinst-abi-v40-result.json` |
| Authoritative compiler logs | `logs/source-profile-legacy-reference-build-nso-object-isinst-abi-v40-<assembly>.log` |
| Frozen 41 source paths | `analysis/il2cpp/object-isinst-abi-v40-source-snapshot/` |
| Frozen three invocation binaries | `analysis/il2cpp/object-isinst-abi-v40-tool-binaries/` |
| Complete candidate patch | `src/re/tool-patches/cpp2il-sf2-hfa-experimental-object-isinst-abi-v40.patch` |
| Candidate/source/bin locks | `reports/cpp2il-hfa-experimental-lock-object-isinst-abi-v40.json`, `object-isinst-abi-v40-source-snapshot.json`, `object-isinst-abi-v40-tool-binary-snapshot.json` |
| Fresh CIL/IR evidence | `analysis/reconstruction/object-isinst-v40/` |
| Pending compiler source contexts | `analysis/reconstruction/compiler-additions-v40/source-context.json` |

Critical hashes:

```text
Cpp2IL.Core.dll       14232d46ca291ffb67944705e94ec5460bc8ee70c3df88ee3ef27e77b6e736d6
Cpp2IL.dll            3cd1e888a20bf2256c120a25102aad2cb276c2d068d8bdf1ea88ca3ab21ff9e3
LibCpp2IL.dll         c15339ded4039f7aaf827c80db38788a02ac3e86a016e24bcdefc9ef515d52df
Invocation JSON       3cd258cb7c4f4ba455cef66e5f05fee040dc83dff38bd80fd7ec03546ade6e1b
Complete 41-file patch 2a0844fb02086f0a7a0846f1d27592a4df91b2b691f006a9a84db7a1420d7dd1
Frozen source manifest 9d4f1247fcb384e9505e9d8eb7c023644947d55bf91fd0626875bef965e27076
Canonical delta       32b341c34c85d1354c855474e6a424067fc81e372baa3056560e7eb30be0b509
Current v40 summary   2c56ec47fccd3782cc8f994ad2066e1426cb36646ea1568f05cce52d8cf298e4
```

The frozen reverse check passed against the **frozen source tree**, not just live sources. Receipt: `reports/object-isinst-abi-v40-frozen-reverse-check.json`. When reproducing a Git apply check with explicit `--git-dir` and `--work-tree`, run with the frozen tree as `cwd`; otherwise Git can report misleading file-not-found failures.

### 9.2 What v40 actually validated

- Independent exact signature contract: 57 checks.
- Original-caller forced production stages: 41 checks.
- Independent fresh-output correlation: 41 checks.
- Separate original native wrapper oracle: 1,034 cases / 8,272 checks, with 1,024 **supplied** Class::IsAssignableFrom boundary results. It did not execute real assignability/COM semantics.
- Existing bounded regression batch: 18/18 pass.
- 44-assembly CIL syntax and stack/header audits pass only in their stated structural scope.

The fresh sampled constructor aligns 3,064 rows under 506 typed local identities, 342 branch targets and 375 metadata operands. Thirty-eight relocated tokens are identical string literals. Four zero stores into a never-read/address-escaped local became Nop; fourteen unused Object locals disappeared. All other aligned operations/control are retained. This does not make the unknown helper executable.

Key reports: `object-isinst-abi-contract-v40.json`, `object-isinst-abi-production-v40.json`, `recovered-object-isinst-abi-nso-object-isinst-abi-v40.json`, `native-object-isinst-abi-v40.json`, `recovery-regression-nso-object-isinst-abi-v40.json`.

### 9.3 The exact pending additions

Read these first:

1. `reports/compiler-diagnostic-attribution-v40-handoff.json` — SHA `50041ae6861a1da330d1d9e02a36390776c740097adea0f099f6e278f5a66632`.
2. `reports/compiler-diagnostic-added-locations-v40.json` — SHA `8b96b28ed39e7e66bfad06016ff2ccf52a5b9fac829f161f3d8965a3de069fb9`.
3. `reports/compiler-diagnostic-added-methods-v40.json` — SHA `29135673cc2824c160288dc4f3c0f113fdd873e5df6362edf6e76f5963f0b704`.

The following owner names are **textual declaration candidates**, not yet bound to verified metadata tokens/native methods. Lines refer to the v40 source export.

| Assembly/file | Candidate owner | Added diagnostic |
|---|---|---|
| firstpass `BestHTTP/Authentication/Digest.cs` | `GenerateResponseHeader(HTTPRequest, Credentials)` | line 803: CS0165 unassigned `obj25` |
| firstpass `Newtonsoft/Json/Converters/StringEnumConverter.cs` | `GetEnumNameMap(Type)` | lines 382, 389: two CS0030 `string* → object` |
| main `CocosAnimationData.cs` | `ParseFrame(XmlNode,string)` | line 958: CS0030 `object → int*` |
| main `Nekki/SF2/Core/API/ListSF.cs` | `GetFightNodeFromSlot(int,string)` | `object & int` occurrences 3→4; new alignment candidate line 10115 |
| main `Nekki/SF2/Core/API/Roster.cs` | `RemoveBattle(RosterBattle)` | same error 1→2; candidate line 3499 |
| main `Nekki/SF2/Core/MultiplayerSF/RaidConfigParser.cs` | `ParseRaidQuests(XmlDocument)` | same error 3→4; candidate line 985 |
| main `Nekki/SF2/Core/MultiplayerSF/RaidPerksContainer.cs` | `Parse(XmlDocument)` | same error 3→4; candidate line 168 |

All before/after locations for the four multiplicity-growth groups are retained. Do not assume the singled-out alignment candidate is the exact semantic addition. Bind source scopes to real method tokens/RVAs; compare v39/v40 CIL and original native pointer-result/null-control behavior. Do not infer original arithmetic from C# compiler wording. **None of the eight was accepted as harmless, unchanged prior behavior, or a correct recovery.**

Original tools for this saved work: `src/re/tools/capture_added_compiler_diagnostics.py`, `refine_added_diagnostic_methods.py`; exact logs are named `compiler-diagnostic-added-locations-v40.log` and `compiler-diagnostic-added-methods-v40.log`.

## 10. Immediate research thread: Object::IsInst and real array class provenance

This was the immediate thread at the stop, not a claim that it solves the whole project.

### 10.1 Exact helper and ABI

Original `Object::IsInst` is at **0xB5B390..0xB5B484**, an exact 244-byte FDE/body. SHA:

`1b265abeee0dfb0991ffe2b237b6cf3f817a9a5071eb8787a2dc28b87d9cbec6`

Official Unity 2018.1.9f1 common runtime source confirms:

```cpp
Il2CppObject* Object::IsInst(Il2CppObject* object, Il2CppClass* targetClass)
```

Original X0 is the object, X1 the class, X0 result is the original object or null. It is **not Boolean**. Other argument registers are not incoming dependencies for this helper. The actual function has null-object, ordinary-class and import/WinRT/COM branches, with calls, metadata and failure effects.

The v40 ABI-only carrier captures exactly `[numeric target, distinct X0 result, original X0 input, original X1 input]`, seeds canonical `System.Object` result type, excludes managed alias shortcuts and rechecks owner/target/opcode/count/result at emission. It does not prove source class origin, implement the helper, create managed `isinst`, fuse array stores or synthesize a return.

The existing automatic key-function finder still returns zero for this helper. A relevant Type method is a tail branch rather than the BL pattern expected by that finder. No global heuristic identity was silently enabled.

### 10.2 Why removing phantom captured registers was insufficient

There are 13,188 original BL sites to the helper across 4,783 FDEs. An earlier source survey found 3,355 array→nint diagnostics near it. A conservative actual-IR attribution across 650 source-owner candidates tied 2,954 of those to the **real** array→klass→element_class chain, not simply false X2+ argument captures; 401 remained unattributed and zero were proved phantom-only casts.

Reports: `compiler-mechanism-survey-v38.json`, `object-isinst-actual-ir-v38.json`, `object-isinst-native-source-proposal-v40.json`, `array-cast-use-attribution-v38.json`.

The sampled profile constructor is RVA **0x11A4CC0**, with 28 helper calls. First call is BL at **0x11A4D88**, IR row 63. Header read row 61 and element-class read row 62 feed the real X1 argument. The element class offset is +0x40, independently confirmed by official v24 layout.

The first original failure edge reaches `ArrayTypeMismatch` helper **0xB4DA50** at native **0x11A5C54**, before bounds load **0x11A4D94** and store **0x11A4DAC**. Preserve this ordering. Blind `stelem.ref` fusion can change the exception when both element type and index are bad. A parameter statically typed `object[]` can hold a runtime `string[]`; static element types are insufficient because of covariance.

The current idea was to prove actual runtime element class only for a **fresh unique typed `NewArr T[]`**, then separately prove object origin and helper semantic preconditions. The first profile sample has four NewArr roots feeding 28 textual projection candidates (two String, 26 mapping candidates). No semantic site was accepted or rewritten.

### 10.3 Original exact-class subpath oracle — useful, still not caller proof

`src/re/tools/execute_native_object_isinst_exact_class.py` executes original Object::IsInst plus original Class::IsAssignableFrom exact-class path with **zero function/return replacements**. Result: 40 cases / 320 checks; separate rejected controls stop before metadata initialization or import handling.

- Report `reports/native-object-isinst-exact-class.json`, SHA `59e64cb5942e30e3b5bafe177bc5052d5c10074fe8511eddce5878a221f581f2`.
- `Class::IsAssignableFrom`: **0xB05920..0xB05B7C**, 604 bytes, SHA `3cb95ce5d103a953c4db8d1a01c03eb5e0ca56c7162b58853ce0cc133d655d2e`.
- Its exact class-pointer comparison at 0xB05938 / branch 0xB0593C reaches the fast true path, skipping Class::Init calls at 0xB0594C / 0xB05954.
- The Object wrapper still reads object klass and its +0x122 import bit **before** ordinary assignability. Equal class pointers alone do not bypass classification.
- Synthetic ordinary object/class inputs are supplied. Data-read hooks observe only object header and ordinary flag reads; the direct assignability fast path reads no class storage.
- General assignability, COM, metadata initialization, failures/unwinding and production caller identity are not recovered by this test.
- The shared guest loader presets seven unrelated guard bytes; traced subpaths do not read them. Guest original text and input file hashes remain unchanged.

String provenance read-only evidence is in `reports/fresh-string-literal-source-v40.json` (SHA `12c107d22b9d8c46da47e05ae5b6332003512e1ca48d2c4e4f6fce759065d5b8`). First literal: GOT **0x39F3CC8 → slot 0x3B7A110**, metadata literal index **4849**, value `OS X`. First String[] metadata load: GOT **0x397A410 → slot 0x3B2DC88**. Unique mscorlib String definition: index 27, token 0x0200001C, byval 53, bitfield 0x8 (`HasCctor`, not import/WinRT).

Official String literal allocation uses `il2cpp_defaults.string_class`. However, per-site canonical runtime identity, slot initialization and actual dataflow still require proof. `StringLiteral` IR only holds a value and is also used for synthetic helper names; its text/type alone cannot certify an original managed String object. The first site's pre-resolve graph shows an actual registered literal-slot dereference, which could support a narrower retained provenance witness. Do not promote arbitrary synthetic literals.

### 10.4 Other designs are not implementations

- `reports/byte-array-layout-fusion-design-v40.json` and `reports/byte-array-layout-fusion-design-v40.md`: original Array::NewSpecific at 0xB5FE50 calls Class::Init. Possible duplicate-init composition for exact Byte[] allocation windows was studied; no helper removal/fusion implemented. Class::Init at 0xB04F60 is **bool metadata initialization**, distinct from running a managed `.cctor`.
- `reports/virtual-call-result-root-design-v39.json` and `reports/virtual-call-result-root-design-v39.md`: one-result receiver origin for FirstAttribute→Count, still a design, no Core integration.
- The earlier reader prefix clone/whole XML helper tests do not establish whole reader execution.

## 11. Exact unfinished v41 source — do not mistake it for validated progress

### 11.1 Seven-file native-read carrier

Saved incremental diff: `patches/experimental-native-read-proof-v41.patch`

SHA `834693154ec49d6e32d38bcb3a2b45e948de703fdda5f452acfe005ba8feaf04`

Design/source bindings: `reports/native-integer-read-carrier-design-v41.json`

SHA `19992499083688b68cb43ccf1f8ea55136ef25e6c262605a274577a35201b51d`

Edited paths under `refs/Cpp2IL/Cpp2IL.Core/`:

1. `ISIL/MemoryOperand.cs`
2. `InstructionSets/NewArmV8InstructionSet.cs`
3. `Analysis/SsaForm.cs`
4. `Analysis/LocalVariables.cs`
5. `Analysis/SsaSimplifier.cs`
6. `Analysis/CopyCoalescer.cs`
7. `Analysis/Simplifier.cs`

API:

```csharp
MemoryOperand.NativeReadProof.TryCreate(owner, nativeAddress, source)
memory.NativeRead
proof.ValidFor(owner, memory)
proof.BoundBase
// Internal, called only at existing proven rename/copy sites:
memory.RebindBaseForProvenCopy(replacement)
```

It records immutable original owner/address/raw instruction word/8-byte width/native register names/offset. Seed only exact unsigned-offset 64-bit `LDR X`, excluding SP base, ZR destination, indexed/writeback/literal/FP/vector/pair/32-bit alternatives. Validate image gate, selected exact FDE, current native bytes, live offset/index/scale/FP tag and bound base.

The five existing rewrite sites derive immutable successors only after matching the previous attached witness and old base. Register equality includes SSA version; LocalVariable equality uses reference identity. Arbitrary direct `Base` mutation must remain stale and cannot be blessed by a later tracked rewrite.

This is necessary because the actual original header load uses X20 but valid later forwarding gives a final X0 local. Comparing only final raw register names would reject legitimate dataflow. The carrier does not establish array/object semantics, availability, escape behavior or safe movement of memory effects.

Root performed a source review with no blocker found; `git diff --check` passed. **No compilation or contract tests have run.** Neither `NativeReadCarrierContractProbe` nor its requested tests exists.

Required tests were: native 64-bit versus 32-bit load separation; wrong owner/address/word/frame/image; stale direct mutation plus attempted rebind; distinct SSA versions and same-type different locals; all five actual rewrite paths; legitimate X20→X0 forwarding; whole MemoryOperand copies/inlining; unchanged no-proof behavior. Do not skip these just because the source looks plausible.

### 11.2 New fresh-array element-class proof helper

File: `refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64FreshArrayElementClass.cs`

SHA `7a541d6698240627a4555295be2da3606d170abfb31f37515502cf13f3220c08`

API: `TryProve(owner, call, out Proof[, out reason])`, `IsValid(owner, call, proof)`.

Intent: read-only uncached origin proof binding actual call, array, NewArr, canonical type, header/projection carriers and current graph objects. It uses unique definitions, validated acyclic call cone, recomputed availability/dominance, bounded copy/alias closure and conservative pure allocation-to-call windows. NewArr is handled explicitly because generic `Instruction.Destination` currently omits it. It rejects unsupported parameter/field/Phi/covariant roots and effectful/escaping windows rather than assuming all 28 candidates work.

**It has no production hook, no operand rewrite, no emitter change and no semantic IsInst translation.** Even a correct accepted origin proves only one prerequisite.

Known unfinished issues found during read-only review:

- **Concrete compile blocker:** around line 49 it calls `owner.AnalysisAddress`, but `MethodAnalysisContext` has no such property. Existing API is `LegacyArm64ValueThisThunks.AnalysisAddress(owner)`. This was deliberately not fixed during the documentation-only handoff; preserve the stopped hash above.
- The generic “skip destination operand” test in `UsesAreClosed` treats operand 0 as a destination whenever `row.Destination` is a local. Call/IndirectCall destinations are operand 1. Review this exclusion and unavailable/escaping alias cases; no exploit or corrected contract was validated.
- CFG predecessor/successor topology is checked, but instruction branch/fallthrough/terminator operands have not been fully tied back to those edges. A stale or contradictory instruction/CFG pair must not manufacture a proof.
- Full compile correctness, positive actual-profile acceptance, negative graph fixtures, exact captured operand invalidation and limits remain untested.

No `FreshArrayClassOriginProbe` exists. Source review was incomplete. A v41 Core build or full recovery was never started. **Fix/review source first, then establish contracts and actual witnesses before using this for any semantic rewrite.**

The carrier's baseline diff uses frozen v40 sources where present and the pinned upstream commit for previously unmodified SsaForm/Simplifier paths. The current 41-path full packager inventory does not yet include all newly changed v41 paths/new helper. Its omission guard should reject packaging until deliberately updated and reviewed. Do not disable that guard.

## 12. Reproducing experiments without corrupting the baseline

### 12.1 Current Windows commands — documentation, not a request to rerun v40

The following is verified syntax for a **new unique run**, after the intended tool sources have been reviewed/built. Existing wrappers reject existing output directories but can build tools/write logs before that check. Never reuse a historical run name or delete its directory to bypass preservation.

```powershell
$Root = 'F:\SF2SwitchPC'
. "$Root\src\tools\Initialize-UsbWorkspace.ps1" -Root $Root
$Run = 'replace-with-new-reviewed-unique-run'

& "$Root\src\tools\Invoke-Cpp2IlMetadataRecovery.ps1" `
  -Root $Root -RunName $Run `
  -RecoverAttributes -OriginalMarkersOnly -RecoverHfa `
  *> "$Root\logs\cpp2il-$Run-pipeline.log"

& "$Root\src\tools\Invoke-RecoveredSourceBuild.ps1" `
  -Root $Root -RunName $Run `
  -ProjectExport -PreserveAnonymousTypes -UseLegacyDecompilerReferences `
  *> "$Root\logs\source-profile-pipeline-$Run.log"

& "$Root\src\tools\Invoke-SourceReferenceCheck.ps1" `
  -Root $Root -RunName $Run -UseLegacyReferenceAssemblies `
  -SourceKind source-profile-project-build `
  *> "$Root\logs\source-profile-legacy-reference-pipeline-$Run.log"

& "$Root\src\tools\Invoke-RecoveryRegression.ps1" `
  -Root $Root -RunName $Run -IncludeEnumerator -IncludeBooleanReader `
  *> "$Root\logs\regression-pipeline-$Run.log"

python "$Root\src\re\tools\compiler_diagnostic_delta.py" `
  --before nso-object-isinst-abi-v40 --after $Run --label UNIQUE_LABEL
```

Serial initializer writes matter: each writes shared `reports/workspace-paths.json`. Serialize Core builds. Independent immutable-file analysis can run in parallel; changing a live dependency during a probe invalidates its identity.

The recovery wrapper builds `refs/Cpp2IL/Cpp2IL/Cpp2IL.csproj` Release/net10.0, then invokes Cpp2IL with exact effective main/metadata, forced Unity 2018.1.9f1, low-memory mode, `dll_il_recovery` output, attributeinjector and original-markers-only configuration. It records the exact three DLL hashes in the invocation receipt.

### 12.2 Why there are two source-build stages

The preliminary .NET 10 export build is not the authoritative full body comparison. For v40 it had only 1/10 preliminary diagnostics due to its reference setup. **Do not report those as the game now having eleven errors.**

The matching-reference project runs the .NET 10 compiler with:

- `NoStdLib=true`, `DisableImplicitFrameworkReferences=true`.
- Official pinned .NET 3.5 reference assemblies substituted for matching framework names.
- Remaining recovered dependency metadata.
- Unchanged exported `.cs` files, with before/after manifests checked.

Reference lock: `reports/legacy-reference-assemblies-lock.json`. Its integrity gate is `PASS_OFFICIAL_CATALOG_PACKAGE_SHA512`. Ordinary build commands are:

```powershell
dotnet restore $project --source "$Root\cache\nuget" `
  --ignore-failed-sources --property:NuGetAudit=false
dotnet build $project -c Release --no-restore --maxcpucount:1 `
  --nodeReuse:false --verbosity:normal
```

Here `$project` must be the infrastructure-generated `MatchingReferences.csproj`. Do not execute arbitrary decompiler-generated project build targets. A compatible reference profile removes misleading framework-resolution errors; it does not repair method semantics.

The original-marker view intentionally omits other behavior-relevant custom attributes. A clean compiler result in that view would not certify a complete serialized Unity project.

### 12.3 Freeze the exact tool state before the next edit

For an accepted new invocation, package the **complete** patch against pinned upstream, freeze every changed/new source and the actual three invocation binaries, and verify hashes before making the next tool edit:

```text
python src/re/tools/package_cpp2il_hfa_experiment.py --artifact-label NEW_LABEL
python src/re/tools/capture_candidate_source_snapshot.py --artifact-label NEW_LABEL --run NEW_RUN
```

Read the scripts first. Packaging is a complete alternative patch, not a small incremental patch to stack on an older complete candidate. Capture requires the live Core and listed sources still match the completed invocation. Use a dedicated immutable tool/dependency location for subsequent probes.

Historical canonical v19 and default experimental candidates remain separate from named v37/v38/v39/v40 candidates. Do not overwrite them just to make a filename say “latest.” For v40 reproduction, isolate pinned upstream plus its complete 41-path candidate; preserve the unbuilt live v41 work.

Regression wrappers require the authored probes already built under `src/re/<Probe>/bin/Release/net10.0`. Read their arguments and pinned identities. Some tests execute isolated clones with explicit boundaries; some inspect actual output only. Do not generalize clone success to whole methods.

Original infrastructure checks include `python -m unittest discover -s tests -v` (139 tests last recorded) and Windows `src/tools/Test-UsbWriteBoundary.ps1`; syntax gates cover Python/PowerShell. These validate infrastructure, not gameplay. Adapt the boundary test explicitly for the new host, keeping the original Windows result separate.

## 13. Suggested first actions for the receiving AI

These are a concrete continuation point, not a requirement to perpetuate the old strategy.

1. **Verify the transferred state.** Read this document/master/acceptance, check the companion evidence manifest, establish a safe private cloud root and host dependency strategy. Confirm inputs/effective payload exist and v40 frozen artifacts match. Distinguish current unbuilt source from old binaries. Do not start by rebuilding everything.
2. **Audit the central recovery failure.** Inspect the actual no-op diagnostic helper, representative missing result/control flow, unsupported class projections and EH gap. Decide whether improving this Cpp2IL pipeline, integrating a genuinely stronger local recovery component, or a different evidence-backed reconstruction strategy offers the best route. Test a concrete method family with real bodies and behavior.
3. **Resolve the saved v40 additions or explicitly supersede that candidate.** Eight source diagnostics remain unattributed. Use the saved source contexts, tokens/RVAs and native evidence rather than an arbitrary source text repair.
4. **If retaining the v41 approach, complete its source review and contracts.** Fix the known compile error, inspect destination/CFG issues, test the carrier and origin routine separately, then prove actual fresh-array/object metadata identities. Only afterward consider a bounded exact ordinary-class semantic implementation. Preserve original failure ordering. An origin tag alone is not game logic recovery.
5. **Demonstrate executable progress.** Recover a meaningful complete method family, compile unchanged generated source with compatible references, compare actual emitted behavior to original ARM64/native/data evidence, and audit callers/side effects/exceptions. Expand based on results.
6. **Keep the broad blockers visible.** Do not spend the entire next budget polishing synthetic carriers while production EH, runtime effects and thousands of method bodies remain missing. Keep a ledger of actual recovered implementations versus structural support work.

Do not claim the proposed v41 work will eliminate the earlier 3,355 casts, solve all 28 sample sites or unlock the whole game. No such result has been measured. A stronger AI may find a better solution; the point of this handoff is to give you the evidence needed to do so.

## 14. Required completion standard and return package

The user wants a **full clean decompile usable as the foundation for a complete later OS port**, not restoration of original comments/formatting. Functional reconstruction is acceptable only when its evidence and validation support equivalence; label recovered native evidence, inferred code and platform boundary replacements distinctly.

Before calling this phase complete:

- Both complete game source assemblies build reproducibly with a documented compatible reference profile.
- No unresolved helper calls, empty/default substitutions, guessed constants or skipped behavior remain in required game logic. Diagnostic-free bodies also require scrutiny; syntax alone is insufficient.
- Runtime type/class operations, allocations, calls/ABI, generics/interfaces/virtual dispatch, control flow and exception/cleanup semantics are accounted for.
- Behavior-relevant serialization/custom attributes, scenes and asset/script dependency identities needed by the next phase are preserved or explicitly recovered and validated.
- Native/data/behavior comparisons cover important original systems and callers, with exact tested boundaries and failures retained.
- Nintendo-specific imports and runtime contracts are identified for later replacement; the recovered foundation does not require executing the original ARM64 game to supply its logic.
- The Switch edition's content/mode/save identity is preserved. No Android substitution or emulator wrapper.
- All `reports/decompilation-acceptance.json` gates are supported by actual evidence. Update the gates when findings require more precision; do not merely flip statuses.

Then **stop before implementing the Windows/PS5 port**, return the complete private workspace plus a concise build/reproduction guide, source/asset manifests, exact changed tool patches, evidence, known platform boundaries and a factual acceptance report. The user intends to bring that result back to the original agent for the porting phase. No FPS/performance claim belongs to this phase without an actual runnable target and measurements.

If the goal is still incomplete, continue concrete recovery within the user's scope; if a hard dependency is genuinely missing, finish independent work and report its exact identity. Do not fabricate progress, hide rejected tests, or treat model confidence as evidence.

## 15. Files to read first and stale-document warnings

Recommended reading order:

1. This handoff and `AI_HANDOFF_EVIDENCE_MANIFEST.json`.
2. `input/reference/SF2_Switch_to_Windows10_Codex_Master_Prompt.md` and `AGENTS.md`, with the scope/cloud updates in section 2 above.
3. `reports/decompilation-acceptance.json` and current `STATUS.md` / `TASKS.md`.
4. `reports/object-isinst-abi-source-recovery-v40.json`, `diagnostic-scaffolds-nso-object-isinst-abi-v40.json`, `recovered-object-isinst-abi-nso-object-isinst-abi-v40.json`.
5. `reports/compiler-diagnostic-attribution-v40-handoff.json` and its referenced delta/location/method reports.
6. v40 frozen candidate/source/bin manifests and v41 carrier/helper source/designs.
7. Feature-specific native/data reports and exception-recovery reports as needed.

Known stale material:

- `START_HERE.md` still calls an old v4 scoped C# export “latest”; use this handoff and v40 manifests instead.
- `analysis/continuation-state.json` contains old `v39_active` / `v40_active` entries alongside newer `active_v39` / `active_v40` / `active_v41`. The older entries and its historical timestamp can be stale. This handoff and the exact current reports control the stop state.
- `reports/decompilation-quality.json` contains historical snapshots; the v40 diagnostic census/fresh report is the newer explicit no-op finding.
- Historical `reports/decisions.md` next-step suggestions are not current completion evidence.
- Initial failed fixtures/logs were deliberately retained. A later scoped PASS does not erase the original failure or widen what was proved.

No local build, recovery, contract or gameplay job was left running at the handoff. Shell session IDs and prior agent names are not resumable resources on another host. All durable context is in the supplied files.

**Please take this forward with fresh expertise and strict evidence. The user is investing in a real recovery, and the strongest contribution you can make is correct executable logic with reproducible proof.**
