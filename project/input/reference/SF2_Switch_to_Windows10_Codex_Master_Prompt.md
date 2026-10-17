# MASTER IMPLEMENTATION PROMPT — Shadow Fight 2 (Nintendo Switch Edition) → native Windows 10

**Intended agent:** GPT-6.1 Sol, Extra High reasoning, Codex **local** CLI/IDE on the Windows 10 computer attached to the external USB drive.  
**Project status at handoff:** No game binary has been inspected yet. Do not imply otherwise.  
**Primary outcome:** An independently launching native x64 Windows build of the **Nintendo Switch edition** of Shadow Fight 2, with the full original Switch-edition feature set, sound, visuals, combat and local multiplayer, and a verified 120 Hz presentation target, with no Switch emulator required to play the delivered Windows program.

## 0 — Mission, scope, and non-negotiable execution rules

You are the lead reverse engineer, binary analyst, Unity engineer, technical producer and QA engineer for this project. This is an **implementation assignment**, not a request for a high-level essay. Create the USB-hosted repository, inspect the user's legally obtained NSP, automate as much asset and structural recovery as possible, build a real functioning Windows target, continuously validate it, and produce reproducible artifacts and evidence. Work in measured, independently verifiable phases. Keep implementing after each phase rather than stopping at a planning document.

The Nintendo Switch release is the target, **not the ordinary mobile game**. Do not silently substitute an Android version or generic fan remake. The genuine Switch edition adds local SPARRING multiplayer, four save files per Nintendo profile, a rebalanced STORY campaign, additional equipment, Sensei's story, and a redesigned interface. It removes energy, ads, microtransactions, Underworld/raids, Forge and Ascension; shortened duel-restoration waits are part of its balancing. Preserve the release's actual behavior and content after checking the installed build version. Source: official Nekki FAQ: https://nekki.helpshift.com/hc/en/13-shadow-fight-2-nintendo-switch-edition/faq/245-how-does-the-nintendo-switch-version-differ-from-other-versions-of-the-game/ .

The presumed engine is Unity + **IL2CPP**, based on research on modern Shadow Fight 2, including https://github.com/onerdna/sf-2.x-guide . **Do not claim the exact user's Switch NSP has been proven Unity/IL2CPP until inspecting it.** If evidence disagrees, update the approach. IL2CPP converts C# IL into native C++/machine code: `DummyDll` is a metadata/type reconstruction, **not** the original method implementations. Do not fabricate recovered C# functions or assume a project can be rebuilt just by dragging `Data/Managed` into Unity. Switch ExeFS contains ARM64 native artifacts, usually `main` NSO, not a Windows `GameAssembly.dll`. Look at the actual files first.

**Permission and confidentiality:** Work solely with a copy acquired from a game the user is authorized to access and analyze. Do not source/download pirated NSPs, commercial game assets, Nintendo console keys, leaked SDKs or rights-protected material from third parties. Do not upload an NSP, decrypted game binaries, asset bundles, keys or dumps to GitHub, Codex Cloud, online decompilers, artifact sites or unrestricted logging. Do not assume an owned game grants redistribution permission. Keep extracted proprietary assets private; do not distribute the completed copyrighted game. Record applicable license and local-law uncertainties rather than claiming blanket legality. Avoid destructive operations or modifying the original NSP. Game-specific third-party mod repos are **references**; do not automatically import bundled proprietary assets or execute intrusive Android patch/injection software.

**Strict drive boundary:** All project working files, clones, caches that can be relocated, analysis databases, large downloads, extracted files, Unity projects, logs, screenshots, tests, compiled builds and exports must live on the **physically connected USB drive**, not the host machine's `C:` drive. Never format a drive. Detect the real USB volume, not an assumed drive letter. Standard Windows OS activity, installed dependencies, registry, drivers and some unavoidable application caches may still touch `C:`; report unavoidable writes explicitly and minimize them. Avoid `C:\Users\...` as the active project. If Codex Cloud is being used, switch to a local Codex execution surface because a cloud task does not automatically see a local physical USB drive. A clone in a remote repository does not give access to a local NSP. Use Windows-native Unity Editor/build tools; WSL can be supplementary for CLI analysis but must not redirect gigabytes of output to its virtual disk.

**Success is not a claim:** 120 FPS is a **measured acceptance target on actual hardware**, not guaranteed by this prompt, the subscription or the tools. The completion state is only `PASS` if the native Windows executable actually launches and the specified feature/parity tests pass; otherwise report precise status and blockers. Never replace missing parts with misleading fake menus or a visual mockup. A short-running proof of concept is a milestone, not a completed port.

## 1 — First action: recognize and provision the USB workspace

1. Confirm operating system build (`winver`/PowerShell), CPU, RAM, GPU, GPU driver, native monitor refresh rate, installed runtimes, terminal shell, `git`, `python`, `.NET`, Java/JDK, Unity Editor/Hub availability, Codex location and model/effort in use. Do not assume Intel Arc is present; detect it.
2. Enumerate mounted volumes with PowerShell `Get-Volume`, `Get-Partition` and `Get-Disk`. Verify the candidate drive's disk BusType or equivalent USB-device provenance; USB SSDs may appear as fixed rather than removable. If several are attached, identify the one containing the NSP via a targeted read-only filename search. Do not recursively index the whole `C:` drive. Confirm free space; aim for **at least 60–100 GB free** for large analysis databases, exported Unity assets and build caches, while measuring actual requirements. NTFS is preferable for many small Unity files and robust metadata; if the existing drive uses exFAT, do not reformat it—warn and operate carefully. Benchmark I/O; high latency and tiny random-write throughput can dominate asset import on a cheap flash drive.
3. Define `$Root` as `<VERIFIED_USB_DRIVE>:\SF2SwitchPC`; avoid hard-coded `E:` or `D:` in scripts. Record USB disk identity and volume label in `reports/usb-preflight.json`, with no personal serials published externally. Create the following directory contract and use it consistently:

```
SF2SwitchPC/
  input/                 # user-owned NSP/update and reference material; read-only by policy
  originals_manifest/    # hashes, content manifests; no keys
  tools/                 # portable approved tool binaries and exact versions
  refs/                  # checked-out public source repositories, licenses and notes
  unpacked/nsp_pfs0/    # NSP contents, generally .nca files and metadata
  unpacked/base/         # base ExeFS and RomFS, separately
  unpacked/update/       # update contents, separately
  unpacked/effective/    # effective merged view with provenance and patch rules
  analysis/nso/          # native binaries, disassembly, symbols, call graphs
  analysis/il2cpp/       # metadata / type schema / Ghidra maps / comparisons
  analysis/assets/       # asset export and import manifests / previews
  analysis/reference/    # captured owned-game behavior and feature comparison
  unity/                 # native Windows Unity project, only once engine/version verified
  src/                   # portable original code, scripts, converters and tests
  tests/                 # unit, integration, replay, frame-timing and visual tests
  build/                 # staging and reproducible Windows x64 builds
  dist/                  # tested portable Windows release
  reports/               # evidence, feature parity matrix, performance results
  logs/                  # tool transcript and compiler logs
  cache/                 # toolchain package/temp/build caches
  backups/               # versioned safety snapshots
  .codex/                # project-local instructions or configuration as supported
  AGENTS.md
  README.md
  TASKS.md
  STATUS.md
```

4. Implement `src/tools/Initialize-UsbWorkspace.ps1` with a preflight that refuses to write outside the canonical resolved USB root for project outputs. Resolve full paths before writing; forbid path traversal (`..`), reparse-point escape and drive-letter mixups. Build `src/tools/Test-UsbWriteBoundary.ps1` that proves all configured *project* destinations are children of `$Root`.
5. In the active PowerShell session, redirect **relocatable** process caches to `$Root\cache`: `TEMP`, `TMP`, `TMPDIR` where honored, `PIP_CACHE_DIR`, `NUGET_PACKAGES`, `npm_config_cache`, `GRADLE_USER_HOME`, `GIT_LFS_STORAGE` only if supported for this repo, and any tool-specific output/cache locations after confirming official documentation. Create directories first. Do not indiscriminately override `USERPROFILE`, `APPDATA` or system variables in ways that break Windows/Unity authentication. Check whether `CODEX_HOME` can be set to a USB directory in the installed Codex version and document the results. Unity `Library/`, `Temp/`, `Logs/` and build locations must be within the USB-hosted Unity project where possible. Unity Hub, drivers and Visual Studio Build Tools may install OS-side components; obtain approval and report exceptions rather than promising zero system writes.
6. Make `AGENTS.md` authoritative for all successive Codex turns, with explicit project purpose, drive boundary, confidential-input rules, test commands, task state convention, no-fake-success requirement and checkpoint strategy. Use a disk quota / free-space alert before massive exports. Initialize a **local-only** Git repository with `.gitignore` patterns protecting the NSP, keys, NCAs, recovered binary data, proprietary assets, installed binaries, Unity Library, temp files and build outputs. Do not `git push` private recovered code/assets.
7. Hash the original NSP SHA-256 without modifying it, capture size/time/base-update relationship, and create a manifest. If the NSP is not found, implement all remaining *non-game-specific infrastructure and tests* now, then clearly mark the precise missing input. Never fabricate extracted files.

## 2 — Verified toolchain and repositories: audit, acquire and pin

Research current upstream README/releases/compatibility **before executing commands**; record URL, branch/tag, commit SHA, license, platform, intended use, integrity SHA-256 for releases, and success/failure in `reports/toolchain-lock.json`. Install prebuilt official releases when appropriate rather than recompiling every research utility. Where a repository is unmaintained, unavailable or legally problematic, note this and substitute an actively maintained alternative. **Never execute random unsigned `.exe`, third-party patched APKs or unknown downloaded scripts simply because they mention Shadow Fight 2.** Use the following prioritized catalog:

**A. Nintendo content inventory/extraction**
- `https://github.com/SciresM/hactool` — examine NSP PFS0 and NCA metadata; extract ExeFS/RomFS where authorized source material and any required *user-owned, lawfully obtained* key material are already supplied. It does **not** magically turn an encrypted NSP directly into a Unity directory by simply passing `--romfsdir` on the NSP.
- `https://github.com/DarkMatterCore/nxdumptool` (inspect `rewrite` branch) — optional dump of the user's own installed Switch title when relevant. The rewrite supports NSP, NCA filesystem extracts and USB workflows; it runs on Switch hardware, not as a magic PC-side NSP decompiler. If the existing provided NSP is sufficient, don't make the user redump.
- `hactoolnet` / LibHac — **optional** secondary format inspection if a trustworthy, accessible current build exists. Some previous GitHub locations are no longer available; do not rely on a nonexistent repository. Do not download closed-source “all-in-one” piracy bundles.
- `https://github.com/Adubbz/Ghidra-Switch-Loader` — import Switch-native formats into Ghidra; confirm extension compatibility with the installed Ghidra release/JDK before building.

**B. Unity IL2CPP and asset recovery**
- `https://github.com/Perfare/Il2CppDumper` — high-priority metadata and structure reconstruction; its README explicitly lists **NSO** support and Ghidra scripts. `DummyDll` restores metadata shell/type information but **not method bodies**.
- `https://github.com/SamboyCoding/Cpp2IL` — secondary IL2CPP control-flow/IL recovery; use the current development branch only after checking which NSO ARM64 path and output mode are supported. Its own docs call recovered IL messy and the development branch work-in-progress. Do not treat reconstructed CIL as verified source.
- `https://github.com/NepMods/Cpp2IL-Analysis` — optional specialized ARMv8/NSO analysis branch, explicitly evaluate its maintenance and compatibility first; never assume its incomplete instruction-set coverage suffices for a full-game rewrite.
- `https://github.com/AssetRipper/AssetRipper` — primary Unity serialized asset inspection/conversion and project reconstruction. AssetRipper reports Unity 3.5–6000.4.x compatibility with version-dependent limitations; preserve GUIDs/dependencies and test imports.
- `https://github.com/nesrak1/UABEA` and optionally `https://github.com/nesrak1/UABEANext` — second-opinion raw serialized bundle/asset editor, especially for inspecting broken references or export failures. UABEA explicitly recommends AssetRipper/AssetStudio for primary extraction.
- `https://github.com/djkaty/Il2CppInspector` — optional older reference for metadata structures and analysis scripts; only use if the target binary/version justifies it.

**C. Automated native investigation**
- `https://github.com/NationalSecurityAgency/ghidra` — authoritative native ARM64 decompiler, scripting/headless processing and call graphs. Download an **official release**; don't assume the newest Ghidra extension supports the same JDK/Ghidra API.
- `https://github.com/morluto/rea` — REA agent-facing reverse engineering framework and MCP; official setup is `npx rea-agents setup` after reviewing its README and requirements. The upstream documents Node 22.x (>=22.19), 24.x (>=24.11) or 26+ and describes Ghidra/Hopper/IDA native providers. **Windows Ghidra provider support may be experimental:** check current documentation, verify a real test decompilation, and fall back to Ghidra headless scripts/PyGhidra if the MCP bridge fails. Only use the confirmed official `rea-agents` npm package; do not trust similar names/forks. Setup may alter agent configuration; show the proposed changes first.
- Optional: `https://github.com/Unity-Technologies/InputSystem` documentation/sample references for PC input and paired local players (add Input System using a Unity-compatible package version, not by copying the GitHub HEAD blindly).

**D. Shadow Fight 2-specific research (reference, not an off-the-shelf port)**
- `https://github.com/onerdna/sf-2.x-guide` — high priority: explains modern Shadow Fight 2 Unity/IL2CPP and reverse-engineering strategy. Mostly Android evidence; verify applicability before projecting claims to Switch.
- `https://github.com/moltinginstar/sf2mod` — 2026 Android-specific save structure/hash research; useful for *comparison*, not a Switch save implementation. Read `WRITEUP.md`; do not import its cheats or Android re-sign workflow into a Windows port.
- `https://github.com/onerdna/stalker` — reference for some Shadow Fight 2 save/inventory representations; Android, not Switch; code is a research reference only.
- `https://github.com/FlipThoseTitle/Gymnast-Tool-Suite` — optional Blender/animation workflow reference. Check provenance and license of any separately distributed game assets: **do not fetch bundled third-party Nekki assets** as a shortcut. Use only the original authorized dump for assets.
- `https://github.com/NikkaGames/AutoShadow` — **read-only optional source reference** for Android IL2CPP instrumentation patterns. Do not run/inject its native mod into a live game; not a Switch dumper and not required.
- `https://ilogos.biz/case/shadow-fight-2-porting/` — context: iLogos assisted with the original mobile-to-Switch port and describes porting controls and Nintendo SDK integration. It is not a source repository.
- Official Nintendo Switch feature/control FAQ at `https://nekki.helpshift.com/hc/en/13-shadow-fight-2-nintendo-switch-edition/` — primary feature baseline.

For every repo, produce a one-page `reports/repo-triage.md` summary: **actionable code? format? runtime? target versions? license? source authenticity?** Clone only the useful subset into `refs/`; do not waste limited workspace on dozens of unrelated mods. Prefer primary tools and honest direct evidence to vague “reverse-engineering magic” marketing. No repo on this list reconstructs the complete proprietary game automatically.

## 3 — Archive classification and NCA extraction: do this in the correct order

1. In read-only mode, inspect the NSP header/magic, package structure, SHA-256, game title/build identifiers and NCA inventory. `.nsp` is generally a **PFS0 container of NCAs**. Inventory first. The conceptual hactool sequence is: `hactool -t pfs0 --outdir=<USB_ROOT>\unpacked\nsp_pfs0 <INPUT.nsp>` then inspect each relevant Program NCA, then (for correct identified Program NCA only) use `hactool -k <USER_PROVIDED_LEGAL_KEYSET_PATH> --exefsdir=<...> --romfsdir=<...> <PROGRAM.nca>`. **Do not run these examples blindly:** inspect the installed hactool `--help`, metadata/content types, rights requirements and whether these particular NCAs are update/delta/compressed/rights-managed. A missing rights requirement is a blocker, not a cue to fetch keys from the internet.
2. Record which content is Program, Control, Meta, Data and Patch. Determine base versus update/patch NCAs and effective title program version. Maintain distinct base and update sources with a reproducible merged effective view; don't silently concatenate or overwrite two versions. Use the proper base NCA/patch-aware extractor if necessary and supported, with test hashes/provenance. Confirm that output files actually exist, aren't sparse placeholders and have plausible sizes.
3. Extract ExeFS (`main`, `main.npdm`, SDK modules or other actual files as observed) and RomFS. Preserve exact case, paths and original names. Build `reports/extract-manifest.json` listing source NCA, section, output path, size, SHA-256 and whether it originates in base/update/effective mapping. Include `reports/extract.log` with return codes and tool versions. Fail closed on extraction errors; do not pretend success if hactool returns a nonzero exit code.
4. Derive the engine/runtime empirically: string inventory in native code, Unity serialized file headers, `UnityFS`, `globalgamemanagers`, `resources.assets`, `Managed`, `il2cpp_data/Metadata/global-metadata.dat`, Player settings, Unity version markers, script type metadata. Expect potentially **nonstandard Switch data layout**. The installed game may have custom packing; classify before assuming it has exactly PC-style folder names. **`ProjectSettings/ProjectVersion.txt` is normally a Unity project source artifact, not guaranteed in a shipping Switch RomFS.** Determine engine build/version from actual player data where possible and record confidence.
5. Inspect the executable format and architecture: `main` likely ARM64 NSO. Confirm native instruction set, compression, dynamic imports, Unity/IL2CPP signatures, metadata linkage and any embedded/native plugins. Use signature-based verification, not filename alone.
6. Produce **`reports/engine-fingerprint.md`** with exact engine version, scripting backend, metadata location and validity, code registration location if recovered, scene/asset counts, program build IDs, native dependencies and unresolved anomalies, each with evidence and source paths. This is the first major go/no-go gate. If the game is **Mono** instead of IL2CPP, use ILSpy and compare actual DLL assemblies; if **non-Unity**, design a different engine-compatible recovery path based on evidence rather than pretending Unity applies.

## 4 — Build an evidence-backed reverse-engineering knowledge base

**IL2CPP phase:**
1. Run Il2CppDumper locally on the compatible NSO native binary and its correct `global-metadata.dat`, capturing `dump.cs`, `script.json`, `stringliteral.json`, structure headers, `DummyDll` and Ghidra scripts when supported. Validate that metadata type/method counts are coherent and addresses fall inside actual mapped executable regions. Unsupported metadata versions or obfuscation require a documented parser investigation; do not use secret web upload services. Record all output versions and error logs.
2. Run Cpp2IL separately to recover whatever code/IL/control flow its chosen version actually supports for ARM64 NSO. Classify each result as verified, plausible, skeleton-only or error. Preserve native function address and any reconstructed metadata token. **Cpp2IL output is a hypothesis, not canonical source.** Cross-validate important combat methods with Ghidra.
3. Import `main` NSO with a compatible Switch loader into Ghidra; if required, decompress by an official tool to a format that Ghidra can import with correct virtual addresses. Use IL2CPP generated label/type scripts; confirm symbol addresses and method-to-native mappings with spot checks. Use Ghidra headless/scripted export or REA Ghidra MCP for bounded, relevant functions. Avoid huge one-shot decompilation context dumps. Produce executable analysis scripts in `src/re/tools/`, not just manual screenshots.
4. Create **an indexed method and data schema corpus**, e.g. SQLite/JSONL on USB: namespace, full type name, method signature, RVA/offset, native address, linked scene/prefab/asset, suspected feature, known callers/callees, confidence, cited binary evidence offset, and investigation status. Retrieval must be on-demand by symbol/function/method class. Keep a structured contradiction log when hypotheses differ.
5. Identify major modules by tracing from Unity lifecycle/event entry points and gameplay strings/serialized references: bootstrap, localization, home screen, story map, equipment shop, upgrades, weapon/armor management, combat world, animation controller, physics/collision, AI, damage/health, projectile/magic, economy, duels/timers, reward state, scenes, UI navigation, saves, settings, sound/music, Sensei story, local SPARRING two-controller pairing and character select.
6. Prioritize behavior-backed reconstruction of combat. Extract concrete state machines and domain schemas first: character stances/poses, attack states, animation clips, hit/hurtbox rules, contact and knockback, jump/crouch, weapon length and category, ability cooldowns, combo windows, block/parry logic, AI transition probabilities, stamina/resource and round state. Annotate every inferred numerical coefficient with evidence, else mark it as a measurement requiring testing.
7. Build `reports/switch-vs-mobile.md`: distinguish platform-adapter code from genuine Switch-exclusive design/content. Use the modern Android references only when equivalent methods/structures can be matched and prove equivalence by field layouts, function signatures or behavior. The Switch **rebalance** may invalidate mobile damage/economy defaults.
8. Investigate platform APIs: `nn::hid`/controller, Nintendo profile/user identity and local save slots, vibration, filesystem/romfs, paths, achievements (if actually present), controller prompt icons, localization, fonts, lifecycle/home button/suspend. Create `reports/platform-dependency-matrix.csv` with each observed dependency, call sites, required replacement and test. Never globally regex-replace all `nn` substrings or expect magic `UnityEngine.Switch` identifiers without evidence.
9. Treat REA MCP as a *query/instrumentation assistant*: validate provider setup by fetching an actual function's pseudocode + references, then have the agent reason and implement based on recorded evidence. If native bridge cannot import the Switch file, use manual Ghidra import, PyGhidra/headless script exports or a local intermediary converter rather than repeatedly installing random MCP forks.
10. Record an `analysis-coverage.json` by feature subsystem: all identified functions, fully understood, partially inferred, not analyzed, and validation status. Decompilation percentages do not equal gameplay completeness.

**Reference behavioral oracle:** If an authorized working original Switch copy or permitted local reference runtime is available, record repeatable gameplay clips, controller inputs, save-state boundaries and screenshot/video captures **with timestamps** for comparisons. An emulator may be used only as a developer's behavioral reference where lawful and available; **do not package or call an emulator the completed port**. If no runnable reference exists, lean on asset/binary behavior, published official controls and conservative confidence flags; don't invent exact parity measurements.

## 5 — Recover assets and reconstruct a buildable Unity project

1. Inventory Unity serialized files, AssetBundles, scenes, resource managers and streaming content. Use AssetRipper on a **copy of the extracted effective RomFS/Unity payload**, preserving original raw data. Include exported textures/sprite atlases, sprites and pivots, 9-slice data, UVs, meshes/skinned meshes/bones, rigs, animation clips, events, animator state machines, materials, shaders, fonts, UI prefabs, audio, lighting and localization as each actually appears.
2. Implement `src/assets/Build-AssetManifest.py` (or C# equivalent) that produces: source bundle/file, serialized type, pathID, GUID if available, Unity version, name, hash, dependencies, export format, reconstruction status, import destination and usage in scenes. Flag duplicate texture names, case collisions, missing references, unsupported shader formats, corrupted export, non-UTF8 text and hidden Unity assembly types. Keep a reversible mapping back to source pathIDs.
3. Use UABEA as a **second-opinion inspector** for mismatches, not a second full uncontrolled exporter. A recovered asset folder is not a complete Unity source project: implement reconstruction tools for broken script references, materials, UI layout, shader substitution and scene prefabs.
4. Determine the shipping Unity editor version via embedded version signatures/build metadata; choose a licensed, locally available **compatible editor** on the USB drive (do not just pick latest Unity or assert `ProjectVersion.txt` must exist). If exact version is unavailable or incompatible with Windows 10, prove the closest workable minor/LTS path with a small import experiment. Record migration warnings and shader/material differences; do not permanently migrate the only asset export until reference snapshots exist.
5. Preserve combat pose timing and visual feel: pivots, sprite sorting, bones/rig retargeting, motion curves, event markers, contact poses, opacity, UI scale and transitions. Do not replace the genuine Shadow Fight silhouettes with unrepresentative generic humanoid sprites and claim parity.
6. Create a scene reconstruction order: bootstrap → shared/UI systems → title/menu → fighter preview → training/single bout → complete fight scene → story map → equipment/inventory/shop → dialogues/cinematics → Sensei campaign → local SPARRING → remaining secondary menus, transitions and audio. Each scene should import, open, run and build with integration tests before moving on.
7. Save explicit import logs and a `reports/asset-integrity.md`: imported count by asset type, failed/missing count, dependency validation, visual spot checks and unimplemented proprietary shader paths. If Switch-native shaders can't execute on Windows, port/recreate their visual effect using Windows-supported Unity shaders; no reliance on Switch GPU APIs in the final build.

## 6 — Core Windows implementation architecture

Implement in C# inside the compatible Windows Unity project wherever practical. Prefer modular **separation of concerns**, with unit-testable pure game logic and thin Unity presentation wrappers. Build the following components with interfaces and tests; adjust names to observed game's real class structure:

- `Bootstrap/GameSession`: reproducible initialization; scene loading; language/assets setup; feature flags and graceful error logging. No Nintendo runtime dependency.
- `Platform/IPlatformServices`: Windows path provider, save directory, app focus/pause, clock/monotonic timing, notifications where supported, vibration abstraction, user settings; adapters replace actual identified platform calls. `Environment.GetFolderPath`/portable save location must be configurable so the deliverable runs directly from USB; default **save data beside the game in a `userdata/` directory** if writable, otherwise a clearly documented user-selected path. Never write personal save files to `C:` silently.
- `Input/GameInputRouter`: per-player identity, local input actions, keyboard/controller detection, rebinding, analogue thresholds, press/release semantics, deadzone, repeat controls, UI navigation, simultaneous controllers, hot-plug/reconnect, keyboard+controller pairings. For the fighting game **use a shared arena**, not automatic split-screen. Match original Nintendo controls and allow user-defined mapping for two players. Use Unity Input System `PlayerInput`/`InputUser` features only with Unity-version-compatible package and test device pairing.
- `Combat/FixedSimulation`: fixed-timestep time source, deterministic-ish tick advancing, input buffering, commands, fighter state machines, contact/hit/hurtboxes, hitstop, guard windows, knockback, damage, collision, projectiles, stamina/magic, environment bounds, round timers and win/loss. Use numerical values recovered from data/binary behavior, not hardcoded guesses without tests. Preserve round duration independent of render FPS.
- `Combat/AnimationPresenter`: render-to-simulation interpolation plus animation curves, event timing, contact/hit alignment, spine/rig or sprite animation, equipment geometry; no gameplay damage resolution on interpolated visual frames.
- `Combat/AI`: per-opponent decision policy/state machine with measurable difficulty, anticipation, reaction windows, attack patterns, equipment effects and boss-specific scripting.
- `Content/Registry`: schema-driven weapons/armor/helmets/ranged weapons/magic/enchantments, equipment stats and costs, enemy progression, dialogue, locales, story nodes, Sensei-specific unlocks; hashed source provenance and validation of foreign keys/content IDs.
- `Story/Progression`: campaign state, map nodes, economy and rewards, branching/acts, cutscene/dialogue state, tutorial flow, equipment unlocks, duels/timer behavior and Switch rebalance. **No mobile-only monetization/energy/raid/Forge systems** unless actual Switch evidence contradicts the generic official FAQ.
- `Sparring/LocalVersus`: two distinct local players and device assignments, local character selection, independent loadouts if original allows, matchmaking-free shared arena, pause/restart/rematch, controls overlays and disconnect handling. Preserve the exact Switch character availability and mode rules.
- `Persistence/SaveStore`: implement atomic writes (`temp + flush + replace` where filesystem supports), versioned JSON/binary format as appropriate, schema migrations, per-profile four-slot design, save-slot UI, checksums for accidental-corruption detection, backups, import only with tested mapping. Protect user progress on crash/USB surprise-removal; never claim untested original save compatibility. If original Switch saves are available, parse and test a conversion as a separate optional utility, not the only supported save format.
- `Audio/AudioDirector`: music/SFX timing, fighting impact/hit layering, fallbacks when codecs require conversion, configurable latency/mixer levels, menu/battle loops and correct locale voice/music assets.
- `UI/Presentation`: responsive menu navigation for 16:9, 1080p/1440p/4K, controller-first focus, mouse/keyboard optional, localization, original silhouettes/art/typography, save-slot prompts, correct round HUD and clean fullscreen/windowed behavior. Avoid stretching sprites or unintended 120-Hz animation-speed changes.
- `Diagnostics/ReplayAndTelemetry`: record input events with tick IDs, seed/version and game-state checksums; play back golden scenarios at multiple render rates and verify **identical simulated outcomes** within specified tolerance.

Create `docs/architecture.md` and strongly typed content schemas (with validation and migration tests). Keep recovered metadata identifiers in an evidence mapping layer, not everywhere in application code. Match actual game state transitions and content instead of building an entirely generic fighting engine unrelated to Shadow Fight 2.

## 7 — 120 FPS / interpolation engineering: make it genuinely correct

**Do not equate “120 FPS visible” with “120 FPS simulation”**. First use source evidence and gameplay recordings to find the native simulation step (could be 30, 50, 60 or custom; do not assume 60). Preserve combat simulation at the evidence-based fixed rate initially; separately render at 60/120/144/uncapped and allow optional user-defined caps. Physics/time-dependent animations must not run twice as quickly at 120. A starting model if the game proves to tick at 60 Hz:

```
SIM_DT = 1.0 / 60.0                # evidence-dependent; not a fact about SF2
accumulator += min(elapsed_monotonic, MAX_FRAME_DELTA)
while accumulator >= SIM_DT and iterations < SAFE_CATCHUP_LIMIT:
    prior = capture_authoritative_state()
    apply_buffered_inputs_for_next_tick()
    simulate_one_tick(SIM_DT)
    current = capture_authoritative_state()
    accumulator -= SIM_DT
alpha = clamp(accumulator / SIM_DT, 0, 1)
render_interpolated(prior, current, alpha)  # visual only
```

Make a real C# architecture with an authoritative state and its previous/current snapshots; interpolate positions/rotations/sprite/bone presentation carefully, including boundaries and animation frames. For abrupt events (punch connects, knockback, teleport, round reset, hitstop), explicitly determine which transforms must snap and which may blend; test for ghost trails and delayed hit reactions. Never interpolate gameplay hitboxes or damage. Input samples may arrive at higher frame frequency; buffer inputs to fixed ticks with repeatable timestamps and low latency. Use a monotonic clock and clamp runaway catch-up on stalled USB I/O, while monitoring simulation slowdown.

On Unity for Windows, `Application.targetFrameRate` interacts with display refresh and VSync; 120 FPS needs actual 120+ Hz monitor capability or an uncapped benchmark. Implement Video Settings with `60`, `120`, monitor-native and uncapped options and VSync separately, plus fullscreen/windowed/borderless. When VSync is enabled on desktop, it may override targetFrameRate—validate the chosen setting rather than assuming both caps stack. Base renderer on **Direct3D 11** for Windows 10 compatibility and optionally benchmark D3D12/Vulkan only after reliable builds. Do not assert a GPU/API is faster without measurements.

Implement frame pacing telemetry: per-frame CPU/GPU frame time, render FPS, 1% low, 0.1% low if measurable, p50/p95/p99 frame-time distributions, GC allocations, physics-step count, animation latency, loading/hitches, VRAM use and disk I/O spikes. 120 FPS requires about **8.33 ms average per presented frame** and appropriate tail latency. Measure on actual target hardware, after shader warm-up, in menu, static scene, active single-player fight, busy boss fight, equipment transitions and two-player SPARRING. Run repeatable minimum 10-minute sessions; target 1% low near 120 while recognizing hardware/USB quality limitations. Never use artificial frame counters to certify FPS. Export CSV and graphs to `reports/performance/`. Use GPU profiler/Unity Profiler and (optionally) an appropriately licensed trusted frame-present telemetry tool, not guesses.

Preserve animation cadence and clean motion without changing attack durations or animation events. If genuine 120-Hz interpolation yields artifacting, retain 60-Hz authoritative action logic and debug the presentation layer. Do not use AI image-frame interpolation in the gameplay critical path; it adds latency and can invent contact frames. Benchmark optional GPU interpolation only as an independent experiment and keep disabled unless superior under automated comparisons.

## 8 — Milestones with mandatory test gates and tangible deliverables

**M0: USB/toolchain preflight.** Verified physically external workspace, proven path guard, NSP SHA-256 and free-space report; dependencies inspected; `AGENTS.md`, README, gitignore, task ledger exist. `PASS` requires all *project outputs* on verified USB and no unwanted source modification.

**M1: Complete binary/asset fingerprint.** Package correctly inventoried; exact game/title version and effective NCA set known; ExeFS/RomFS extracted without silent errors; engine/runtime determined with confidence; key/rights-related blockers documented. File counts/hashes and reproducible commands saved. `PASS` requires native binary plus actual assets present and parsed.

**M2: Symbol/asset catalogs.** Il2CppDumper results generated if compatible; NSO imported correctly; at least one target method traced end-to-end with correct metadata match; extracted scenes/asset graph indexed; representative sprite/rig/audio imported. `PASS` requires validated binary addresses and source evidence, not invented type names.

**M3: Native Windows vertical slice.** A Windows `.exe` (not emulator) launches from USB, renders one representative actual fight scene with imported legal assets, supports keyboard/controller, draws both fighters, resolves basic attacks/damage and a win/loss, logs cleanly, survives restart. Compare movement/combat timing against an original-game observation or validated binary/data reference. This is a research prototype, **not** the completed port.

**M4: Core combat parity.** Tested combat mechanics: stance, movement, jump/roll/crouch, full weapon categories, magic/ranged attacks, block, hits, combo transitions, knockdown, round reset, AI and boss patterns; recorded test replays show stable outcomes at render 30/60/120 with gameplay clock unchanged. Every implemented mechanic has its own test case and binary/data/observation provenance.

**M5: Full Switch content integration.** All campaign scenes/acts, story progression, Sensei storyline, equipment/item databases, inventory/shop/upgrades, scripted events, audio, localization, settings, save slots and local SPARRING with two controllers work. Diff all content identifiers against extracted data and official feature checklist. No fake “coming soon” replacements. Any missing actual feature is tracked as `FAIL` or `BLOCKED`.

**M6: Polish/120 FPS certification.** Fix collision/animation interpolation glitches, controller latency, sound desync, UI scaling, load stutter, crash recovery, save integrity, Windows 10 compatibility, fullscreen, resize and hotplug. Run long performance and stability validation on target PC and connected USB. `120 FPS achieved` only if measured and documented, with recorded test resolution, display Hz, hardware specs, FPS/frametime distribution and GPU/driver details. Provide fallback 60 FPS when target cannot be sustained.

**M7: Deliverable audit.** Produce a portable `dist/ShadowFight2SwitchPC/ShadowFight2SwitchPC.exe` plus required Windows Unity `*_Data` and legitimately used runtime dependencies, config and `userdata/` path. Ensure it launches **offline**, with no external emulator and no Switch SDK/runtime needed, on the tested Windows 10 setup. Supply SHA-256, build command, source refs/commit pins, testing report, controls sheet, compatibility notes and explicit remaining limitations. Do not publish copyrighted binaries/assets or automatic GitHub Actions artifact uploads.

### Test matrix (build it as runnable test cases, not prose-only checkboxes)

For each important scene and mechanic test: `Feature ID | Original reference | Input sequence | Expected state | Native output | Visual parity | Timing parity | Save persistence | Pass/fail | Evidence`. Cover at minimum:
- Startup splash, home screen, switch between STORY and SPARRING, UI font rendering, locale changes, full controller navigation.
- Story new-game flow, several campaign checkpoints, Sensei-specific flow, equipment selection, upgrade, magic/projectile unlock, win/loss reward, correct cash/armor stats and restart from save.
- Each fighter's movement, stance, attack/move category, special effect, combo, grab/throw if actually present, blocking/dodging, knocked-down/wake-up timing, fatal hit/round end and boss scripted states.
- Two controllers with independent inputs on **one** arena, player disconnect/reconnect, keyboard + gamepad, rematch, separate control profiles, split assignment and pause focus.
- Save slot creation/read/update/reset, four slots/profile model, interrupted/atomic write, invalid data recovery, USB device reconnect (without damaging the filesystem), migration versioning and path permission errors.
- 720p, 1080p, 1440p, 4K; 60/120 Hz modes; different fullscreen/window flags; GPU lost-focus/recover; controller hot-plug; audio sample rates; huge asset import/low-memory scenario.
- Replay identical input sequence at 60-Hz and 120-Hz render. Combat output must be equivalent within reasoned tolerances; simulation time and hit results cannot change based on display FPS.

## 9 — Automated task loop, context management, and exact handoff protocol

Create and maintain `TASKS.md`, `STATUS.md`, `reports/feature-parity.csv` and `reports/decisions.md`. At the end of each working iteration **write**:

```
[DATE / COMMIT / MILESTONE]
Workspace: <VERIFIED_USB_ROOT>
Source game: <SHA-256 + title/build version; do NOT copy binary>
Last confirmed successful command:
Last confirmed output artifact:
Tests: <passed/failed/blocked counts, commands and logs>
New evidence: <file + offset/address + observation>
Hypothesis changes and confidence:
Top blockers: <with precise reproduction>
Next three safe actions:
```

Break analysis into bounded feature families rather than using the model's context for a full binary dump. Keep `AGENTS.md` concise and enforce it in all sessions. Use scripts to select small function neighborhoods from the indexed knowledge base and link source addresses so conclusions can be rechecked after context compaction. Periodically regenerate a fresh textual `STATUS.md` whose claims are derived from test results, not optimistic estimates.

Use a repeating **observe → hypothesize → implement → compile → run → test → record evidence → refine** loop. Do not spend the first half of the project endlessly reading internet threads. Start with a simple runnable native slice as early as permitted by evidence. If tools fail, collect exact stderr/log + exit codes and repair the shortest failing dependency. If recovered CIL looks readable but causes crashes, fall back to method-level ARM64 analysis and reconstruct domain behavior instead of forcing a corrupted assembly to compile. For large refactors: commit only your own safe source/reconstruction scripts locally; take USB snapshots before change, run smoke suite, roll back cleanly on failures.

**Decision branches:**
- NSP absent/inaccessible → finish preflight, create extraction commands, license/tool checks and project skeleton; log `BLOCKED: source NSP` and exact path needed, rather than inventing assets.
- Rights/key-related NCA extraction blocker → preserve logs, seek only legitimate user-provided means, do not retrieve keys from piracy sites.
- Mono metadata actually present → use ILSpy on verified managed assemblies and proceed with asset import and platform adapters.
- IL2CPP metadata present but obfuscated/incompatible → analyze observed loader and metadata structure with Ghidra; document lawful constraints; don't promise automatic recovery.
- Assets recover but game logic does not → continue instrumented functional reconstruction scene by scene, using metadata/behavior and type structure; never claim full parity until checked.
- Unity reconstruction irreparably breaks critical assets → test a separately implemented Windows-native renderer/engine only if evidence shows less risk, while maintaining original feature requirements and imported asset compatibility; record the tradeoff. Do not start a new engine merely because a first import produced warnings.
- USB lacks disk I/O performance → keep output paths on USB and adjust import batches/caching, choose reduced parallelism; explain realistic limitation instead of silently relocating writes to C:.
- Code/asset redistribution issue → keep local-only; create reporting and script artifacts without publishing protected material.

## 10 — Deliverables and definition of DONE

Artifacts must be produced under `<VERIFIED_USB_ROOT>` and demonstrated with machine-verifiable files, not stated intentions:

1. `dist/ShadowFight2SwitchPC/ShadowFight2SwitchPC.exe` and its complete runtime data, if successfully built and validated.
2. `README.md` with **one-click local launcher** / Windows requirements / controls / save path / troubleshooting / offline run instructions.
3. `src/` implementation, asset converters, extraction audit utilities, USB-drive discovery script, a pinned toolchain manifest and no confidential/proprietary input committed.
4. `analysis/` local-only reverse-engineering project, metadata index, exact file offsets/addresses and corroborating evidence.
5. `reports/engine-fingerprint.md`, `reports/platform-dependency-matrix.csv`, `reports/feature-parity.csv`, `reports/asset-integrity.md`, `reports/performance/`, `reports/toolchain-lock.json`, `reports/repo-triage.md`, test suite output and legal/license notes.
6. A final factual `STATUS.md` stating whether every milestone passed, exactly which Switch edition features are implemented, where the user can launch, and measured FPS/frametimes. Label remaining work with failures/blockers **without euphemisms**.

**Completion check:** I should be able to plug the USB drive into the Windows 10 target computer, double-click a native executable, play complete Shadow Fight 2 **Switch Edition** Story and Sensei content, enter local two-player Sparring, load/save four slots per profile, play without game-service dependencies or an emulator, and select 120 Hz output without speeding up gameplay or producing major animation artifacts. Treat this as the contract. If the verified original assets cannot legally be embedded in a shareable package, keep the executable as a strictly private local derivative and/or develop an installer that uses only the user's local authorized source in compliance with applicable rules. Do **not** claim release completion before test evidence exists.

## 11 — Immediate execution order: act, don't just reply

**On receiving this prompt, start now**:

1. Detect local vs cloud Codex; identify the attached external USB drive and the candidate NSP **read-only**.
2. Run the USB preflight, create the safe project root, directory structure, `AGENTS.md`, `.gitignore`, `README.md`, `STATUS.md`, `TASKS.md`, `Initialize-UsbWorkspace.ps1`, and hash manifest.
3. Fetch and inspect upstream repos/docs, create `toolchain-lock.json`, provision the minimum verified tools **to the USB** and set cache paths. If installing system prerequisites is unavoidable, explain exactly which ones and request permission only for those changes; otherwise continue independent work.
4. Inventory NSP via correct PFS0→NCA workflow; extract actual Program ExeFS/RomFS and resolve base/update correctly if legally accessible; generate fingerprint report. Never put executable/tool commands in the user's `C:` project root.
5. Based on actual fingerprint, choose IL2CPP/Mono/other binary workstream; extract method/type schema + assets; bring up a verified Windows Unity test scene.
6. Implement the first **genuine runnable combat vertical slice**, compile, run, take logs/screenshots and verify it. Continue through complete feature roadmap using the automated test loop and regularly updated file-based checkpoints.

Begin the first shell/tool operations now. Show concise progress with command results, file locations, and verified artifacts. Do not respond with only a new plan, generic disclaimer, or empty assurances. Be resource-efficient, but never sacrifice correctness, provenance or source confidentiality for apparent speed.
