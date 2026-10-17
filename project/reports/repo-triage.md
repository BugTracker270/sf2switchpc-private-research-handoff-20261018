# Repository/tool triage

Updated 2026-10-17T22:13:42.501609+03:00 (Asia/Riyadh). Public source fetched without sending any game material.

## SciresM/hactool

- Authentic upstream: https://github.com/SciresM/hactool
- Pin: `master` / `1d64a83450e025622f3468c28fc4164dad2c5ef6`
- License: ISC; archived: False.
- Format/runtime: C; Windows CLI; PFS0/NCA/NSO
- Target/version/use decision: 1.4.0 official Windows release executes successfully. Source clone pins current master separately. NCA header/body inspection, base-aware patch extraction and NSO decompression used. Key profile is local-only. It can return 0 after invalid headers, so semantic output gates are required.

## DarkMatterCore/nxdumptool

- Authentic upstream: https://github.com/DarkMatterCore/nxdumptool
- Pin: `rewrite` / `ade1a481121498ec649fbc832afe733050790acd`
- License: GPL-3.0; archived: False.
- Format/runtime: C/C++; Switch hardware; content/tickets
- Target/version/use decision: rewrite branch reviewed as a format reference. Signature/ticket structures corroborated common-ticket parsing, including little-endian signature type. No console program installed; supplied NSPs suffice. No keys or SDK fetched.

## Adubbz/Ghidra-Switch-Loader

- Authentic upstream: https://github.com/Adubbz/Ghidra-Switch-Loader
- Pin: `master` / `5d80d195bf284f8ad5f2f9b66c3bdd5c67dd66a6`
- License: ISC; archived: False.
- Format/runtime: Java; Ghidra extension; NSO/ARM64
- Target/version/use decision: Official 1.6.1-c600d05 release explicitly built for Ghidra 12.1.2, with published SHA-256 matched. Installed inside portable Ghidra. Real main import succeeded with ARM64 language and correct 0x7100000000 base.

## NationalSecurityAgency/ghidra

- Authentic upstream: https://github.com/NationalSecurityAgency/ghidra
- Pin: `master` / `9a723ce99952771b8368329503aa589ae233e916`
- License: Apache-2.0; archived: False.
- Format/runtime: Java plus native decompiler; Windows x64
- Target/version/use decision: Official Ghidra 12.1.2 release hash matched. Existing JDK 26 satisfies release minimum 21. Headless import, metadata labels and actual pseudocode/disassembly exports verified. Initial automatic analysis timed out at 600 seconds; bounded scripted recovery is used and recorded separately.

## Perfare/Il2CppDumper

- Authentic upstream: https://github.com/Perfare/Il2CppDumper
- Pin: `master` / `4741d46ba9cd6159c5d853eb9d6fc48b4bfa2b1a`
- License: MIT; archived: False.
- Format/runtime: C#; Windows standalone; NSO + metadata
- Target/version/use decision: v6.7.46 runs on the actual effective NSO and metadata v24. 90,105 method records, metadata schemas, header and DummyDll generated. DummyDll bodies are stubs. Source confirms the <=24 static dummy-object argument rule used in independent ABI checks.

## SamboyCoding/Cpp2IL

- Authentic upstream: https://github.com/SamboyCoding/Cpp2IL
- Pin: `development` / `b5ad444b82267cb1e4b88b8b373c008105bdea52`
- License: MIT; archived: False.
- Format/runtime: C#; .NET 10; NSO ARM64 to ISIL/CIL
- Target/version/use decision: Development commit built locally with installed SDK. NSO and ARM64 paths confirmed in source. Recovered CIL contains many diagnostic helper calls despite a 100% tool success message. A local MIT-source patch corrects legacy ARM64 static argument placement, verified on a native-matched sample. Full CIL correctness remains unproven.

## NepMods/Cpp2IL-Analysis

- Authentic upstream: https://github.com/NepMods/Cpp2IL-Analysis
- Pin: `development` / `39b570b0859e5971afc3edcd4bfc95d57e6313a9`
- License: MIT; archived: False.
- Format/runtime: C#; older specialized Cpp2IL fork
- Target/version/use decision: Source metadata and README reviewed. Stale rewrite/new-analysis instructions and inherited old release links do not establish better target support than current upstream. Not executed or imported. Reconsider only for a specific missing opcode after a native comparison.

## AssetRipper/AssetRipper

- Authentic upstream: https://github.com/AssetRipper/AssetRipper
- Pin: `master` / `beeb50ee1c223e856c860caa338e5309404956a3`
- License: GPL-3.0; archived: False.
- Format/runtime: C# / native Windows release; Unity serialized assets
- Target/version/use decision: Official 2.0.0 release digest matched; local headless web API bound to 127.0.0.1. Actual 2018.1.9f1 data loaded and exported. Folder-only backend detection is Unknown, so a separate staging copy with metadata-only DLLs aids field decoding. This synthetic Mono detection does not change original IL2CPP evidence.

## nesrak1/UABEA

- Authentic upstream: https://github.com/nesrak1/UABEA
- Pin: `master` / `057e2f6ae67ebc94a38faca9f946f8577162fa99`
- License: MIT; archived: False.
- Format/runtime: C#; Unity serialized data inspection
- Target/version/use decision: MIT upstream metadata reviewed; raw README fetch had transient transport failures. Deferred second-opinion inspector because primary export passed raw TextAsset equality checks. No unverified binary acquired; suitable only if a concrete serialized-data mismatch requires it.

## nesrak1/UABEANext

- Authentic upstream: https://github.com/nesrak1/UABEANext
- Pin: `master` / `5c5aef52f877f70fe056e76424848d691cca49ae`
- License: MIT; archived: False.
- Format/runtime: C#; newer Unity inspector
- Target/version/use decision: MIT upstream identity/commit recorded. Documentation fetch failure preserved. Deferred; no assumption about current NSO or target-version support. Existing source-object manifest and raw files retain evidence for later inspection.

## djkaty/Il2CppInspector

- Authentic upstream: https://github.com/djkaty/Il2CppInspector
- Pin: `master` / `116c6355e7ee3656eab85ca753f913d428abc7a3`
- License: AGPL-3.0; archived: False.
- Format/runtime: C#; legacy IL2CPP type/native tooling
- Target/version/use decision: AGPL upstream source metadata reviewed as a legacy reference. Not installed because working Dumper/current Cpp2IL/Ghidra paths exist. Do not infer modern ARM64 compatibility from historical capabilities.

## morluto/rea

- Authentic upstream: https://github.com/morluto/rea
- Pin: `main` / `9d940c2f284cc6f75b27900336e52ceeba4aa2af`
- License: MIT; archived: False.
- Format/runtime: Node.js MCP/CLI; Ghidra provider
- Target/version/use decision: Official rea-agents 6.5.0 installed locally with npm lifecycle scripts disabled. Node 22.23.1 meets declared requirements. Doctor accepts Ghidra/JDK but Windows native self-test refuses removable exFAT TEMP: fixed NTFS is required. Host configuration was not edited; headless Ghidra fallback is functional.

## onerdna/sf-2.x-guide

- Authentic upstream: https://github.com/onerdna/sf-2.x-guide
- Pin: `main` / `243be4a50f7edccf1d15a694daa63cebc08ef687`
- License: UNSPECIFIED; archived: True.
- Format/runtime: Markdown; Android-oriented engine guide
- Target/version/use decision: Describes transition to Unity/IL2CPP and tool workflow. Fundamental backend advice corroborates independently observed Switch data, but Android paths and later 2.x behavior are not transferred to Switch 1.1.0. No source license declared in metadata; reference-only, no code imported.

## moltinginstar/sf2mod

- Authentic upstream: https://github.com/moltinginstar/sf2mod
- Pin: `main` / `ce58a83291e7e43b8bc20657aab72d35adefa2ba`
- License: UNSPECIFIED; archived: False.
- Format/runtime: Python/writeup; Android 2.46 save tooling
- Target/version/use decision: Android save/hash and signing-certificate/device-ID workflow is not a Switch save implementation. README reviewed; no mod, re-sign, cheat or device-injection commands run. Reference-only; no permission inferred to copy unspecified-license code or assets.

## onerdna/stalker

- Authentic upstream: https://github.com/onerdna/stalker
- Pin: `master` / `2b0b0bbba14f1e1848d4029b2d88f46a06412c1d`
- License: GPL-3.0; archived: False.
- Format/runtime: Android application; mobile save viewer/modifier
- Target/version/use decision: GPL-3.0 source identity reviewed. Save record names can be compared only after matching the supplied Switch schemas. Mobile energy, Forge and signing assumptions are not used. No APK or intrusive Android helper installed.

## FlipThoseTitle/Gymnast-Tool-Suite

- Authentic upstream: https://github.com/FlipThoseTitle/Gymnast-Tool-Suite
- Pin: `main` / `539d6e7833fb22b0e40bd9db1bf37b3407a6a216`
- License: GPL-3.0; archived: False.
- Format/runtime: Python; Blender 5.2+ / Cascadeur 2025.3+
- Target/version/use decision: Only source-only SF2 animation importer was fetched from the pinned GPL-3.0 tree. Its point-frame layout was independently matched to actual Switch animation data; an original bounded decoder was implemented. No bundled scenes or third-party Nekki assets fetched, and no Blender/Cascadeur add-on executed.

## NikkaGames/AutoShadow

- Authentic upstream: https://github.com/NikkaGames/AutoShadow
- Pin: `main` / `49d459be5818eb5f7afede002870f046fd212465`
- License: NOASSERTION; archived: False.
- Format/runtime: Android native instrumentation
- Target/version/use decision: Source identity/README only. Not a Switch dumper or port framework. No injection, executable mod or APK run; license metadata requires further review before any reuse.

## Unity-Technologies/InputSystem

- Authentic upstream: https://github.com/Unity-Technologies/InputSystem
- Pin: `develop` / `05e45ddbaf18a93245b068d787d74b738b90d01c`
- License: NOASSERTION; archived: False.
- Format/runtime: C# Unity package; future Windows input
- Target/version/use decision: Official package reference only. New current package cannot be assumed compatible with Unity 2018.1.9f1. Input implementation/editor migration is outside current reverse-engineering scope; no package added to a fake Unity project.
