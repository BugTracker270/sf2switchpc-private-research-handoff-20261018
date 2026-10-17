# Current transfer status

The NEW private repository has a synthetic 4 MiB test asset whose local authenticated round trip matched SHA-256. The parent cloud connector returns 404 for the repository until its repository permissions are updated. Its current GitHub fetch supports UTF-8 only and rejects binary archives. Bulk project artifacts are therefore HELD. Do not upload large assets until the parent has a supported authenticated binary download route and verifies an actual download. Do not pass tokens or signed credentials between tasks.

This source view is 1,738 original byte-preserved files, 70,213,777 bytes, plus new handoff documentation. It is a partial handoff; binaries, ignored build outputs, extracted assets, caches, archives and original Git histories remain on USB pending secret review and a supported route. The complete preflight inventory is compressed under handoff/FULL_INVENTORY_PREFLIGHT.json.gz, and original-to-source mapping is in SOURCE_MANIFEST.json.

Credential exclusions are mandatory: input/keys, input/hactool-key-profile, and any detected credential/private-key material including copies. The filename candidate list is a conservative review queue, not proof that every listed public certificate is secret. The source scanner's 11 findings were reviewed as public Mono strong-name identity mappings or artifact hash fields; see SOURCE_FINDING_REVIEW.json.

Source-only review requires no binary transfer or keys. A future fresh .NET 10 Core build is a proposal only, and can obtain pinned public dependencies from official NuGet sources. Exact frozen v40 binary reproduction and native/game behavior work require the private reviewed artifacts and are blocked by the current binary route.

# Build and continuation guide

## Scope and host choice

The goal is a full clean, behavior-validated recovered game logic foundation; port implementation is outside this phase. Full recovery remains incomplete. Packaging or compiling a tool is not decompilation completion.

Measured USB host: Windows 10 build 19045; Intel i7-10750H, 12 logical CPUs; 8,419,950,592 bytes physical RAM, 861,995,008 bytes available at this preflight (89% load); USB free 66,380,890,112 bytes before local preflight files. Installed SDKs: .NET 10.0.400 and 9.0.317; Python 3.12.10; Java 26.0.2; PowerShell and Git. Existing USB tools include Unicorn 2.1.4, Ghidra 12.1.2, Cpp2IL, ILSpy, and exact .NET 3.5 references. No new tool was installed in this phase.

Parent cloud: Linux x86_64, 28 GiB free, 9.7 GiB RAM, Python 3.12, Java 21, Git; .NET and PowerShell absent. The full >29 GiB raw tree cannot fit there with a 5 GiB reserve. Do not download/extract all components at once. Keep the canonical USB copy authoritative and use source/probe/native subsets in a separate cloud working root. Do not create billable Codespaces, Actions, LFS, or cloud capacity implicitly.

## Layout proposed for the NEW private GitHub repository

- `START_HERE.md`, this guide, `manifests/`, and `scripts/` describe exact state and safe retrieval.
- `project/` is a byte-preserving source view of the original project: original scripts/tests, complete modified Cpp2IL source and its local project dependencies, licenses, locks and reports needed to understand builds. Exclude `bin`, `obj`, caches, raw game assets, archived evidence and nested Git databases from ordinary Git objects; retain them in appropriate independently extractable research artifacts after secret review.
- A private draft/research release holds necessary, reviewed reproducibility artifacts, each below 2 GiB, with per-file SHA-256 manifests and component dependencies. This is a project handoff, not an unlimited general backup service.
- Preserve original `.github/workflows` as inert evidence below `project/` or in archives. Do not put inherited workflow YAML in the new repository root's `.github/workflows`. Do not enable Actions or spend compute.
- Never add a remote to the canonical USB root or push its existing history. Preserve original/nested `.git` byte-for-byte only after object/config secret review, or quarantine and explicitly report any unsafe history. Never silently filter and call history identical.

GitHub reference limits checked 2026-10-17: regular Git rejects files >100 MiB; repositories should stay small (ideally <1 GB, strongly <5 GB); release assets must each be under 2 GiB and a release has at most 1000 assets. GitHub's acceptable-use and excessive-bandwidth rules still apply. Sources: https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github ; https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases ; https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies .

## Dependency closures

1. **Source-only review:** all `refs/Cpp2IL` source, project files, sibling projects/submodule source and licenses; all original `src` source, tests and patches; handoff/master/acceptance; current and frozen candidate locks and reports. No game inputs or key files are needed for reading.
2. **Core compilation:** .NET 10 SDK / C# 14; `refs/Cpp2IL/Cpp2IL.Core/Cpp2IL.Core.csproj`, all transitive `ProjectReference` source (including LibCpp2IL and StableNameDotNet), and pinned NuGet package versions. Restore packages from official configured NuGet sources, or a reviewed USB `cache/nuget` artifact. A Windows build/cache is not proof of Linux-native dependency compatibility. Do not upload private source to a dependency service.
3. **Frozen copy-forwarding baseline probe:** `src/re/CopyForwardingRestartProbe` source/project; .NET 10; frozen `analysis/il2cpp/object-isinst-abi-v40-tool-binaries/Cpp2IL.Core.dll`; dependency DLLs from `src/re/ValueThisThunkProbe/bin/Release/net10.0` as required by its project. The probe uses minimal real ISIL objects and does not load game metadata. It requires a NEW report location if an existing report is present; do not rerun over historical reports.
4. **Current bounded safety probe:** `src/re/CopyForwardingSafetyProbe` source/project; current compiled Core and the same managed dependency set. Supply a new unique label. Its test interpreter models explicit byref and memory-write boundaries; it is tool-behavior evidence, not original game method execution.
5. **Native / production-stage probes:** complete compatible Cpp2IL/LibCpp2IL managed runtime closure plus original effective `unpacked/effective/exefs/main`, metadata at `unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat`, original decompressed NSO where named by the selected oracle, and exact referenced frame inventories/locks. Scripts can import neighboring oracle modules and USB-hosted Python packages; inspect the selected script imports and its `.csproj` before choosing a component set. No keys are needed: extraction is complete.
6. **Matching-reference exported-source build:** unchanged exported source for the chosen run, generated compiler project, every recovered reference DLL in the corresponding reference view, pinned official .NET 3.5 reference assemblies, .NET 10 SDK/compiler, and manifests. Both v40 builds are known failures. The preliminary .NET 10 export diagnostics are not the authoritative matching-reference result.
7. **Ghidra:** matching project `.gpr` plus its entire `.rep` directory, compatible Ghidra release/loader and supported Java, separately from the smaller native SQLite/JSONL index. Java 21 in the cloud is not assumed compatible with the existing Ghidra 12.1.2 installation.

Use `COMPONENT_PLAN.json` to keep sources, build closures, native evidence, historical outputs, assets, original inputs and caches independently selectable. The complete file inventory is in `FULL_INVENTORY_PREFLIGHT.json`. Its unset hashes and pending archive/Git reviews are intentional: no bulk transfer is cleared yet.

## Exact previously tested Windows commands

These commands were executed before the packaging-only phase, with process caches redirected by the original USB initializer:

```powershell
$Root = 'F:\SF2SwitchPC'
. "$Root\src\tools\Initialize-UsbWorkspace.ps1" -Root $Root
$env:DOTNET_GCHeapHardLimit = '0x20000000'
dotnet build "$Root\refs\Cpp2IL\Cpp2IL.Core\Cpp2IL.Core.csproj" -c Release -f net10.0 --no-restore --maxcpucount:1 --nodeReuse:false --property:BuildProjectReferences=false --property:GeneratePackageOnBuild=false --property:UseSharedCompilation=false
```

Core result: exit 0, zero warnings/errors. It replaced the live Core build only after the full restart checkpoint was verified; the frozen v40 binary remains separate. This is the subsequent unvalidated v41-era build, not v40 reproduction.

```powershell
dotnet "$Root\src\re\CopyForwardingRestartProbe\bin\Release\net10.0\CopyForwardingRestartProbe.dll" $Root
dotnet "$Root\src\re\CopyForwardingSafetyProbe\bin\Release\net10.0\CopyForwardingSafetyProbe.dll" $Root 'restart-v41-copy-guard'
```

Historical results: frozen baseline confirms 6 semantic counterexamples and 9 preserved controls, exit 0 for that confirmation contract; current suite records 27 cases, 24 equivalent and 3 failing `load-before-memory-write` cases, exit 2. These report names already exist. **Do not rerun these exact historical labels.** Read the durable JSON instead. No complete game method or whole game was executed.

## Proposed Linux commands — NOT TESTED

Install a compatible .NET 10 SDK into the private workspace from official Microsoft distribution only; verify its published checksum. Do not install host software or accept terms implicitly. `dotnet --list-sdks` must confirm the SDK. PowerShell is not needed for a source-only Core compile if the separate cloud boundary/cache setup is implemented first.

```bash
ROOT="$PWD/project"
export TMPDIR="$ROOT/cache/temp"
export DOTNET_CLI_HOME="$ROOT/cache/dotnet"
export NUGET_PACKAGES="$ROOT/cache/nuget"
export NUGET_HTTP_CACHE_PATH="$ROOT/cache/nuget-http"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$TMPDIR" "$DOTNET_CLI_HOME" "$NUGET_PACKAGES" "$NUGET_HTTP_CACHE_PATH"
dotnet restore "$ROOT/refs/Cpp2IL/Cpp2IL.Core/Cpp2IL.Core.csproj" --property:TargetFrameworks=net10.0 --property:NuGetAudit=false
dotnet build "$ROOT/refs/Cpp2IL/Cpp2IL.Core/Cpp2IL.Core.csproj" -c Release -f net10.0 --no-restore --maxcpucount:1 --nodeReuse:false --property:GeneratePackageOnBuild=false --property:UseSharedCompilation=false --property:EnableSourceControlManagerQueries=false
```

These are original infrastructure projects, not arbitrary decompiler-generated build targets. A fresh Linux source build can have a different hash; record a new identity and never change historical pinned probe constants to manufacture a pass. With only 28 GiB free, install/extract the smallest dependency closure first and retain >=5 GiB free. Do not run broad recovery initially.

## Windows-to-Linux mapping and preservation

Map old `F:\SF2SwitchPC\...` to a new canonical private `.../project/...` root in NEW adapter/config artifacts. Preserve historical logs/reports verbatim. Parse historical Windows paths with `PureWindowsPath`, not Linux `Path` separator assumptions. Regenerate infrastructure HintPaths/compile globs in separate new projects while keeping exported source bytes untouched.

Preserve case, line endings and hashes. Do not run Git checkout or text conversion over the only copy. The existing Windows USB guard must remain intact and is expected to fail in a cloud directory; implement a separately named cloud containment/read-only-input/cache/free-space adapter. Do not fake physical USB verification. Never override HOME/USERPROFILE/CODEX_HOME globally.

## First continuation after verified download

Read the full handoff and newer stopped-state reports; verify component and checkpoint hashes; distinguish v39, frozen v40, original unbuilt v41 and the later failed-validation candidate. Inspect the three failing safety cases and the parent's source-review findings, but do not call them repaired. Fresh-array operand-destination and stale-CFG concerns remain unvalidated; its API compile repair is not a semantic proof. The eight v40 added compiler diagnostics and production exception handling remain open. Aim for a complete original method family with original native/data behavior validation rather than compiler-count improvements.

This packaging assignment did not authorize resuming decompilation, executing these commands, starting a port, or spending cloud compute. Commands above are evidence or proposed instructions for the parent to evaluate within the user's current scope.
