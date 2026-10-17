# Private Switch research checkpoint

This USB contains actual base + patch extraction, decompilation output and analysis tools. **Full semantic reverse engineering remains incomplete. No Windows game build exists.**

- [Current status](STATUS.md), [decompilation quality](reports/decompilation-quality.md), [feature coverage](reports/feature-parity.csv).
- Original, patch-aware data/executable view: `unpacked/effective`.
- Native project: `analysis/nso/SF2-effective.gpr`. Portable Ghidra and its matching Switch Loader are under `tools/ghidra`.
- Native disassembly/pseudocode: `analysis/nso/native-corpus*`; corrected typed exports: `typed-behavior-ai-layout-v2`, `typed-combat-layout-v2`, `typed-combat-prototype-repairs-v2`, and `typed-geometry-layout-v2` under analysis/nso. The earlier v3 samples used an incomplete runtime header and are superseded.
- Runtime type archive: `analysis/il2cpp/sf2-arm64-types-layout-v2.gdt`; critical class/array offsets are independently checked. The final regex export is in `analysis/nso/native-regex-switch-repair-v1` after verified switch-table repairs.
- Searchable native corpus: `analysis/nso/corpus.sqlite`; metadata/annotations: `analysis/il2cpp/research.sqlite`.
- Direct native metadata/string witnesses: `analysis/nso/data-refs.sqlite`; query with `python src/re/tools/native_data_refs.py --string usersDefault`. Only adjacent ADRP/LDR forms are indexed; absence from this index is not proof that a string or method is unused.
- Recovered C# attempts: `analysis/il2cpp/cpp2il-csharp-nso-metadata`; latest scoped AI/math exports: `analysis/il2cpp/cpp2il-csharp-nso-runtime-macros-v4`. These contain unresolved diagnostics; they are not original or buildable game source.
- Asset export: `analysis/assets/unity-export/ExportedProject`; exact source-object identities/hashes: `analysis/assets/source-objects.jsonl`.
- Animation/move/XML catalogs: `analysis/assets/content-v2`; decoded AI archives: `analysis/assets/tactics-decoded-v2`; full bounded table schemas: `analysis/assets/ai-tables-v1`; decoded audio: `analysis/assets/audio-decoded`.
- Compiled research reference models: `analysis/reconstruction`; original ARM64 comparisons: `reports/native-ai-execution.json`, `reports/native-node-integration.json`, `reports/native-save-gate-execution.json`, `reports/native-capsule-geometry.json`, `reports/native-strike-selection.json`, `reports/native-damage-combination.json`, and `reports/native-empty-animation-gate.json`. These test selected functions with synthetic initialized objects and do not run the full game.
- Move template order and filename provenance: `analysis/assets/moves-resolved-v1`; report: `reports/move-template-resolution.json`.
- Story/Sensei loading and quest identity: `reports/story-quest-research.md`, `analysis/assets/quest-loading-v1` and `reports/native-quest-lookup.json`. Original animation curves and point updates: `reports/native-animation-bezier.json` and `reports/native-animation-step.json`.
- Currency widths, denomination and paid-bonus rules: `reports/economy-research.md`. The wallet arithmetic tests document their persistence/statistics stubs explicitly.
- Logical save-slot structure, selected-user Switch mount paths and save scheduling: `reports/save-research.md`, `reports/save-schema-research.json` and `reports/native-save-scheduler.json`. No real save or durable-write test has occurred.
- Run the bounded original-code suite with `pwsh -NoProfile -File src/tools/Invoke-NativeRegression.ps1 -RunName <fresh-name>`; scope assumptions and exact logs are recorded in `reports/native-regression.json`. This is not whole-game execution.
- Exact tool errors, commands and return codes: `logs` and `reports`. Earlier failed attempts are retained; use the versions identified in STATUS.md.

From a PowerShell terminal in this directory:

```powershell
. .\src\tools\Initialize-UsbWorkspace.ps1
python src\re\tools\native_corpus_index.py --name 'PvpScene' --limit 10 --export analysis/nso/selected-view
python -m unittest discover -s tests -v
```

The local Git repository contains original infrastructure/reports only, with no remote. Inputs, keys, extracted assets, native binaries, recovered proprietary code and tool distributions are ignored. Do not publish those private directories.
