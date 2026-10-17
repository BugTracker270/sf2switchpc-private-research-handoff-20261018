# SF2 Switch local reverse engineering

Read the supplied master specification in input/reference and STATUS.md before continuing.
User's latest scope: full clean decompilation is the primary goal; reverse engineering supports it. Completion requires buildable recovered game logic suitable for a later complete port (e.g. Windows 10 or PS5 homebrew), with identified platform boundaries. Metadata shells, pseudocode coverage, diagnostic stubs and unresolved helpers do not qualify. Do not start a platform port in this phase.

- Canonical project root is this SF2SwitchPC directory on a verified USB disk. Verify BusType=USB every session.
- Dot-source src/tools/Initialize-UsbWorkspace.ps1 before child tools. Guard writes with UsbBoundary.ps1 or Python usb_boundary.py. Never write project outputs outside root, follow reparse points, format drives, install system software, or change host configuration without user approval.
- Inputs are read-only by policy. Preserve original archives. Keys, tickets, binaries, extracted assets and reconstructed proprietary code stay local and ignored by Git. Never publish/upload them or print key bytes. Do not fetch keys, SDKs, commercial game files, bundled Nekki assets, or run injection/cheat software.
- Git is local only, no remotes/push. Commit only original infrastructure and reports that contain no secrets. Stage explicit allowlisted files and inspect staged names.
- Use upstream sources, pin versions/commits and hashes, inspect instructions before executing. REA setup must not modify host agent config without review.
- Unity/IL2CPP, game version, architecture and feature behavior remain UNKNOWN until supported by supplied binary/data. DummyDll is not recovered method code. No fake results, guessed parity, or invented FPS.
- Check free space before large writes; keep at least 5 GiB reserve. exFAT is not journaled; avoid concurrent heavy exports and keep checkpoints.
- Run pwsh -NoProfile -File src/tools/Test-UsbWriteBoundary.ps1 and python -m unittest discover -s tests -v. Record exact errors and return codes under logs/.
- Update STATUS.md, TASKS.md, reports/decisions.md and analysis-coverage.json from evidence. States: NOT_STARTED, IN_PROGRESS, PASS, FAIL, BLOCKED, OUT_OF_SCOPE.
- Stop at missing required lawful material after completing independent work; state exact missing input. No claim of full reverse engineering without validated function/asset/behavior coverage.
