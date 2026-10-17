# Current transfer status

The NEW private repository has a synthetic 4 MiB test asset whose local authenticated round trip matched SHA-256. The parent cloud connector returns 404 for the repository until its repository permissions are updated. Its current GitHub fetch supports UTF-8 only and rejects binary archives. Bulk project artifacts are therefore HELD. Do not upload large assets until the parent has a supported authenticated binary download route and verifies an actual download. Do not pass tokens or signed credentials between tasks.

This source view is 1,738 original byte-preserved files, 70,213,777 bytes, plus new handoff documentation. It is a partial handoff; binaries, ignored build outputs, extracted assets, caches, archives and original Git histories remain on USB pending secret review and a supported route. The complete preflight inventory is compressed under handoff/FULL_INVENTORY_PREFLIGHT.json.gz, and original-to-source mapping is in SOURCE_MANIFEST.json.

Credential exclusions are mandatory: input/keys, input/hactool-key-profile, and any detected credential/private-key material including copies. The filename candidate list is a conservative review queue, not proof that every listed public certificate is secret. The source scanner's 11 findings were reviewed as public Mono strong-name identity mappings or artifact hash fields; see SOURCE_FINDING_REVIEW.json.

Source-only review requires no binary transfer or keys. A future fresh .NET 10 Core build is a proposal only, and can obtain pinned public dependencies from official NuGet sources. Exact frozen v40 binary reproduction and native/game behavior work require the private reviewed artifacts and are blocked by the current binary route.

# SF2 Switch private research handoff — upload pending

Private repository created: https://github.com/BugTracker270/sf2switchpc-private-research-handoff-20261018. The 4 MiB synthetic test asset passed a local authenticated upload/download SHA-256 comparison. Project payload upload and parent cloud binary retrieval are pending.

The CLI now authenticates as **BugTracker270**, numeric ID **202965583**, following the user's login. The new repository is verified private. No credentials were copied into this project or transmitted in reports.

The source project remains at `F:\SF2SwitchPC`. All new preparation files are under `build/github-private-handoff-20261017`, which is excluded from its own inventory. No new decompilation, recovery, game execution, or build was run during this phase.

## Read in this order

1. `UPLOAD_STATUS.json`, `FULL_INVENTORY_PREFLIGHT.json`, and `CREDENTIAL_EXCLUSIONS_PENDING_REVIEW.json` here.
2. Original `AI_HANDOFF_FULL_DECOMPILE.md`, `AGENTS.md`, the master specification in `input/reference`, and `reports/decompilation-acceptance.json`.
3. `BUILD_AND_CONTINUE.md` and `COMPONENT_PLAN.json` here.
4. Current `reports/copy-forwarding-source-reassignment-restart-v41.json`, `reports/copy-forwarding-safety-restart-v41-copy-guard.json`, and `reports/copy-forwarding-restart-source-edits-v41.json`.

## State identities

- Last local Git checkpoint: v39, `f51919b11eba685c83f25fe755cd1d8c827caa87`.
- Latest complete recovery run: frozen v40, `nso-object-isinst-abi-v40`. Both complete source builds fail; helper semantics and production EH remain missing.
- Original stopped v41: eight unbuilt source files, preserved in the full handoff and the byte-verified restart checkpoint.
- Subsequent unvalidated edits: a bounded copy-forwarding correction in `Simplifier.cs`, plus the known `AnalysisAddress` API compile repair in `LegacyArm64FreshArrayElementClass.cs`. Core compiled successfully. The last bounded suite passed 24/27 cases; the three `load-before-memory-write` cases failed. This is not a production-validated recovery candidate.

The last durable checkpoint is `backups/usb-restart-v40-v41-20261017T205754Z.zip`, 423,581,197 bytes, 6,723 entry hashes verified. Its SHA-256 is `e3aaea4aa05922c79b29d5780bcd14dbc590924e4f0c63deddb9fb51a00d017c`.

## Resume upload safely

After the intended account is available through an approved existing authentication route, run `Start-PrivateGitHubAccessTest.ps1` from this directory. It refuses a different account, creates a NEW private repository, checks private visibility before uploading, creates a draft access-test release, uploads a 4 MiB synthetic file, downloads it, and verifies SHA-256. It creates no credentials, changes no global Git settings, starts no Actions/Codespaces, and does not upload the project.

The access-test script executed. Its final draft-tag metadata lookup returned 404; the existing release and test file were inspected without repeating the upload, their hashes matched, and the receipt was recovered. The synthetic test is now a private prerelease. Read ACCESS_TEST_RECEIPT.json. Do not rerun repository creation. The parent cloud should verify actual private binary retrieval; app metadata access alone does not establish that capability.

No full-tree secret clearance has been completed. Both key directories are mandatory exclusions. All archives and Git objects require recursive content inspection, including actual key copies in logs/config/history; quarantine any inseparable secret-bearing file locally and enumerate it. Do not treat filename screening as a completed secret scan.
