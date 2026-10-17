"""Capture selected transfer evidence without changing game/tool implementation."""
import ast
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import subprocess

from usb_boundary import destination

ROOT = Path(__file__).resolve().parents[2]

REPORTS = '''
decompilation-acceptance.json
in-progress-save-v40-v41.json
object-isinst-abi-source-recovery-v40.json
object-isinst-abi-source-recovery-v40.md
diagnostic-scaffolds-nso-object-isinst-abi-v40.json
recovered-object-isinst-abi-nso-object-isinst-abi-v40.json
recovered-object-isinst-abi-v40.md
compiler-diagnostic-delta-v40.json
compiler-diagnostic-added-locations-v40.json
compiler-diagnostic-added-methods-v40.json
compiler-diagnostic-attribution-v40-handoff.json
recovered-source-profile-project-build-nso-object-isinst-abi-v40.json
recovered-source-profile-legacy-reference-check-nso-object-isinst-abi-v40.json
cpp2il-hfa-experimental-lock-object-isinst-abi-v40.json
object-isinst-abi-v40-source-snapshot.json
object-isinst-abi-v40-tool-binary-snapshot.json
object-isinst-abi-v40-frozen-reverse-check.json
object-isinst-abi-independent-source-review-v40.json
object-isinst-abi-contract-v40.json
object-isinst-abi-production-v40.json
native-object-isinst-abi-v40.json
native-object-isinst-exact-class.json
recovery-regression-nso-object-isinst-abi-v40.json
cil-stack-audit-nso-object-isinst-abi-v40.json
native-integer-read-carrier-design-v41.json
fresh-array-class-origin-design-v40.json
fresh-string-literal-source-v40.json
object-isinst-native-source-proposal-v40.json
object-isinst-official-source-v40.json
array-cast-use-attribution-v38.json
unknown-operation-emitter-contract-design.md
class-guard-eh-eligibility-inventory-v35.json
exception-metadata-parser-v35.json
exception-metadata-independent-review-v35.json
exception-region-design-v36.json
exception-region-independent-review-v36.json
tool-survey-20261017.md
toolchain-lock.json
extract-manifest.json
engine-fingerprint.md
legacy-reference-assemblies-lock.json
assembly-leaf-getter-source-recovery-v39.json
assembly-leaf-added-diagnostics-attribution-v39.json
runtime-helper-abi-source-recovery-v37.json
virtual-companion-source-recovery-v38.json
recovered-xml-attribute-runtime-nso-virtual-companion-copy-v38.json
'''.split()

OTHER = '''
AI_HANDOFF_FULL_DECOMPILE.md
AI_HANDOFF_START_HERE.txt
AGENTS.md
STATUS.md
TASKS.md
README.md
.gitignore
input/reference/SF2_Switch_to_Windows10_Codex_Master_Prompt.md
originals_manifest/inputs.json
analysis/continuation-state.json
logs/cpp2il-nso-object-isinst-abi-v40-result.json
analysis/il2cpp/cil-audit-nso-object-isinst-abi-v40/summary.json
patches/experimental-native-read-proof-v41.patch
refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64FreshArrayElementClass.cs
src/re/tool-patches/cpp2il-sf2-hfa-experimental-object-isinst-abi-v40.patch
analysis/reconstruction/compiler-additions-v40/source-context.json
analysis/reconstruction/object-isinst-v40/fresh-output/correlation40.json
src/tools/verify_ai_handoff.py
src/tools/build_ai_handoff_manifest.py
src/tools/Initialize-UsbWorkspace.ps1
src/tools/UsbBoundary.ps1
src/tools/usb_boundary.py
src/tools/Invoke-Cpp2IlMetadataRecovery.ps1
src/tools/Invoke-RecoveredSourceBuild.ps1
src/tools/Invoke-SourceReferenceCheck.ps1
src/tools/Invoke-RecoveryRegression.ps1
src/re/tools/compiler_diagnostic_delta.py
src/re/tools/capture_added_compiler_diagnostics.py
src/re/tools/refine_added_diagnostic_methods.py
src/re/tools/package_cpp2il_hfa_experiment.py
src/re/tools/capture_candidate_source_snapshot.py
src/re/tools/summarize_object_isinst_abi_recovery.py
src/re/tools/summarize_diagnostic_scaffolds.py
src/re/tools/execute_native_object_isinst_exact_class.py
src/re/tools/execute_native_object_isinst_abi.py
'''.split()

RECORDED_INPUTS = [
    ('input/base/Shadow Fight 2 [0100AB000ABFE000][v0][Base].nsp',
     '98d2d44f224321a174ce672826c5ece77d4f98350da336a21ffefc247e36cba5'),
    ('input/update/Shadow Fight 2 [0100AB000ABFE800][v131072][Up v1.1.0].nsp',
     '21831c39c058b815d838a7543678685ef89e1e95778753e71091ae3b8415b8f8'),
    ('unpacked/effective/exefs/main',
     '94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238'),
    ('analysis/nso/main-uncompressed.nso',
     'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968'),
    ('unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat',
     'f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85'),
]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    # This updates continuation metadata only; original game inputs, tool source
    # and all existing recovery/validation reports remain byte-identical.
    state_path = destination(ROOT, ROOT / 'analysis/continuation-state.json')
    state = json.loads(state_path.read_text(encoding='utf-8-sig'))
    state['latest_user_scope'] = ('Documentation only: full detailed AI handoff for a user-provided '
        'complete private cloud copy; finish decompilation there before any porting. No local decompile resumed.')
    state['new_heavy_jobs_held_for_scope_decision'] = False
    state['local_decompile_work_stopped_for_external_handoff'] = True
    state['handoff_document'] = 'AI_HANDOFF_FULL_DECOMPILE.md'
    state['active_v41']['known_unbuilt_compile_blocker'] = ('owner.AnalysisAddress does not exist; '
        'existing API is LegacyArm64ValueThisThunks.AnalysisAddress(owner). Not fixed during handoff.')
    state['updated_utc'] = datetime.now(timezone.utc).isoformat()
    state_path.write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')

    files = {ROOT / 'reports' / name for name in REPORTS}
    files.update(ROOT / name for name in OTHER)
    carrier = json.loads((ROOT / 'reports/native-integer-read-carrier-design-v41.json').read_text())
    for row in carrier['sources']:
        source = ROOT / row['path']
        if sha(source) != row['sha256']:
            raise ValueError('Stopped carrier bytes changed: ' + row['path'])
        files.add(source)
    helper = ROOT / 'refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64FreshArrayElementClass.cs'
    if sha(helper) != '7a541d6698240627a4555295be2da3606d170abfb31f37515502cf13f3220c08':
        raise ValueError('Stopped origin helper changed')
    for relative in ('analysis/il2cpp/object-isinst-abi-v40-source-snapshot',
                     'analysis/il2cpp/object-isinst-abi-v40-tool-binaries'):
        files.update(p for p in (ROOT / relative).rglob('*') if p.is_file())
    dlls = list((ROOT / 'analysis/il2cpp/cpp2il-recovery-nso-object-isinst-abi-v40').glob('*.dll'))
    if len(dlls) != 44:
        raise ValueError('Expected all 44 completed output assemblies')
    files.update(dlls)
    for name in ('ObjectIsInstAbiContractProbe', 'ObjectIsInstProductionProbe', 'RecoveredObjectIsInstAbiProbe'):
        files.update(p for p in (ROOT / 'src/re' / name).iterdir() if p.suffix in ('.cs', '.csproj'))
    for name in ('Assembly-CSharp-firstpass', 'Assembly-CSharp'):
        files.add(ROOT / 'analysis/il2cpp/source-profile-legacy-reference-check-nso-object-isinst-abi-v40'
                  / name / 'MatchingReferences.csproj')
    missing = [str(p.relative_to(ROOT)) for p in files if not p.is_file()]
    if missing:
        raise FileNotFoundError(repr(missing))
    if any(p.suffix.lower() in ('.keys', '.tik', '.cert') for p in files):
        raise ValueError('Credentials excluded')
    rows = [{'path': p.relative_to(ROOT).as_posix(), 'bytes': p.stat().st_size, 'sha256': sha(p)}
            for p in sorted(files)]
    manifest = {
        'status': 'SELECTED_HANDOFF_BYTES_CAPTURED_NOT_GAME_READINESS',
        'prepared_at_asia_riyadh': datetime.now(timezone(timedelta(hours=3))).isoformat(),
        'original_root': str(ROOT),
        'last_git_checkpoint': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
        'latest_completed_run': 'nso-object-isinst-abi-v40',
        'v40_full_clean_decompile_ready': False, 'v41_unbuilt_and_unvalidated': True,
        'files': rows,
        'recorded_game_input_hashes_not_rehashed_at_handoff': [{'path': p, 'sha256': h} for p, h in RECORDED_INPUTS],
        'credential_files_included': False,
        'scope': ('Selected critical evidence, all 44 generated DLLs, frozen v40 tool sources/binaries, '
            'current eight unbuilt v41 files and handoff infrastructure. This is not a complete-folder backup. '
            'Transfer the entire private project including ignored data/dependencies/logs. '
            'Input hashes are recorded provenance, not fresh reads during handoff.')}
    destination(ROOT, ROOT / 'AI_HANDOFF_EVIDENCE_MANIFEST.json').write_text(
        json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    ast.parse((ROOT / 'src/tools/verify_ai_handoff.py').read_text(), filename='verify_ai_handoff.py')
    print(json.dumps({'manifest_files': len(rows), 'selected_bytes': sum(r['bytes'] for r in rows),
        'handoff_words': len((ROOT / 'AI_HANDOFF_FULL_DECOMPILE.md').read_text(encoding='utf-8').split()),
        'v41_stopped_hashes_unchanged': True}))


if __name__ == '__main__':
    main()
