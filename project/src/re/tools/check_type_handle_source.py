"""Check literal-handle source correction against the isolated actual-CIL gate."""
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination

ROOT = Path(__file__).resolve().parents[3]
PATTERN = re.compile(r'\((?:System\.)?RuntimeTypeHandle\)typeof\(')


def count(run, assembly):
    folder = ROOT / f'analysis/il2cpp/source-profile-project-build-{run}' / assembly
    if not folder.is_dir():
        raise ValueError('Completed source export required')
    return sum(len(PATTERN.findall(path.read_text(encoding='utf-8-sig')))
               for path in folder.rglob('*.cs') if not {'obj', 'bin'}.intersection(path.relative_to(folder).parts))


def main():
    before_run, after_run = 'nso-sparse-params-v25', 'nso-type-handle-v26'
    rows = [dict(assembly=assembly, before=count(before_run, assembly), after=count(after_run, assembly))
            for assembly in ['Assembly-CSharp-firstpass', 'Assembly-CSharp']]
    if any(row['before'] <= row['after'] for row in rows):
        raise ValueError('Expected actual literal-handle casts to decrease in both full source exports')
    before = json.loads((ROOT/f'reports/recovered-type-handle-token-{before_run}.json').read_text())
    after = json.loads((ROOT/f'reports/recovered-type-handle-token-{after_run}.json').read_text())
    if before['type_from_handle_calls'] != 2 or before['checks'] != 0 or 'InvalidProgramException' not in before['fatal']:
        raise ValueError('Preserved actual invalid-CIL baseline required')
    if after['status'] != 'PASS_RECOVERED_TYPE_HANDLE_TOKEN_CONTRACT' or after['type_from_handle_calls'] != 1:
        raise ValueError('Corrected actual-CIL contract gate required')
    selected = ROOT/f'analysis/il2cpp/source-profile-project-build-{after_run}/Assembly-CSharp/CocosAnimationUiSpriteRenderer.cs'
    report = dict(status='PASS_SCOPED_LITERAL_TYPE_HANDLE_CIL_AND_SOURCE_CORRELATION', recovery_run=after_run,
                  assemblies=rows, corrected_clr_contract_checks=after['checks'],
                  selected_source_sha256=hashlib.sha256(selected.read_bytes()).hexdigest(),
                  source_edits=False, complete_getter_validated=False, whole_game_source_ready=False,
                  scope='Count only the exact invalid RuntimeTypeHandle cast applied to typeof expressions in unchanged '
                        'complete per-type decompiler exports. The isolated literal expression passes its CLR contract; '
                        'neither original ARM64 execution nor the full unresolved getter is certified. Both complete '
                        'assemblies still fail compilation; counts are not a readiness percentage.')
    destination(ROOT, ROOT/'reports/type-handle-source-v26.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
