"""Inventory actual diagnostic scaffolds from the completed offline CIL audit.

No-helper and small bodies remain unclassified; neither implies recovered logic.
The assembly hashes bind this observation to the completed recovery invocation.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination

HELPER_TYPE = 'Cpp2ILInjected.Cpp2ILHelpers'
HELPER_NAME = 'NoteDecompilerIssue'
HELPER_MEMBER = HELPER_TYPE + '::' + HELPER_NAME
GAME = {'Assembly-CSharp', 'Assembly-CSharp-firstpass'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'nso-[a-z0-9-]+', args.run):
        raise ValueError('Expected a local recovery run label')
    folder = ROOT / 'analysis/il2cpp' / ('cil-audit-' + args.run)
    audit = json.loads((folder / 'summary.json').read_text(encoding='utf-8-sig'))
    invocation_path = ROOT / 'logs' / ('cpp2il-' + args.run + '-result.json')
    invocation = json.loads(invocation_path.read_text(encoding='utf-8-sig'))
    if invocation['exit_code'] != 0 or len(audit['assemblies']) != 44:
        raise ValueError('A completed 44-assembly recovery/audit is required')
    output = ROOT / 'analysis/il2cpp' / ('cpp2il-recovery-' + args.run)
    private = destination(ROOT, ROOT / 'analysis/il2cpp' / ('diagnostic-scaffolds-' + args.run) / 'methods.jsonl')
    private.parent.mkdir(parents=True, exist_ok=True)
    assemblies = []
    with private.open('w', encoding='utf-8') as details:
        for audit_assembly in audit['assemblies']:
            name = Path(audit_assembly['file']).stem
            path = folder / (name + '.jsonl')
            counts = Counter()
            helpers = []
            for line in path.read_text(encoding='utf-8').splitlines():
                row = json.loads(line)
                if row['error'] is not None:
                    raise ValueError('Malformed CIL audit cannot certify scaffolds')
                counts['inspected_method_bodies'] += 1
                if row['type'] == HELPER_TYPE and row['name'] == HELPER_NAME:
                    helpers.append({'token': row['token'], 'opcodes': row['opcodes'],
                                    'body_bytes': row['body_bytes'], 'il_sha256': row['il_sha256'],
                                    'bare_return_no_log_or_throw': row['opcodes'] == ['ret'] and row['body_bytes'] == 1})
                    continue
                calls = row['call_targets'].count(HELPER_MEMBER)
                if calls:
                    counts['methods_calling_diagnostic_helper'] += 1
                    counts['diagnostic_helper_call_sites'] += calls
                    details.write(json.dumps({'assembly': name, 'type': row['type'],
                        'method': row['name'], 'token': row['token'], 'il_sha256': row['il_sha256'],
                        'diagnostic_helper_calls': calls,
                        'diagnostic_strings': len(row['diagnostic_messages'])}) + '\n')
                else:
                    counts['bodies_without_diagnostic_helper_semantics_unclassified'] += 1
                    counts['minimal_bodies_without_diagnostic_helper_semantics_unclassified'] += int(row['small_body'])
            if len(helpers) != 1:
                raise ValueError('Expected exactly one injected diagnostic helper in ' + name)
            assembly = output / audit_assembly['file']
            assemblies.append({'assembly': name, 'assembly_sha256': sha(assembly),
                'audit_jsonl_sha256': sha(path), 'game_assembly': name in GAME,
                'counts': dict(counts), 'injected_helper': helpers[0]})
    game = [a for a in assemblies if a['game_assembly']]
    if len(game) != 2:
        raise ValueError('Both complete game assemblies must be present')
    totals = Counter()
    for assembly in game:
        totals.update(assembly['counts'])
    no_op = all(a['injected_helper']['bare_return_no_log_or_throw'] for a in assemblies)
    report = {'status': 'OBSERVED_DIAGNOSTIC_SCAFFOLDS_FULL_SOURCE_NOT_READY',
        'recovery_run': args.run, 'invocation_sha256': sha(invocation_path),
        'recovery_core_sha256': invocation['tool_assembly_sha256']['Cpp2IL.Core.dll'],
        'audit_summary_sha256': sha(folder / 'summary.json'),
        'assembly_count': len(assemblies), 'game_assembly_counts': dict(totals),
        'all44_injected_helpers_are_bare_returns': no_op,
        'assemblies': assemblies, 'private_method_inventory': str(private.relative_to(ROOT)),
        'private_method_inventory_sha256': sha(private), 'source_sha256': sha(Path(__file__)),
        'original_game_methods_invoked': 0, 'cil_modified': False, 'core_modified': False,
        'diagnostic_free_bodies_semantically_validated': False, 'full_clean_decompile_ready': False,
        'scope': 'Completed offline CIL audit only, with exact output assembly hashes. Diagnostic helper call counts are implementation gaps, not recovered behavior. A bare-ret helper neither logs nor throws. Unassigned result locals may therefore be observed as InitLocals defaults if execution reaches their reads; this census does not execute or JIT-validate those methods. Bodies without diagnostic calls, including minimal bodies, remain semantically unclassified and can contain other missing logic, defaults or absent exception handling. No completion percentage or native parity follows.'}
    destination(ROOT, ROOT / 'reports' / ('diagnostic-scaffolds-' + args.run + '.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'game_assembly_counts': dict(totals),
                      'all44_injected_helpers_are_bare_returns': no_op}))


if __name__ == '__main__':
    main()
