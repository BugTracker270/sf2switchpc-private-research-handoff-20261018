"""Record a bounded protected-field candidate without changing recovery policy."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def main():
    survey = json.loads((ROOT / 'reports/private-access-protected-candidate-nso-native-leaves-v29.json').read_text())
    if (survey['status'] != 'PROTECTED_FIELD_CANDIDATE_CIL_AND_METADATA_CONFIRMED'
            or survey['field_visibility'] != 'Family' or not survey['getter_public'] or survey['getter_virtual']
            or len(survey['caller_field_accesses']) != 2 or survey['caller_calls']):
        raise ValueError('Protected caller survey differs')
    expected = {
        'Nekki.SF2.Core.Fights.Model.Components.Nodes.ModelNode$$get_CurrentPosition': (0xFE9F00, '001040f9c0035fd6'),
        'Nekki.SF2.Core.Fights.Model.Components.Edges.ModelEdge$$get_StartPosition': (0xFEA1D0, '082440f9001140f9c0035fd6'),
    }
    database = sqlite3.connect(ROOT / 'analysis/nso/corpus.sqlite')
    witnesses = []
    for name, (rva, code) in expected.items():
        row = database.execute('select rva,corpus,offset,length from functions where name=?', (name,)).fetchone()
        if row[0] != rva:
            raise ValueError('Protected witness address differs')
        with (ROOT / row[1]).open('rb') as stream:
            stream.seek(row[2])
            record = json.loads(stream.read(row[3]))
        native = bytes.fromhex(''.join(line.split('\t')[1] for line in record['assembly'].splitlines()))
        if native.hex() != code:
            raise ValueError('Protected witness native instructions differ')
        witnesses.append(dict(method=name, rva=f'0x{rva:X}', reachable_instructions=len(native) // 4,
            native_sha256=hashlib.sha256(native).hexdigest(), native_calls=0, native_init_guards=0))
    report = dict(status='NATIVE_PROTECTED_GETTER_CANDIDATE_CONFIRMED_NOT_ENABLED', recovery_run='nso-native-leaves-v29',
        metadata_and_cil_report='reports/private-access-protected-candidate-nso-native-leaves-v29.json',
        witnesses=witnesses, prior_main_compiler_current_field_diagnostics=113,
        object_to_node_field_offset='0x48', node_to_current_field_offset='0x20',
        selected_getter_proven_by_existing_helper=True, current_private_only_emitter_accepts=False,
        owner_before_field_init=survey['before_field_init'], owner_has_type_initializer=survey['has_type_initializer'],
        proposed_narrow_capability='Single ordinary protected (Family) instance field loads outside their owner may use the same exact public nonvirtual native-proven getter. Keep stores, field addresses, intermediate struct paths and unsupported layouts unchanged. Preserve original field attributes and emit direct call rather than virtual dispatch.',
        initialization_requirement='For a strict no-new-initialization proof, initially admit only owners with no type initializer, or prove an already-initialized owner dominates the access. ModelNode has a BeforeFieldInit initializer, so native leaf proof alone does not certify cross-runtime initialization timing. Do not remove or reorder existing initialization effects.',
        next_runtime_witness='After a separately checkpointed emitter increment, clone actual rewritten ModelEdge.get_StartPosition plus exact recovered ModelNode.get_CurrentPosition at an explicitly initialized isolated receiver/storage boundary; test reference identity, unrelated storage and null node exception ordering. Then compile the same source files and count remaining protected field diagnostics.',
        core_source_edited=False, game_metadata_modified=False, recovered_cil_executed=False, whole_game_source_ready=False)
    destination(ROOT, ROOT / 'reports/private-access-protected-analysis-v29.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
