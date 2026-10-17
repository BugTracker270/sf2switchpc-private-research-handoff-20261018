"""Count unchanged compiler diagnostics and correlate selected leaf witnesses."""
import collections
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination

ROOT = Path(__file__).resolve().parents[3]
RUN = 'nso-generic-ctor-v27'


def main():
    manifest = json.loads((ROOT / f'reports/recovered-source-profile-legacy-reference-check-{RUN}.json').read_text(encoding='utf-8-sig'))
    assemblies = []
    source_cache = {}
    for assembly in manifest['assemblies']:
        log = ROOT / assembly['compiler_log']
        seen = set()
        codes = collections.Counter()
        members = collections.Counter()
        handle_stores = 0
        for line in log.open(encoding='utf-8-sig', errors='replace'):
            match = re.search(r'error (CS\d+): (.*?)(?: \[.*)?$', line)
            if not match:
                continue
            key = line.split(' [F:')[0].strip()
            if key in seen:
                continue
            seen.add(key)
            codes[match[1]] += 1
            if match[1] != 'CS0122':
                continue
            member = re.search("'([^']+)'", match[2])
            if not member:
                raise ValueError('No named inaccessible member')
            members[member[1]] += 1
            if member[1] == 'InputControlMapping.handle':
                location = re.match(r'(.+\.cs)\((\d+),(\d+)\):', line)
                if not location:
                    raise ValueError('No source position')
                source = Path(location[1])
                if source not in source_cache:
                    source_cache[source] = source.read_text(encoding='utf-8-sig').splitlines()
                text = source_cache[source][int(location[2]) - 1]
                handle_stores += bool(re.search(r'\.handle\s*=(?!=)', text))
        if len(seen) != assembly['unique_compiler_diagnostic_lines']:
            raise ValueError('Diagnostic counter differs from compiler manifest')
        assemblies.append(dict(assembly=assembly['assembly'], unique_diagnostic_lines=len(seen),
            diagnostic_codes=dict(codes.most_common()), inaccessible_member_diagnostics=codes['CS0122'],
            most_frequent_inaccessible_members=dict(members.most_common(25)),
            handle_diagnostics=members['InputControlMapping.handle'], handle_store_diagnostics=handle_stores,
            log_sha256=hashlib.sha256(log.read_bytes()).hexdigest()))
    corpus = sqlite3.connect(ROOT / 'analysis/nso/corpus.sqlite')
    records = []
    selected = {
        'InControl.InputControlMapping$$set_Handle': (0x1520D00, '011c00f9c0035fd6'),
        'Nekki.SF2.Core.Fights.Model.Components.Nodes.ModelNode$$get_CurrentPosition': (0xFE9F00, '001040f9c0035fd6'),
        'Nekki.SF2.Core.Utils.Perks.PerkAction$$get_Modificator': (0xF638A0, '00f04039c0035fd6'),
    }
    for name, (rva, expected) in selected.items():
        row = corpus.execute('select rva,corpus,offset,length from functions where name=?', (name,)).fetchone()
        if row[0] != rva:
            raise ValueError('Native address differs')
        with (ROOT / row[1]).open('rb') as stream:
            stream.seek(row[2])
            record = json.loads(stream.read(row[3]))
        native = bytes.fromhex(''.join(line.split('\t')[1] for line in record['assembly'].splitlines()))
        if native.hex() != expected:
            raise ValueError('Native leaf witness differs')
        records.append(dict(method=name, rva=f'0x{rva:X}', reachable_instructions=2,
            native_sha256=hashlib.sha256(native).hexdigest(), no_native_calls_or_branches=True))
    report = dict(status='PRIVATE_ACCESS_DIAGNOSTICS_AND_NATIVE_LEAF_WITNESSES_CONFIRMED',
        recovery_run=RUN, assemblies=assemblies, leaf_witnesses=records,
        renderer_constructor=dict(rva='0xF10A20', parameter_types=['UnityEngine.GameObject'],
            inlined_in='0xF10590', false_branch='0xF105FC', field_offset='0x10',
            metadata_guard_address='0x3B86135', common_object_ctor_target='0x65A2A0',
            common_add_component_target='0x10C7C30', common_method_info_slot='0x39EE508',
            original_csharp_field_flags='private readonly',
            observation='Create false branch and constructor have the same guard, base-constructor call, generic engine call and final field store; a general constructor matcher must retain ordered effects and allocation identity.'),
        recommendation='Use an existing public nonvirtual native-proven exact leaf setter for inaccessible handle stores. Keep original private fields and metadata unchanged. Never replace handle loads with its effectful fallback getter. Treat constructor inlining separately.',
        whole_game_source_ready=False, source_edited=False,
        scope='Distinct diagnostics include cascades and do not measure defect counts or completion. Leaf native instruction witnesses and selection tests are narrow; full method execution and source compilation remain separate gates. Protected fields are reported but initial emitter integration may restrict private fields only.')
    destination(ROOT, ROOT / 'reports/private-access-diagnostics-v27.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({a['assembly']: dict(private=a['inaccessible_member_diagnostics'], handle_stores=a['handle_store_diagnostics']) for a in assemblies}))


if __name__ == '__main__':
    main()
