"""Private native witnesses and sanitized bounded future virtual-copy design."""
import hashlib
import json
import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def main():
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original native input changed')
    frames = [json.loads(line) for line in (ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl').read_text().splitlines()]
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    methods = []
    for address, name in [(0x15CA080, 'XmlExtensions.TryGetAttribute'), (0x15CA570, 'XmlExtensions.FirstAttribute')]:
        frame, = [f for f in frames if f['rva'] == address]
        code = raw[0x100 + address:0x100 + frame['end_rva']]
        rows = [dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str, bytes_hex=i.bytes.hex()) for i in cs.disasm(code, address)]
        if len(rows) * 4 != len(code):
            raise ValueError('Incomplete original decoding')
        methods.append(dict(name=name, start=address, end=frame['end_rva'], bytes=len(code), sha256=hashlib.sha256(code).hexdigest(), instructions=rows))
    private_path = 'analysis/reconstruction/virtual-copy-root-v38/native-inventory.json'
    output = destination(ROOT, ROOT / private_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(dict(native_sha256=digest, methods=methods, execution_performed=False), indent=2) + '\n')
    for method in methods:
        print(method['name'], hex(method['start']), hex(method['end']), method['sha256'])
        for i, row in enumerate(method['instructions']):
            if row['mnemonic'] == 'blr':
                print('virtual-call', hex(row['address']))
                for near in method['instructions'][max(0, i-7):i+2]:
                    print(hex(near['address']), near['mnemonic'], near['operands'])
    by_address = {row['address']: row for method in methods for row in method['instructions']}
    expected = {
        0x15CA094: ('ldr', 'x8, [x1]'),
        0x15CA098: ('ldp', 'x9, x8, [x8, #0x188]'),
        0x15CA09C: ('mov', 'x0, x1'),
        0x15CA0A0: ('mov', 'x1, x8'),
        0x15CA0A4: ('blr', 'x9'),
        0x15CA590: ('blr', 'x9'),
        0x15CA594: ('ldr', 'x8, [x0]'),
        0x15CA598: ('ldp', 'x9, x1, [x8, #0x178]'),
        0x15CA59C: ('blr', 'x9'),
    }
    if any((by_address[at]['mnemonic'], by_address[at]['operands']) != pair for at, pair in expected.items()):
        raise ValueError('Reviewed native copy/root windows differ')
    triage_path = 'reports/virtual-receiver-root-triage-v37.json'
    triage = json.loads((ROOT / triage_path).read_text(encoding='utf-8-sig'))
    if triage['core_sha256'] != '23b43f3a1d07dca7483ec0fac031380d934a16f2fc8c34bc5922f52af0ac6044':
        raise ValueError('Triage is not the reviewed unchanged Core snapshot')
    first, second = triage['methods'][:2]
    call = first['calls'][0]
    count_call = second['calls'][1]
    if call['accepted'] or call['slot'] != 6 or call['companion'] is not None or not call['target_scope_accepts']:
        raise ValueError('Companion-copy baseline gap differs')
    if count_call['accepted'] or count_call['slot'] != 5 or count_call['receiver_chain'][0]['definitions'][0]['opcode'] != 'Call':
        raise ValueError('Stable producer-result baseline gap differs')
    negatives = [
        'Companion root loads the wrong slot or a different class value.',
        'Raw MethodInfo argument is not X1, or an explicit native argument would occupy X1.',
        'Copy chain has a cycle, duplicate definition, late definition, non-dominating definition or exceeds32 steps.',
        'A copy source is Phi, address-taken, redefined, memory-reloaded or arbitrarily converted.',
        'Terminal companion load or any intermediate copy is outside the original pure same-block dispatch window.',
        'A field read/store, semantic call or other fault/effect is introduced between class dereference and dispatch.',
        'Non-parameter receiver root has no unique typed reference-producing definition.',
        'Producer return is value type, byref, pointer, generic/open, floating point or otherwise outside the proven X0 ABI.',
        'Producer is an unresolved raw call or has an invalid existing virtual carrier.',
        'Class-load receiver and invocation receiver trace to different same-typed producer results.',
        'Original producer does not dominate both class dereference and invocation, or root escapes by address.',
        'Emitter sees a changed producer identity, root destination, receiver, target, owner or call opcode.',
        'Clone or CopyCoalescer loses the exact producer/root proof identity.',
        'Malformed incoming cone edge or later cycle hides a receiver definition.',
        'Void targets, explicit managed arguments and the Yaml field-root case remain rejected under this proposal.',
    ]
    report = dict(status='DESIGN_ONLY_BOUNDED_VIRTUAL_COMPANION_COPY_AND_STABLE_CALL_RESULT_ROOT', native_source_sha256=digest,
        existing_core_snapshot_sha256=triage['core_sha256'], existing_triage_report=triage_path,
        existing_triage_sha256=hashlib.sha256((ROOT / triage_path).read_bytes()).hexdigest(),
        private_native_path=private_path, private_native_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
        original_methods=[{k: m[k] for k in ('name', 'start', 'end', 'bytes', 'sha256')} for m in methods],
        companion_copy_window=dict(class_load='0x15CA094', paired_slot6_load='0x15CA098', receiver_copy='0x15CA09C', companion_copy='0x15CA0A0', dispatch='0x15CA0A4', function_offset='0x188', companion_offset='0x190'),
        stable_call_result_window=dict(producer_dispatch='0x15CA590', returned_receiver_class_load='0x15CA594', paired_slot5_load='0x15CA598', consumer_dispatch='0x15CA59C', function_offset='0x178', companion_offset='0x180'),
        proposed_companion_rule='Trace only raw X1 companion through at most32 unique available local Move copies to its exact original paired memory load, with same-class identity, slot+8, no index and same-block pure timing window. Preserve all load/copy instructions and all other consumers; do not synthesize values or delete a live companion definition.',
        proposed_receiver_rule='Separate subsequent extension: allow the exact unique available typed reference result of a prior already-proven managed Call as a root. Carry immutable producer-instruction and result-local identity, prove fresh cone dominance/no escape and identical receiver at class load/call, and protect/revalidate both at SSA removal, cloning, coalescing and emission. Do not re-invoke its producer or assume equal-type values are identical.',
        negative_fixture_matrix=negatives, existing_contract_fixtures_to_preserve=43, existing_contract_checks_to_preserve=218, existing_host_clr_cases_to_preserve=99,
        core_modified=False, recovery_performed=False, accepted_new_production_calls=0, game_functions_executed=0,
        void_targets_in_scope=False, explicit_arguments_in_scope=False, arbitrary_field_roots_in_scope=False, full_clean_decompile_ready=False)
    destination(ROOT, ROOT / 'reports/virtual-copy-root-design-v38.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    destination(ROOT, ROOT / 'reports/virtual-copy-root-design-v38.md').write_text(
        '# Bounded virtual-copy proposal\n\n'
        'The smallest next correction is the slot6 companion copy in TryGetAttribute: original native code loads function and MethodInfo together, '
        'copies MethodInfo X8→X1, then dispatches. Keep the original parameter-root proof and trace only this companion through unique available local copies '
        'within the same pure dispatch block. Preserve the loads and their other uses.\n\n'
        'A separate extension could accept FirstAttribute’s slot5 receiver as the unique result of its prior proven get_Attributes call. '
        'It needs immutable producer/root identities, dominance, no escape and fresh emission validation; type equality alone is insufficient. '
        'Do not reload a getter or recreate a producer.\n\n'
        'The JSON records15 negative fixture families. Preserve the existing43 selection fixtures,218 checks and99 host CLR cases. '
        'Void targets, explicit arguments and arbitrary field roots remain outside this proposal. No Core change, fresh recovery or new accepted production call is claimed.\n', encoding='utf-8')
    print(json.dumps(dict(status=report['status'], reviewed_native_instructions=len(expected), negative_fixture_families=len(negatives))))


if __name__ == '__main__':
    main()
