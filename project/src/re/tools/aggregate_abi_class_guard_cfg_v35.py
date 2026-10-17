"""Read-only original native CFG witness for the remaining ordinary class guards."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
import sys

import capstone
from capstone.arm64_const import ARM64_OP_IMM

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination
from native_unwind_inventory import Cursor, Image

EXPECTED = {
    0x4A8920: ('GetAssetBundleSafe', 256, '07369c1cddf45700ee6c60c559312bc29ed5debc2c953755d9ac7d7c1414991c'),
    0x4A83A0: ('UnloadDependencies', 384, '0fd52a9b449be83e29a7424dab0003da060929dbe574320d54ecfac5121483f2'),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lsda_call_sites(image: Image, frame: dict, cie: dict) -> dict:
    """Bounded LSDA call-site inventory only; actions/types/unwinding are not decoded."""
    if cie['lsda_encoding'] == 255:
        return dict(present=False, call_sites=[], landing_entries=[])
    cursor = Cursor(image, frame['fde_rva'] + 4, frame['fde_end_rva'])
    cursor.number('I')
    if cursor.encoded(cie['pointer_encoding']) != frame['rva']:
        raise ValueError('FDE pointer replay differs')
    cursor.encoded(cie['pointer_encoding'] & 15)
    augmentation_size = cursor.leb()
    augmentation_end = cursor.position + augmentation_size
    lsda = cursor.encoded(cie['lsda_encoding'])
    if cursor.position != augmentation_end or cursor.position != frame['cfi_start']:
        raise ValueError('Unexpected LSDA FDE augmentation extent')
    ro_end = image.segments[1][1] + image.segments[1][2]
    cursor = Cursor(image, lsda, min(lsda + 4096, ro_end))
    lp_encoding = cursor.number('B')
    lp_start = frame['rva'] if lp_encoding == 255 else cursor.encoded(lp_encoding)
    type_encoding = cursor.number('B')
    type_table = None
    if type_encoding != 255:
        offset = cursor.leb()
        type_table = cursor.position + offset
    call_encoding = cursor.number('B')
    if call_encoding & 0xF0:
        raise ValueError('Only direct unsigned LSDA call-site offsets reviewed')
    table_length = cursor.leb()
    table_start = cursor.position
    table_end = table_start + table_length
    if table_end > cursor.end:
        raise ValueError('LSDA call-site table exceeds bounded extent')
    entries = []
    while cursor.position < table_end:
        if len(entries) >= 256:
            raise ValueError('LSDA call-site inventory bound exceeded')
        offset = cursor.encoded(call_encoding)
        size = cursor.encoded(call_encoding)
        landing = cursor.encoded(call_encoding)
        action = cursor.leb()
        if size < 0 or not frame['rva'] <= lp_start + offset <= lp_start + offset + size <= frame['end_rva']:
            raise ValueError('LSDA protected range outside exact frame')
        if landing and (not frame['rva'] <= lp_start + landing < frame['end_rva'] or (lp_start + landing) % 4):
            raise ValueError('LSDA landing pad outside exact frame')
        entries.append(dict(start=hex(lp_start + offset), end=hex(lp_start + offset + size),
                            landing=hex(lp_start + landing) if landing else None, action=action))
    if cursor.position != table_end:
        raise ValueError('LSDA call-site entry overlaps table end')
    return dict(present=True, rva=hex(lsda), landing_pad_base=hex(lp_start), type_encoding=type_encoding,
                type_table=hex(type_table) if type_table is not None else None,
                call_site_encoding=call_encoding, table_start=hex(table_start), table_end=hex(table_end),
                table_sha256=digest(image.read(table_start, table_length)), call_sites=entries,
                landing_entries=sorted({e['landing'] for e in entries if e['landing'] is not None}),
                scope='Call-site range and landing-entry observations only; action chains, type tables, personality behavior and actual unwinding are not implemented or certified.')


def main() -> None:
    path = ROOT / 'analysis/nso/main-uncompressed.nso'
    raw = path.read_bytes()
    if digest(raw) != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original native image differs')
    frames = {}
    with (ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl').open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['rva'] in EXPECTED:
                if row['rva'] in frames:
                    raise ValueError('Duplicate exact frame')
                frames[row['rva']] = row
    if frames.keys() != EXPECTED.keys():
        raise ValueError('Missing exact frames')
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    cs.detail = True
    image = Image(raw)
    cies = {row['rva']: row for row in json.loads((ROOT / 'analysis/nso/unwind-inventory-v1/cies.json').read_text())}
    script_path = ROOT / 'analysis/il2cpp/effective-main/script.json'
    script = json.loads(script_path.read_text())
    class_slot = struct.unpack('<Q', image.read(0x3982F58, 8))[0]
    metadata_records = [row for row in script['ScriptMetadata'] if row['Address'] == class_slot]
    if len(metadata_records) != 1 or metadata_records[0]['Name'] != 'BundlesUtil_TypeInfo':
        raise ValueError('Original GOT-to-type metadata witness differs')
    methods = []
    for start, (name, size, expected_hash) in EXPECTED.items():
        frame = frames[start]
        if frame['end_rva'] - start != size:
            raise ValueError('Frame size differs')
        body = raw[0x100 + start:0x100 + start + size]
        if digest(body) != expected_hash:
            raise ValueError('Exact original body differs')
        exception_table = lsda_call_sites(image, frame, cies[frame['cie_rva']])
        instructions = list(cs.disasm(body, start))
        if len(instructions) * 4 != size:
            raise ValueError('Incomplete ARM64 instruction decoding')
        leaders = {start}
        targets = {}
        conditional = set()
        terminals = set()
        for instruction in instructions:
            mnemonic = instruction.mnemonic
            branch = mnemonic == 'b' or mnemonic.startswith('b.') or mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz')
            if branch:
                immediates = [o.imm for o in instruction.operands if o.type == ARM64_OP_IMM]
                if not immediates:
                    raise ValueError('Direct branch missing target')
                target = immediates[-1]
                if not start <= target < start + size or target % 4:
                    raise ValueError('Out-of-frame control transfer needs separate review')
                targets[instruction.address] = target
                leaders.add(target)
                if mnemonic != 'b':
                    conditional.add(instruction.address)
                terminals.add(instruction.address)
            elif mnemonic == 'ret':
                terminals.add(instruction.address)
            elif mnemonic == 'br':
                raise ValueError('Indirect control transfer needs separate review')
            if instruction.address in terminals and instruction.address + 4 < start + size:
                leaders.add(instruction.address + 4)
        block_starts = sorted(leaders)
        blocks = []
        for index, block_start in enumerate(block_starts):
            block_end = block_starts[index + 1] if index + 1 < len(block_starts) else start + size
            members = [i for i in instructions if block_start <= i.address < block_end]
            last = members[-1]
            successors = []
            if last.address in targets:
                successors.append(targets[last.address])
            if (last.address not in terminals or last.address in conditional) and block_end < start + size:
                successors.append(block_end)
            blocks.append(dict(start=hex(block_start), end=hex(block_end), successors=[hex(s) for s in successors], predecessors=[]))
        by_start = {int(b['start'], 16): b for b in blocks}
        for block in blocks:
            for successor in block['successors']:
                by_start[int(successor, 16)]['predecessors'].append(block['start'])
        stage = ROOT / f'analysis/il2cpp/raw-classinit-BundlesUtil-{name}-after-type-v33.txt'
        stage_text = stage.read_text(encoding='utf-8-sig')
        source_observations = [line.strip() for line in stage_text.splitlines()
                               if re.search(r'\+(?:122|D4)\]|RunClassConstructor|Call B2E720|\.currentConfig|\.bundlesDependencies', line)]
        method = dict(name='BundlesUtil::' + name, exact_frame=frame, body_sha256=digest(body),
                      cie=cies[frame['cie_rva']], exception_call_site_inventory=exception_table,
                      instructions=[dict(rva=hex(i.address), mnemonic=i.mnemonic, operands=i.op_str) for i in instructions],
                      native_cfg_blocks=blocks, original_class_init_calls=[hex(i.address) for i in instructions
                          if i.mnemonic == 'bl' and i.operands[0].type == ARM64_OP_IMM and i.operands[0].imm == 0xB2E720],
                      production_v33_stage_snapshot=str(stage.relative_to(ROOT)), snapshot_sha256=digest(stage.read_bytes()),
                      production_v33_flag_call_field_observations=source_observations)
        methods.append(method)
        print(method['name'], size, digest(body))
        for instruction in method['instructions']:
            print(instruction['rva'], instruction['mnemonic'], instruction['operands'])
        print('BLOCKS', json.dumps(blocks))
        print('LSDA', json.dumps(exception_table))
    report = dict(status='READ_ONLY_ORIGINAL_NATIVE_CFG_AND_V33_STAGE_WITNESS', methods=methods,
                  exact_class_metadata_witness=dict(got='0x3982f58', metadata_slot=hex(class_slot),
                      original_record=metadata_records[0], script_sha256=digest(script_path.read_bytes())),
                  native_source_sha256=digest(raw), code_modified=False, core_modified=False,
                  probe_source_sha256=digest(Path(__file__).read_bytes()),
                  execution_performed=False, scope='Original exact-FDE ordinary ARM64 branch blocks, bounded LSDA call-site/landing observations and unchanged v33 production-stage snapshots only. Native CFG block edges contain direct branches/fallthrough only, not exception or nonreturn-call semantics. No CFG rewrite, guard normalization, emitted CIL, actual unwinding or runtime equivalence claim.')
    private = destination(ROOT, ROOT / 'analysis/reconstruction/class-guard-cfg-v35/native-witness.json')
    private.parent.mkdir(parents=True, exist_ok=True)
    private.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    sanitized = dict(status=report['status'], private_evidence_path=str(private.relative_to(ROOT)),
                     private_evidence_sha256=digest(private.read_bytes()), native_source_sha256=report['native_source_sha256'],
                     probe_source_sha256=report['probe_source_sha256'], exact_class_metadata_witness=report['exact_class_metadata_witness'],
                     methods=[dict(name=m['name'], exact_frame=m['exact_frame'], body_sha256=m['body_sha256'],
                         instruction_count=len(m['instructions']), direct_branch_block_count=len(m['native_cfg_blocks']),
                         original_class_init_call_count=len(m['original_class_init_calls']), cie_augmentation=m['cie']['augmentation'],
                         has_lsda=m['exception_call_site_inventory']['present'],
                         lsda_rva=m['exception_call_site_inventory'].get('rva'),
                         lsda_table_sha256=m['exception_call_site_inventory'].get('table_sha256'),
                         lsda_call_site_count=len(m['exception_call_site_inventory']['call_sites']),
                         lsda_landing_entries=m['exception_call_site_inventory']['landing_entries'],
                         private_production_snapshot=m['production_v33_stage_snapshot'],
                         private_production_snapshot_sha256=m['snapshot_sha256']) for m in methods],
                     code_modified=False, core_modified=False, execution_performed=False,
                     scope='Sanitized hashes, ranges, counts and original exception-metadata findings. Full original disassembly and typed instruction snapshots remain in ignored local analysis evidence. This is not a production recovery or runtime-equivalence result.')
    destination(ROOT, ROOT / 'reports/class-guard-cfg-native-witness-v35.json').write_text(json.dumps(sanitized, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
