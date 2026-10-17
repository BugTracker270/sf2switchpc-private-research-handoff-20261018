"""Read-only native candidate census for the already verified reference Enumerator family."""
from bisect import bisect_right
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys
import capstone
from capstone import arm64 as arm

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination

TARGET, CTOR = 0x1585F60, 0x11DD130
CONSUMERS = {0x11DD3E0: 'MoveNext', 0x11DD540: 'Current', 0x11DD3B0: 'Dispose'}
SOURCE_HASH = 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968'


def canonical(name):
    return 'x' + name[1:] if name.startswith('w') and name[1:].isdigit() else {'fp': 'x29', 'lr': 'x30'}.get(name, name)


def main():
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_HASH:
        raise ValueError('Original native input differs')
    text_file, text_rva, text_size = struct.unpack_from('<III', raw, 0x10)
    segments = [struct.unpack_from('<III', raw, offset) for offset in (0x10, 0x20, 0x30)]
    def read_pointer(rva):
        for file_at, memory_at, size in segments:
            if memory_at <= rva and rva + 8 <= memory_at + size:
                return struct.unpack_from('<Q', raw, file_at + rva - memory_at)[0]
        return None
    frames_path = ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl'
    cies = {row['rva']: row for row in json.loads((frames_path.parent / 'cies.json').read_text())}
    frames = sorted((json.loads(line) for line in frames_path.open()), key=lambda row: row['rva'])
    starts = [row['rva'] for row in frames]
    prefix_ends = []
    for row in frames:
        prefix_ends.append(max(row['end_rva'], prefix_ends[-1] if prefix_ends else 0))
    def owners(address):
        index, result = bisect_right(starts, address) - 1, []
        while index >= 0 and prefix_ends[index] > address:
            if frames[index]['rva'] <= address < frames[index]['end_rva']:
                result.append(frames[index])
            index -= 1
        return result
    direct = []
    text = memoryview(raw)[text_file:text_file + text_size - text_size % 4]
    for index, (word,) in enumerate(struct.iter_unpack('<I', text)):
        if word & 0xFC000000 not in (0x94000000, 0x14000000):
            continue
        immediate = word & 0x03FFFFFF
        if immediate & 0x02000000:
            immediate -= 0x04000000
        address = text_rva + index * 4
        target = address + immediate * 4
        if target in (TARGET, CTOR):
            direct.append((address, target, 'bl' if word & 0x80000000 else 'b'))
    db_path = ROOT / 'analysis/nso/corpus.sqlite'
    database = sqlite3.connect(db_path.as_uri() + '?mode=ro&immutable=1', uri=True)
    indexed = {target: database.execute('SELECT count(*) FROM calls WHERE callee_rva=?', (target,)).fetchone()[0]
               for target in (TARGET, CTOR)}
    alias_names = {}
    for address, name in database.execute('SELECT rva,name FROM aliases'):
        alias_names.setdefault(address, []).append(name)
    indexed_sites = {}
    for target in (TARGET, CTOR):
        sites, unparsed = [], 0
        for (instruction,) in database.execute('SELECT instruction FROM calls WHERE callee_rva=?', (target,)):
            match = re.match(r'\s*(?:0x)?([0-9a-fA-F]+)(?=[:\s])', instruction)
            if match:
                address = int(match.group(1), 16)
                sites.append(address - 0x7100000000 if address >= 0x7100000000 else address)
            else:
                unparsed += 1
        indexed_sites[hex(target)] = dict(unique_instruction_sites=len(set(sites)), duplicate_instruction_sites=len(sites) - len(set(sites)),
                                         unparsed=unparsed, sites_missing_from_exact_text_scan=len(set(sites) - {a for a, t, _ in direct if t == target}))
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    decoder.detail = True
    decoded_cache = {}
    def decoded(frame):
        start, end = frame['rva'], frame['end_rva']
        if start not in decoded_cache:
            decoded_cache[start] = list(decoder.disasm(raw[text_file + start - text_rva:text_file + end - text_rva], start))
        return decoded_cache[start]
    def stack_address(instruction):
        word = int.from_bytes(instruction.bytes, 'little')
        if word & 0xFF8003E0 == 0x910003E0 and word & 31 != 31:
            offset = ((word >> 10) & 0xFFF) << (12 if word & (1 << 22) else 0)
            return f'x{word & 31}', offset
        return None
    def block_starts(instructions):
        points = {instructions[0].address}
        for instruction in instructions:
            if instruction.mnemonic == 'b' or instruction.mnemonic.startswith(('b.', 'cb', 'tb')):
                for operand in instruction.operands:
                    if operand.type == arm.ARM64_OP_IMM:
                        points.add(operand.imm)
                points.add(instruction.address + 4)
            elif instruction.mnemonic in ('ret', 'br'):
                points.add(instruction.address + 4)
        return sorted(points)
    def methodinfo(instructions, call_index):
        blocks = block_starts(instructions)
        first = blocks[bisect_right(blocks, instructions[call_index].address) - 1]
        def resolve(register, before, depth=0):
            if depth > 12:
                return None
            register = canonical(register)
            if register == 'xzr':
                return dict(kind='constant', value=0)
            for at in range(before - 1, -1, -1):
                instruction = instructions[at]
                if instruction.address < first:
                    return None
                if instruction.mnemonic in ('bl', 'blr') and register in {f'x{i}' for i in range(19)}:
                    return None
                _, writes = instruction.regs_access()
                if register not in {canonical(instruction.reg_name(r)) for r in writes}:
                    continue
                operands = instruction.operands
                if instruction.mnemonic in ('adrp', 'adr') and operands[-1].type == arm.ARM64_OP_IMM:
                    return dict(kind='constant', value=operands[-1].imm, definition=hex(instruction.address))
                if instruction.mnemonic == 'mov' and len(operands) == 2:
                    if operands[1].type == arm.ARM64_OP_IMM:
                        return dict(kind='constant', value=operands[1].imm, definition=hex(instruction.address))
                    if operands[1].type == arm.ARM64_OP_REG:
                        return resolve(instruction.reg_name(operands[1].reg), at, depth + 1)
                if instruction.mnemonic == 'ldr' and len(operands) == 2 and not instruction.writeback \
                        and operands[1].type == arm.ARM64_OP_MEM and not operands[1].mem.index:
                    base = resolve(instruction.reg_name(operands[1].mem.base), at, depth + 1)
                    if base is not None and isinstance(base.get('value'), int):
                        address = base['value'] + operands[1].mem.disp
                        return dict(kind='load', address=address, value=read_pointer(address), definition=hex(instruction.address), base=base)
                if instruction.mnemonic == 'add' and len(operands) == 3 and operands[1].type == arm.ARM64_OP_REG \
                        and operands[2].type == arm.ARM64_OP_IMM:
                    base = resolve(instruction.reg_name(operands[1].reg), at, depth + 1)
                    if base is not None and isinstance(base.get('value'), int):
                        return dict(kind='constant', value=base['value'] + (operands[2].imm << operands[2].shift.value), definition=hex(instruction.address), base=base)
                return None
            return None
        result = resolve('x1', call_index)
        return result if result is not None and result.get('kind') == 'load' else None
    def dead_before_overwrite(instructions, call_index, register):
        by_address = {instruction.address: index for index, instruction in enumerate(instructions)}
        visiting, completed = set(), {}
        def walk(index):
            if len(visiting) >= 512:
                return False, 'bounded_path_limit_before_overwrite'
            if index not in range(len(instructions)):
                return False, 'outside_exact_frame'
            if index in completed:
                return completed[index]
            if index in visiting:
                return False, 'cycle_before_overwrite'
            visiting.add(index)
            instruction = instructions[index]
            if instruction.mnemonic in ('bl', 'blr'):
                result = False, 'possible_implicit_call_argument_before_overwrite'
            else:
                reads, writes = instruction.regs_access()
                read_names = {canonical(instruction.reg_name(r)) for r in reads}
                write_names = {canonical(instruction.reg_name(r)) for r in writes}
                if register in read_names:
                    result = False, 'native_read_before_overwrite'
                elif register in write_names:
                    result = True, 'all_traversed_paths_overwrite_before_read'
                elif instruction.mnemonic in ('ret', 'br', 'eret'):
                    result = False, 'terminal_or_indirect_control_without_typed_return_proof'
                else:
                    successors = []
                    if instruction.mnemonic == 'b' or instruction.mnemonic.startswith(('b.', 'cb', 'tb')):
                        operands = [operand.imm for operand in instruction.operands if operand.type == arm.ARM64_OP_IMM]
                        target = operands[-1] if operands else None
                        successors.append(by_address.get(target, -1))
                        if instruction.mnemonic != 'b':
                            successors.append(index + 1)
                    else:
                        successors.append(index + 1)
                    outcomes = [walk(successor) for successor in successors]
                    result = (True, 'all_traversed_paths_overwrite_before_read') if all(row[0] for row in outcomes) else next(row for row in outcomes if not row[0])
            visiting.remove(index)
            completed[index] = result
            return result
        passed, reason = walk(call_index + 1)
        return dict(passed=passed, reason=reason, normal_native_cfg_only=True, visited_instruction_count=len(completed))
    rows = []
    for address, target, kind in direct:
        matched = owners(address)
        row = dict(call_rva=hex(address), target_rva=hex(target), branch_kind=kind, containing_frames=len(matched))
        if len(matched) == 1:
            frame = matched[0]
            instructions = decoded(frame)
            positions = {instruction.address: index for index, instruction in enumerate(instructions)}
            if address not in positions:
                row['exact_disassembly_contains_call'] = False
                rows.append(row)
                continue
            index = positions[address]
            caller_aliases = alias_names.get(frame['rva'], [])
            setup = stack_address(instructions[index - 1]) if index else None
            adjacent = setup is not None and setup[0] == 'x8'
            row.update(caller_rva=hex(frame['rva']), caller_fde_bytes=frame['end_rva'] - frame['rva'],
                caller_cie_augmentation=cies[frame['cie_rva']]['augmentation'],
                caller_lsda_encoding=cies[frame['cie_rva']]['lsda_encoding'],
                caller_body_sha256=hashlib.sha256(raw[text_file + frame['rva'] - text_rva:text_file + frame['end_rva'] - text_rva]).hexdigest(),
                caller_metadata_aliases=caller_aliases, exact_disassembly_contains_call=True,
                adjacent_x8_sp_buffer=adjacent, buffer_sp_offset=setup[1] if adjacent else None)
            if target == TARGET and kind == 'bl':
                info = methodinfo(instructions, index)
                row['methodinfo_straight_line_provenance'] = info
                row['methodinfo_slot_rva'] = hex(info['address']) if info else None
                row['x0_after_call'] = dead_before_overwrite(instructions, index, 'x0')
                row['x8_after_call'] = dead_before_overwrite(instructions, index, 'x8')
                if adjacent:
                    offset = setup[1]
                    takes, memory = [], []
                    for at, instruction in enumerate(instructions):
                        take = stack_address(instruction)
                        if take and offset <= take[1] < offset + 24:
                            following = instructions[at + 1] if at + 1 < len(instructions) else None
                            direct_target = following.operands[-1].imm if following and following.mnemonic in ('bl', 'b') and following.operands[-1].type == arm.ARM64_OP_IMM else None
                            takes.append(dict(rva=hex(instruction.address), destination=take[0], relative_offset=take[1] - offset,
                                adjacent_direct_target=hex(direct_target) if direct_target is not None else None,
                                known_consumer=CONSUMERS.get(direct_target)))
                        for operand in instruction.operands:
                            if operand.type == arm.ARM64_OP_MEM and instruction.reg_name(operand.mem.base) == 'sp' \
                                    and offset - 16 < operand.mem.disp < offset + 24:
                                memory.append(dict(rva=hex(instruction.address), mnemonic=instruction.mnemonic, displacement=operand.mem.disp,
                                                   writeback=instruction.writeback, operands=instruction.op_str))
                    row['buffer_address_takes'] = takes
                    row['nearby_direct_sp_memory_operands'] = memory
                    row['storage_checks_are_complete'] = False
                    row['storage_limit'] = 'Native SP-relative census only; memory widths, changing SP/CFA, FP/derived-pointer aliases, dataflow lifetime/escapes, EH and full ISIL ownership are not proved.'
        rows.append(row)
    get_calls = [row for row in rows if row['target_rva'] == hex(TARGET) and row['branch_kind'] == 'bl']
    adjacent = [row for row in get_calls if row.get('adjacent_x8_sp_buffer')]
    groups = Counter((row.get('caller_rva'), row.get('buffer_sp_offset')) for row in adjacent)
    for row in adjacent:
        row['calls_reusing_same_literal_slot_in_frame'] = groups[row['caller_rva'], row['buffer_sp_offset']]
    details = dict(status='STATIC_NATIVE_CANDIDATE_INVENTORY_NOT_ACCEPTANCE', native_source_sha256=SOURCE_HASH,
        target_rva=hex(TARGET), constructor_rva=hex(CTOR), calls=rows,
        corpus_index_read_only=True, scan_exact_native_text=True, original_text_bytes=text_size)
    detail_path = destination(ROOT, ROOT / 'analysis/nso/reference-enumerator-sret-survey-v35.json')
    detail_path.write_text(json.dumps(details, indent=2) + '\n')
    summary = dict(status='READ_ONLY_REFERENCE_ENUMERATOR_SRET_STATIC_CANDIDATES',
        native_source_sha256=SOURCE_HASH, probe_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        details=str(detail_path.relative_to(ROOT)), details_sha256=hashlib.sha256(detail_path.read_bytes()).hexdigest(),
        original_text_bytes=text_size, indexed_call_edges={hex(key): value for key, value in indexed.items()},
        indexed_instruction_sites=indexed_sites,
        native_direct_edges=dict(Counter(f"{row['branch_kind']}:{row['target_rva']}" for row in rows)),
        getenumerator_bl_calls=len(get_calls), unique_exact_fde_callers=len({row.get('caller_rva') for row in get_calls if row.get('caller_rva')}),
        adjacent_x8_sp_calls=len(adjacent), adjacent_unique_callers=len({row['caller_rva'] for row in adjacent}),
        adjacent_cie_groups=dict(Counter(row['caller_cie_augmentation'] for row in adjacent)),
        straight_line_methodinfo_slot_candidates=sum(row.get('methodinfo_slot_rva') is not None for row in get_calls),
        adjacent_methodinfo_slot_candidates=sum(row.get('methodinfo_slot_rva') is not None for row in adjacent),
        normal_cfg_x0_dead_before_overwrite=sum(row.get('x0_after_call', {}).get('passed', False) for row in adjacent),
        normal_cfg_x8_dead_before_overwrite=sum(row.get('x8_after_call', {}).get('passed', False) for row in adjacent),
        normal_cfg_both_dead_before_overwrite=sum(row.get('x0_after_call', {}).get('passed', False) and row.get('x8_after_call', {}).get('passed', False) for row in adjacent),
        literal_slot_reused_by_multiple_getenumerator_calls=sum(groups[row['caller_rva'], row['buffer_sp_offset']] > 1 for row in adjacent),
        typed_metadata_aliases_resolved=False, storage_ownership_proved=False, production_acceptances=0, core_edited=False,
        scope='Counts are native static call/window candidates, not runtime/managed recovery coverage. Exact frame ownership, adjacent literal SP buffers, straight-line X1 slot expressions and conservative normal-CFG overwrite observations are separate filters. No production adapter is generalized; metadata, storage lifetime/escape, exception flow and actual CIL parity remain required.')
    destination(ROOT, ROOT / 'reports/reference-enumerator-sret-survey-v35.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
