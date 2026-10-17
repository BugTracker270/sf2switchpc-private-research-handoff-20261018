"""Inventory exact legacy value-receiver +16 tail branches and prove one codec pair."""
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination

ROOT = Path(__file__).resolve().parents[3]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def declared_value_methods(dump):
    namespace = ''
    owner = None
    pending = None
    result = {}
    for line in dump.splitlines():
        if line.startswith('// Namespace:'):
            namespace = line.split(':', 1)[1].strip()
            owner = None
        match = re.match(r'^(?:(?:public|private|protected|internal|abstract|sealed|static|readonly|ref)\s+)*(class|struct|enum|interface)\s+([^\s:]+)', line)
        if match:
            owner = (namespace + '.' if namespace else '') + match[2] if match[1] == 'struct' else None
            pending = None
        address = re.match(r'\s*// RVA: 0x([0-9a-fA-F]+)\b', line)
        if address:
            pending = int(address[1], 16)
            continue
        if pending is not None and '(' in line and line.rstrip().endswith('{ }'):
            if owner is not None and not re.search(r'\bstatic\b', line.split('(', 1)[0]):
                result.setdefault(pending, []).append(dict(owner=owner, declaration=line.strip()))
            pending = None
    return result


def inventory():
    binary_path = ROOT / 'analysis/nso/main-uncompressed.nso'
    binary = binary_path.read_bytes()
    if digest(binary) != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Effective native source hash differs')
    dump_path = ROOT / 'analysis/il2cpp/effective-main/dump.cs'
    methods = declared_value_methods(dump_path.read_text(encoding='utf-8-sig'))
    metadata_path = ROOT / 'analysis/il2cpp/effective-main/script.json'
    metadata = json.loads(metadata_path.read_text(encoding='utf-8-sig'))
    aliases = {}
    for row in metadata['ScriptMethod']:
        aliases.setdefault(row['Address'], []).append(row['Name'])
    frame_path = ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl'
    frames = {row['rva']: row for row in map(json.loads, frame_path.open(encoding='utf-8'))}
    text_size = struct.unpack_from('<I', binary, 0x18)[0]
    rows = []
    for rva, declarations in methods.items():
        if not 0 <= rva <= text_size - 8:
            continue
        first, branch = struct.unpack_from('<II', binary, rva + 0x100)
        if first != 0x91004000 or branch & 0xFC000000 != 0x14000000:
            continue
        immediate = branch & 0x3FFFFFF
        if immediate & 0x2000000:
            immediate -= 0x4000000
        target = rva + 4 + immediate * 4
        frame = frames.get(rva)
        target_frame = frames.get(target)
        valid = frame is not None and frame['end_rva'] == rva + 8 and target_frame is not None and target != rva
        rows.append(dict(rva=f'0x{rva:X}', target=f'0x{target:X}', declarations=declarations,
                         metadata_aliases=aliases.get(rva, []), target_metadata_aliases=aliases.get(target, []),
                         wrapper_frame_bytes=frame['end_rva']-rva if frame else None,
                         target_frame_bytes=target_frame['end_rva']-target if target_frame else None,
                         wrapper_text_sha256=digest(binary[rva+0x100:rva+0x108]),
                         target_text_sha256=digest(binary[target+0x100:target_frame['end_rva']+0x100]) if target_frame else None,
                         exact_frame_and_target_start=valid))
    target_groups = {}
    for row in rows:
        target_groups.setdefault(row['target'], []).append(row['rva'])
    currency = [row for row in rows if any(decl['owner'] == 'CodeStage.AntiCheat.ObscuredTypes.ObscuredInt' for decl in row['declarations'])]
    report = dict(status='EXACT_VALUE_RECEIVER_ADJUSTOR_CANDIDATES_REQUIRE_RECOVERY_INTEGRATION',
                  declared_value_instance_addresses=len(methods), exact_pattern_addresses=len(rows),
                  exact_frame_and_target_start=sum(row['exact_frame_and_target_start'] for row in rows),
                  targets_without_metadata_aliases=sum(not row['target_metadata_aliases'] for row in rows),
                  distinct_targets=len(target_groups), shared_targets={key: value for key, value in target_groups.items() if len(value)>1},
                  obscured_int_candidates=currency, candidates=rows,
                  source_sha256=dict(binary=digest(binary), dump=digest(dump_path.read_bytes()), metadata=digest(metadata_path.read_bytes()), frames=digest(frame_path.read_bytes())),
                  integration_points=[
                      'Preserve original registered RVA while separately selecting native analysis entry at the exact tail target.',
                      'GetRawBytes/GetIsil and native initialization-macro scans must all use the selected analysis entry; changing only one leaves wrong byte ranges.',
                      'Alias the unboxed target into MethodsByAddress only after exact wrapper/type/signature agreement and shared-target ambiguity checks.',
                      'Value-type managed this is an unboxed byref receiver. Removing a verified boxed +16 adjustor is distinct from subtracting 16 from arbitrary field offsets.',
                      'Calls already targeting the unboxed body need the same managed method signature; ordinary aggregate parameter/result and stack ABI gaps still remain.'
                  ],
                  scope='Exact binary instruction and declared metadata inventory, with independent frame boundaries. Candidate count is not recovered-source or behavior coverage. No Core modifications. Entire boxed receiver implementations, nested/generic/ambiguous target identity, and all native ABI cases are not automatically covered.')
    destination(ROOT, ROOT / 'reports/integer-aggregate-adjustor-inventory.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ['status','declared_value_instance_addresses','exact_pattern_addresses','exact_frame_and_target_start','targets_without_metadata_aliases','distinct_targets','obscured_int_candidates']}, indent=2))
    return report


def native_proof():
    from execute_native_capsules import CapsuleScope
    from execute_native_ai_leaves import FUNCTIONS, HEAP
    FUNCTIONS.update(boxed_int_internal_decrypt=(0x7A9200, 0x7A9208), unboxed_int_internal_decrypt=(0x7A8F20, 0x7A9128))
    scope = CapsuleScope(); vm = scope.vm
    int_class, int_statics, detector_class, detector_statics, detector = [HEAP+offset for offset in [0x10000,0x11000,0x12000,0x13000,0x14000]]
    for got, klass, statics in [(0x39BDB08,int_class,int_statics),(0x39BD740,detector_class,detector_statics)]:
        slot = struct.unpack('<Q', vm.mem_read(got,8))[0]
        scope.put(slot,'Q',klass); scope.put(klass+0xB8,'Q',statics); scope.put(klass+0x122,'B',0)
    guards = [0x3A36686,0x3A3667F,0x3A36680,0x3A3667D,0x3A36614,0x3A36681,0x3A36682,0x3A36685,0x3B84EA5]
    for address in guards:
        vm.mem_write(address,b'\1')
    fixture = ROOT / 'analysis/reconstruction/currency-reference/currency-fixtures-v2.jsonl'
    cases = checks = 0
    for line in fixture.open(encoding='utf-8'):
        row = json.loads(line)
        scope.put(int_statics,'i',row['globalKey']); scope.put(detector_statics+8,'Q',0 if row['mode']==0 else detector); scope.put(detector+0x31,'B',row['mode']==2)
        for function, receiver in [('boxed_int_internal_decrypt',HEAP),('unboxed_int_internal_decrypt',HEAP+16)]:
            vm.mem_write(HEAP,b'\xA5'*16+struct.pack('<QQ',*row['instanceWords'])+b'\x5A'*16)
            result = scope.invoke(function,[receiver,0],[])
            words = struct.unpack('<QQ',vm.mem_read(HEAP+16,16))
            if result != row['internalResult'] or list(words) != row['internalAfter']:
                raise AssertionError(f'{function} differs at {cases}')
            checks += 3
            if bytes(vm.mem_read(HEAP,16)) != b'\xA5'*16 or bytes(vm.mem_read(HEAP+32,16)) != b'\x5A'*16:
                raise AssertionError('Value receiver boundary crossed')
            checks += 2
        cases += 1
    report = dict(status='PASS_ORIGINAL_BOXED_ADJUSTOR_VS_UNBOXED_CODEC_AND_FIXTURES', cases=cases, checks=checks,
                  boxed_entry='0x7A9200', unboxed_entry='0x7A8F20', receiver_adjustment=16, fixture_sha256=digest(fixture.read_bytes()),
                  initialization_guards=[hex(address) for address in guards], game_function_mocks=0, text_modified=False,
                  calls=dict(scope.calls), executed_functions=dict(scope.visited),
                  scope='Both original entry paths execute against the same existing native-verified codec fixtures and match result/post-call value words while preserving the supplied 16-byte header and following sentinel. Synthetic initialized metadata and absent/inactive/active-consistent detector states; no mismatch callback, real boxed object allocation, GC, class initialization, general ABI, recovered CIL or full source claim.')
    destination(ROOT, ROOT/'reports/integer-aggregate-adjustor-native-proof.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    inventory()
    native_proof()
