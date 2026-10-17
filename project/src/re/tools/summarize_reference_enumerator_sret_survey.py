"""Assess reusable SRET eligibility conservatively, without generalizing production code."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import struct
import sys
import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(relative):
    path = ROOT / relative
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    native = load('reports/reference-enumerator-sret-survey-v35.json')
    typed = load('reports/reference-enumerator-sret-metadata-v35.json')
    native_path, typed_path = ROOT / native['details'], ROOT / typed['details']
    native_rows, typed_rows = load(native['details'])['calls'], load(typed['details'])
    by_call = {row['call_rva']: row for row in native_rows}
    raw_path = ROOT / 'analysis/nso/main-uncompressed.nso'
    raw = raw_path.read_bytes()
    checks = []
    def check(name, passed):
        checks.append(dict(name=name, passed=bool(passed)))
    check('original native image', hashlib.sha256(raw).hexdigest() == native['native_source_sha256'])
    check('native inventory exact hash', sha(native_path) == native['details_sha256'] == typed['native_inventory_sha256'])
    check('typed inventory exact hash', sha(typed_path) == typed['details_sha256'])
    check('all original target BL sites classified once', len(typed_rows) == native['getenumerator_bl_calls'] == 1112
          and len({row['call_rva'] for row in typed_rows}) == 1112)
    check('metadata survey does not mutate Core or use generic size classifier', typed['core_edited'] is False
          and typed['production_acceptances'] == 0 and typed['generic_struct_size_classifier_used'] is False)
    pointer_loads = []
    for row in native_rows:
        root = row.get('methodinfo_straight_line_provenance')
        while root:
            if root['kind'] == 'load':
                address = int(root['definition'], 16)
                word = struct.unpack_from('<I', raw, 0x100 + address)[0]
                pointer_loads.append(word & 0xFFC00000 == 0xF9400000)
            root = root.get('base')
    check('native MethodInfo expression loads are original 64-bit unsigned-offset loads', pointer_loads and all(pointer_loads))
    groups = defaultdict(Counter)
    proposed = []
    for row in typed_rows:
        group = groups[row['caller_assembly_group']]
        group['native_getenumerator_calls'] += 1
        valid = row['eligible_verified_metadata_family']
        adjacent = row['adjacent_x8_sp_buffer']
        group['typed_reference_family_calls'] += valid
        group['native_adjacent_x8_sp_calls'] += adjacent
        group['typed_adjacent_x8_sp_calls'] += valid and adjacent
        group['typed_adjacent_both_dead_normal_cfg_calls'] += valid and adjacent and row['both_registers_dead_normal_cfg']
        group['typed_adjacent_eh_free_calls'] += valid and adjacent and row['caller_cie_augmentation'] == 'zR'
        first_shape = valid and adjacent and row['caller_cie_augmentation'] == 'zR' and row['receiver_address_takes_only_shape']
        group['typed_adjacent_eh_free_receiver_address_shape_calls'] += first_shape
        if first_shape:
            proposed.append(row)
    check('no current EH-free receiver-only shape candidates', not proposed)
    check('no main-game EH-free adjacent candidate', groups['Assembly-CSharp']['typed_adjacent_eh_free_calls'] == 0)
    check('firstpass EH-free wrappers fail receiver-only shape', groups['Assembly-CSharp-firstpass']['typed_adjacent_eh_free_calls'] == 4
          and groups['Assembly-CSharp-firstpass']['typed_adjacent_eh_free_receiver_address_shape_calls'] == 0)
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    wrapper = by_call['0x33ebbc']
    body = raw[0x100 + 0x33EB70:0x100 + 0x33EB70 + wrapper['caller_fde_bytes']]
    wrapper_instructions = list(decoder.disasm(body, 0x33EB70))
    box_calls = [hex(i.address) for i in wrapper_instructions if i.mnemonic == 'bl' and i.op_str == '#0xb5b070']
    wrapper_loads = [row for row in wrapper['nearby_direct_sp_memory_operands']
                     if row['mnemonic'] == 'ldr' and row['displacement'] in (24, 32, 40)]
    check('passing shape/liveness wrapper still reads aggregate words and boxes', wrapper['adjacent_x8_sp_buffer']
          and wrapper['x0_after_call']['passed'] and wrapper['x8_after_call']['passed']
          and {row['displacement'] for row in wrapper_loads} == {24, 32, 40} and len(box_calls) == 1)
    reusable = defaultdict(list)
    for row in typed_rows:
        original = by_call[row['call_rva']]
        if row['eligible_verified_metadata_family'] and row['adjacent_x8_sp_buffer']:
            reusable[row['caller_rva'].lower(), original['buffer_sp_offset']].append(row)
    different_types = [rows for rows in reusable.values() if len({row['element_type'] for row in rows}) > 1]
    reuse = next(rows for rows in different_types if rows[0]['caller_rva'].lower() == '0xf58b50')
    check('actual main-game physical-slot reuse has distinct concrete generic types', {row['element_type'] for row in reuse}
          == {'Nekki.SF2.Core.Utils.AchievCounter', 'Nekki.SF2.Core.Utils.Achievement'})
    helper_path = ROOT / 'refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64IndirectReturns.cs'
    check('existing pinned adapter source unchanged', sha(helper_path) == '8c89942388dd92070a024e2238754d40aa83c1d7448c302e1e51209b526a2365')
    requirements = [
        'Keep the verified exact callee/constructor FDE+code+canonical metadata-family descriptor. Resolve each call MethodInfo to one identical registered closed-reference alias and the exact substituted ref/int/int/ref declaration; do not use target address or a guessed generic size alone.',
        'For an initial reusable receiver-only contract, require an exact unique caller/frame and CIE zR with no exception-bearing LSDA contract. Reject unknown, shared-signature or exception-bearing callers until independently supported.',
        'Normalize all original frame addresses through SP/CFA/FP, including dynamic adjustment and derived pointers. Prove the whole aligned 24-byte result region is allocated, nonoverlapping and nonescaping throughout its live interval, with no unsupported interior pointers, raw field copies, boxing or address consumers.',
        'Initially reject multiple GetEnumerator definitions sharing a physical region. A later lifetime extension must prove all-path ordering, dominance, consumers and closed generic type for each definition, including same-slot reuse by different T.',
        'Prove native X0 buffer-pointer and X8 uses dead using the complete relevant CFG and typed call ABI, not merely a target match. Preserve exact pre-SSA native-address/ISIL correspondence and clone branch targets without mutating originals on rejection.',
        'Require unchanged actual recovered CIL to store the aggregate into the same correctly typed local consumed by MoveNext/Current/Dispose, with no scalar aggregate initialization, retarget controls or added defaults. Validate actual native/CIL fragments and existing regressions before any production extension.',
        'Before admitting exception-bearing callers, decode exact FDE/CIE LSDA encodings, call-site ranges, landing pads and cleanup/action/type chains. Include exception paths and their buffer consumers/aliases in lifetime and escape proofs; recover the corresponding CLR EH/rethrow behavior. Ordinary reachable CFG omission cannot prove cleanup dead.',
    ]
    result = dict(status='NO_NEW_ELIGIBLE_CALLERS_UNDER_EH_FREE_RECEIVER_ONLY_CONTRACT' if all(row['passed'] for row in checks) else 'SURVEY_VALIDATION_LIMITATION_CONFIRMED',
        checks=len(checks), failures=sum(not row['passed'] for row in checks), tests=checks,
        by_caller_assembly={key: dict(value) for key, value in groups.items()},
        game_assemblies=['Assembly-CSharp', 'Assembly-CSharp-firstpass'],
        strict_initial_shape_candidates=len(proposed), full_storage_ownership_proved=False,
        new_production_acceptances=0, generalized_adapter_prototyped=False, core_edited=False,
        native_static_call_sites=1112, typed_methodinfo_call_sites=typed['typed_registered_reference_family_calls'],
        adjacent_static_call_sites=native['adjacent_x8_sp_calls'], adjacent_cie_groups=native['adjacent_cie_groups'],
        corpus_index_instruction_sites=native['indexed_instruction_sites'],
        physical_regions_reused_with_distinct_t=len(different_types),
        wrapper_counterexample=dict(caller='System.Net.HttpListenerPrefixCollection.System.Collections.IEnumerable.GetEnumerator',
            caller_rva='0x33EB70', call_rva='0x33EBBC', caller_body_sha256=wrapper['caller_body_sha256'],
            buffer_sp_offset=24, original_field_read_offsets=[24, 32, 40], original_box_helper_call_rvas=box_calls,
            reason='Passes adjacent-buffer and conservative normal-CFG register filters but reads/copies all aggregate words for boxing, outside a receiver-only contract.'),
        typed_slot_reuse_counterexample=dict(caller='Nekki.SF2.Core.Utils.GameUtils.AchievCounters.GetAchievement', caller_rva='0xF58B50',
            buffer_sp_offset=8, calls=[dict(call_rva=row['call_rva'], element_type=row['element_type']) for row in reuse],
            reason='One physical buffer holds distinct closed generic Enumerator types at different native call sites. Lifetime/type partition must be proved, not inferred from equal size.'),
        future_acceptance_requirements=requirements,
        native_survey_report_sha256=sha(ROOT / 'reports/reference-enumerator-sret-survey-v35.json'),
        metadata_survey_report_sha256=sha(ROOT / 'reports/reference-enumerator-sret-metadata-v35.json'),
        native_source_sha256=native['native_source_sha256'], metadata_reader_core_sha256=typed['tool_core_sha256'],
        probe_source_sha256=sha(Path(__file__)),
        scope='Read-only static candidate assessment and actual metadata resolution only. The current contract has zero eligible new game callers, so no generalized adapter or acceptance prototype was attempted. This does not prove full storage ownership for rejected candidates or count recovered methods/runtime coverage. The existing pinned SetStage recovery retains its previously documented EH boundary. Full exception recovery is a confirmed prerequisite for expanding this receiver-only family safely.')
    base = ROOT / 'reports/reference-enumerator-sret-assessment-v35'
    destination(ROOT, base.with_suffix('.json')).write_text(json.dumps(result, indent=2) + '\n')
    lines = ['# Reference Enumerator SRET assessment', '', result['status'], '',
             'No generalized production adapter was implemented. There are zero new eligible game callers under the first EH-free receiver-only contract.', '',
             '| Actual caller assembly | Native calls | Typed adjacent buffers | Typed adjacent, normal-CFG registers dead | Typed adjacent, EH-free | EH-free receiver-only shape |',
             '|---|---:|---:|---:|---:|---:|']
    for key in ('Assembly-CSharp', 'Assembly-CSharp-firstpass'):
        group = groups[key]
        lines.append(f"| {key} | {group['native_getenumerator_calls']} | {group['typed_adjacent_x8_sp_calls']} | {group['typed_adjacent_both_dead_normal_cfg_calls']} | {group['typed_adjacent_eh_free_calls']} | {group['typed_adjacent_eh_free_receiver_address_shape_calls']} |")
    other = Counter()
    for key, group in groups.items():
        if key not in ('Assembly-CSharp', 'Assembly-CSharp-firstpass'):
            other.update(group)
    lines.append(f"| Other actual assemblies | {other['native_getenumerator_calls']} | {other['typed_adjacent_x8_sp_calls']} | {other['typed_adjacent_both_dead_normal_cfg_calls']} | {other['typed_adjacent_eh_free_calls']} | {other['typed_adjacent_eh_free_receiver_address_shape_calls']} |")
    lines += ['', 'The exact native scan found 1,112 calls. Of 869 adjacent X8/SP shapes, 860 have exception-bearing zPLR frames and only nine have zR. All nine are interface/boxing wrappers; four are third-party classes inside firstpass. They fail the receiver-only shape. At 1,047 static call sites, the MethodInfo candidate resolves to one unique registered closed-reference alias per call; these are call sites, not unique aliases or recovered methods.', '',
              'Concrete rejection evidence:', '',
              '- HttpListenerPrefixCollection at 0x33EBBC passes buffer/register filters but loads SP+24/+32/+40 and invokes the original boxing helper.',
              '- AchievCounters.GetAchievement reuses SP+8 for Enumerator<AchievCounter> at 0xF58BBC and Enumerator<Achievement> at 0xF58C34. Equal layout does not establish equal typed lifetime.', '',
              'Required before expansion:', '']
    lines += [f'{index}. {text}' for index, text in enumerate(requirements, 1)]
    lines += ['', result['scope'], '']
    destination(ROOT, base.with_suffix('.md')).write_text('\n'.join(lines))
    print(json.dumps({key: result[key] for key in ('status', 'checks', 'failures', 'strict_initial_shape_candidates', 'physical_regions_reused_with_distinct_t', 'by_caller_assembly')}))


if __name__ == '__main__':
    main()
