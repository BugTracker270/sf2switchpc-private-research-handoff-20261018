"""Sanitized, fail-closed design from original Unload exception evidence; no recovery edits."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8-sig'))


def main():
    native_path = ROOT / 'analysis/reconstruction/unload-exception-contract-v35/native-evidence.json'
    native = load(str(native_path.relative_to(ROOT)))
    lsda = native['lsda']
    frame = native['exact_frame']
    instructions = {int(row['rva'], 16): row for row in native['private_original_instructions']}
    sources = {}
    for relative in ('ISIL/OpCode.cs', 'Graphs/Block.cs', 'Graphs/ISILControlFlowGraph.cs',
                     'Model/Contexts/MethodAnalysisContext.cs', 'Analysis/StackAnalyzer.cs',
                     'Analysis/SsaForm.cs', 'IlGenerator.cs', 'OutputFormats/AsmResolverDllOutputFormatIlRecovery.cs'):
        path = ROOT / 'refs/Cpp2IL/Cpp2IL.Core' / relative
        sources[relative] = dict(sha256=sha(path), text=path.read_text(encoding='utf-8-sig'))
    def location(relative, literal):
        text = sources[relative]['text']
        if literal not in text:
            raise ValueError('Required inspected code location changed: ' + relative)
        return dict(path='refs/Cpp2IL/Cpp2IL.Core/' + relative,
                    line=text[:text.index(literal)].count('\n') + 1, sha256=sources[relative]['sha256'])
    locations = {
        'opcode_model': location('ISIL/OpCode.cs', 'public enum OpCode'),
        'ordinary_block_edges': location('Graphs/Block.cs', 'public List<Block> Successors'),
        'entry_only_instruction_enumeration': location('Graphs/ISILControlFlowGraph.cs', 'public List<Instruction> Instructions'),
        'entry_only_reachability': location('Graphs/ISILControlFlowGraph.cs', 'public void RemoveUnreachableBlocks'),
        'normal_call_fallthrough': location('Graphs/ISILControlFlowGraph.cs', 'case OpCode.Call:'),
        'analysis_pipeline': location('Model/Contexts/MethodAnalysisContext.cs', 'ControlFlowGraph = new ISILControlFlowGraph(ConvertedIsil);'),
        'stack_handler_pruning': location('Analysis/StackAnalyzer.cs', 'graph.RemoveUnreachableBlocks();'),
        'ssa_entry_contract': location('Analysis/SsaForm.cs', 'public static void Build(ISILControlFlowGraph graph, DominatorInfo dominatorInfo)'),
        'emitter_new_body': location('IlGenerator.cs', 'var body = new CilMethodBody()'),
        'ordinary_branch_bridge': location('IlGenerator.cs', 'var bridge = new CilInstruction(CilOpCodes.Br'),
        'existing_direct_leaf_integration': location('OutputFormats/AsmResolverDllOutputFormatIlRecovery.cs', 'var aggregateLeaf = LegacyArm64AggregateLeaves.Describe(methodContext);'),
    }
    checks = []
    def check(name, passed):
        checks.append(dict(name=name, passed=bool(passed)))
    source_path = ROOT / 'analysis/nso/main-uncompressed.nso'
    check('original image hash', sha(source_path) == native['original_native_sha256']
          == 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968')
    check('exact original frame', frame['rva'] == 0x4A83A0 and frame['end_rva'] == 0x4A8520)
    expected = [(0x4A8434, 0x4A843C, 0x4A8498, 0x4A8438, 0x11DD3E0, 'MoveNext'),
                (0x4A8444, 0x4A844C, 0x4A848C, 0x4A8448, 0x11DD540, 'Current'),
                (0x4A844C, 0x4A8458, 0x4A8480, 0x4A8454, 0xB0A8A0, 'AssetBundle.Unload')]
    protected = []
    for start, end, landing, call, target, name in expected:
        matching = [row for row in lsda['call_sites'] if row['landing'] and int(row['start'], 16) == start
                    and int(row['end'], 16) == end and int(row['landing'], 16) == landing and row['action'] == 3]
        check(name + ' exact protected call/landing', len(matching) == 1
              and instructions[call]['mnemonic'] == 'bl' and instructions[call]['operands'] == hex(target).replace('0x', '#0x'))
        protected.append(dict(start=hex(start), end_exclusive=hex(end), landing=hex(landing),
                              call=hex(call), callee=hex(target), semantic_role=name, action_entry=3))
    chain = native['action_chains']['3']
    check('typed-wrapper then cleanup action chain', [row['type_filter'] for row in chain] == [1, 0]
          and chain[0]['next_offset'] == -3 and chain[1]['next_offset'] == 0)
    type_one = native['types']['1']
    check('original RTTI name identifies C++ wrapper', type_one['rtti_name'] == '22Il2CppExceptionWrapper'
          and type_one['rtti_vtable']['relocation']['symbol']['name'] == '_ZTVN10__cxxabiv117__class_type_infoE')
    check('handler RTTI equals original managed-exception raiser RTTI',
          type_one['slot_pointer']['raw_or_relative_value'] == native['raiser_rtti_slot']['raw_or_relative_value'] == '0x3674008')
    for address, name in (('0x2373038', '__cxa_begin_catch'), ('0x2373048', '__cxa_end_catch'), ('0x2373058', '_Unwind_Resume')):
        check('original PLT identity ' + name, native['plt_imports'][address]['relocation']['symbol']['name'] == name)
    check('original personality identity', native['personality_slot']['relocation']['symbol']['name'] == '__gxx_personality_v0')
    state = native['cfi_rows'][-1]['state']
    check('original CFI/CFA and saved-register locations', state['cfa_register'] == 29 and state['cfa_offset'] == 16
          and state['saved'] == {'30': -8, '29': -16, '19': -24, '20': -32, '21': -48}
          and instructions[0x4A83A0]['operands'] == 'sp, sp, #0x50'
          and instructions[0x4A83B0]['operands'] == 'x29, sp, #0x40')
    check('all three pads require selector one', all(instructions[landing]['mnemonic'] == 'cmp'
          and instructions[landing]['operands'] == 'w1, #1' for _, _, landing, _, _, _ in expected))
    nonzero_ranges = [(int(row['start'], 16), int(row['end'], 16)) for row in lsda['call_sites'] if row['landing']]
    check('acquisition, both Dispose calls and Clear are outside protected intervals',
          all(not any(start <= address < end for start, end in nonzero_ranges)
              for address in (0x4A841C, 0x4A846C, 0x4A84BC, 0x4A8504)))
    opcode_text = sources['ISIL/OpCode.cs']['text']
    check('current ISIL has no region/leave/finally/rethrow opcode',
          all(token not in opcode_text for token in ('EndFinally', 'Rethrow', 'ExceptionRegion', 'Leave,')))
    check('current Core has no exception-handler table writer', not any('ExceptionHandlers.Add' in path.read_text(encoding='utf-8-sig')
          or 'new CilExceptionHandler' in path.read_text(encoding='utf-8-sig')
          for path in (ROOT / 'refs/Cpp2IL/Cpp2IL.Core').rglob('*.cs') if 'obj' not in path.parts and 'bin' not in path.parts))
    eh_inventory_path = ROOT / 'reports/class-guard-eh-eligibility-inventory-v35.json'
    inventory = load(str(eh_inventory_path.relative_to(ROOT)))
    check('existing measured v33 output has no EH regions', inventory['recovery_run'] == 'nso-class-guard-load-v33'
          and inventory['cil_assembly_count'] == 44 and inventory['cil_method_bodies'] == 60744
          and inventory['cil_exception_regions'] == 0 and not inventory['cil_parse_errors'])
    asm_xml_path = ROOT / 'cache/nuget/asmresolver.dotnet/6.0.1/lib/net10.0/AsmResolver.DotNet.xml'
    asm_xml = asm_xml_path.read_text()
    check('pinned output library already exposes exception table API', all('CilExceptionHandler.' + name in asm_xml
          for name in ('HandlerType', 'TryStart', 'TryEnd', 'HandlerStart', 'HandlerEnd', 'ExceptionType')))
    raiser = load('reports/native-exception-boundary.json')
    check('existing bounded original raiser witness is retained separately', raiser['status'] == 'PASS_NATIVE_EXCEPTION_POINTER_TO_CXX_BOUNDARY'
          and raiser['cases'] == 32 and raiser['checks'] == 224 and raiser['text_modified'] is False
          and raiser['supplied_cpp_rtti_got'] == '0x397B170')
    parser_path = ROOT / 'reports/exception-metadata-parser-v35.json'
    parser = load(str(parser_path.relative_to(ROOT)))
    check('reusable bounded metadata parser synthetic and original-input gates',
          parser['status'] == 'PASS_BOUNDED_EXCEPTION_METADATA_PARSER' and parser['synthetic_tests'] >= 37
          and parser['synthetic_failures'] == parser['synthetic_errors'] == parser['synthetic_skips'] == parser['integration_failures'] == 0
          and parser['parser_sha256'] == sha(ROOT / 'src/tools/exception_metadata.py')
          and parser['private_native_evidence_sha256'] == sha(native_path))
    missing_contracts = [
        dict(area='Native region provenance', gap='No method-level LSDA/actions/types/CFI region descriptor survives conversion. Preserve exact native interval boundaries and original landing roots before reachability pruning.'),
        dict(area='Exception-entry state', gap='Define opaque unwind-token X0 and selector W1 at each landing entry; they are not normal call results/MethodInfo values. Seed frame/CFA and preserved values from the unwind contract; volatile registers become unknown. Do not insert exception edges as ordinary successors.'),
        dict(area='Reachability and SSA', gap='Handler roots require separate reachability. Exceptional state is from the throwing instruction, before any normal return destination, with conservative byref/memory effects. Ordinary phi-edge copy insertion cannot model that transfer. Address-taken Enumerator storage must retain one correct live identity across protected calls and cleanup.'),
        dict(area='Managed region semantics', gap='Represent typed region membership, normal leave, finally entry/exit and propagation. A handler condition is native C++ wrapper RTTI/selector, not an invented System.Exception catch type. A managed finally is a bridge-domain equivalence requiring proof.'),
        dict(area='CIL layout/emission', gap='AsmResolver supports CilExceptionHandler with Finally, inclusive starts/exclusive ends and labels, but current generator never fills the table and always emits ordinary br bridges. Emit leave for normal protected exits, endfinally for handler completion, no br/ret into/out of protected regions, and an empty finally evaluation stack.'),
        dict(area='Validation', gap='Assert serialized EH table/type/bounds and legal transfers, not just MaxStack. Execute original native landing fragments at stated runtime boundaries and then actual emitted recovered CIL; verify side-effect order, exception identity/trace, cleanup once and Clear suppression.'),
    ]
    unresolved = [
        'Actual SDK personality/unwinder installation has not executed. X0/W1 and CFI facts are supported by original pad code, relocations and ABI references; preservation of the installed frame/register state still needs an execution witness.',
        'The three protected callees, exact BundlesUtil static-field binding, all MethodInfo identities and frame-buffer live interval need a complete typed metadata descriptor. The separate SRET survey already proves the GetEnumerator family; it is not a full Unload descriptor.',
        'Selector1 carries the original C++ Il2CppExceptionWrapper. The code extracts a managed pointer, ends catch, disposes, then invokes the original managed raiser when non-null. Other selectors resume without this Dispose; translating them as a catch-all managed finally would exceed the proof.',
        'The native null managed-payload branch reaches the common Clear path. A managed-finally equivalence needs an explicit non-null managed-exception invariant or must preserve/reject this state; the proposal does not silently discard it.',
        'The prior raiser witness covers an existing non-null trace and supplied C++ allocation/throw boundaries. Stack-trace behavior for absent traces, actual C++ unwinding, foreign exceptions, forced unwind and destructor/termination cases remains unproved.',
        'Exact ordinary entry state, the 24-byte Enumerator return/storage identity, post-constructor field reloads and both class-initialization requests must be preserved. Existing v33 Unload CIL is not an execution oracle because EH and its SRET identity are incomplete.',
    ]
    smallest_slice = [
        'First complete an immutable descriptor/proof fixture for only this original 384-byte method: whole-body/FDE/LSDA/action/RTTI/import/CFI hashes, typed field and five List/AssetBundle APIs, exact normal and cleanup orders. Unsupported actions/layouts/aliases/entry states reject atomically.',
        'Run unchanged original landing fragments from each of the three entries with explicit unwind-token/selector/frame and C++ runtime boundaries. Prove selector1 with a non-null managed payload performs begin-catch, end-catch, Dispose once and the same-pointer raise; selectors0/other must reach the original resume boundary without Dispose. This is not yet actual unwinding.',
        'Then validate a disjoint managed region fixture with one Finally clause: acquisition outside try; MoveNext/Current/Unload protected; Dispose only in finally; the second initialization request and Clear only after normal completion. Finally has no catch type. Compare event traces and exception identity under normal/throwing boundaries before production recovery.',
        'If those gates pass, the smallest production candidate is an exact complete-method native-equivalence descriptor/emitter at FillMethodBody, analogous in placement only to the existing exact aggregate-leaf hook. It would emit one structured Finally using original typed members, without routing exceptional control through ordinary CFG/SSA. This is proposed, not implemented or accepted, and must carry explicit inferred-equivalence provenance.',
        'A general EH pipeline is a later larger change: method region sidecars, typed exceptional transfers/entry states, EH-aware reachability, dataflow/alias lifetime, structured CIL layout and verification. Do not broaden normal successors to approximate it.',
    ]
    tests = [
        dict(group='Native descriptor negatives', state='PROPOSED_NOT_RUN', cases=['Truncated/overlapping call-site ranges', 'Changed landing or action offset/cycle', 'Different RTTI/relocation/personality', 'Unresolved/foreign action type', 'Changed CFI/frame/selector register', 'Changed cleanup/raise/resume/normal Clear order']),
        dict(group='Storage/member negatives', state='PROPOSED_NOT_RUN', cases=['Different enum slot or partial/overlapping/escaping region', 'Value/open T or non-unique registered MethodInfo', 'Wrong static field/AssetBundle bool API', 'GetEnumerator inside protected range', 'Dispose or Clear spuriously protected', 'Class-init or field reload reordered']),
        dict(group='Native landing witness', state='PROPOSED_NOT_RUN', cases=['All3 original entries with selector1/non-null distinct exception identities', 'Selector0 and unmatched selector resume unchanged', 'Null managed payload explicitly remains unsupported or tested as its original separate branch']),
        dict(group='CIL region behavior', state='PROPOSED_NOT_RUN', cases=['Empty and1/3/8 element normal iteration', 'Acquisition throws: no Dispose/Clear', 'MoveNext/Current/Unload throw: Dispose once, Clear absent, same exception', 'Dispose throws: replacement exception propagates, Clear absent', 'Post-finally initializer/Clear throws: no duplicate Dispose', 'Forbidden branch into handler, missing endfinally or invalid EH bounds rejected']),
    ]
    references = [
        dict(url='https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/libcxxabi/src/cxa_personality.cpp', supports='Action offsets, type indices and runtime landing parameters; reference model, not a claim that the supplied SDK is this revision.'),
        dict(url='https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/llvm/lib/Target/AArch64/AArch64ISelLowering.h', supports='AArch64 exception-data register convention corroborates original X0/W1 pad use.'),
        dict(url='https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html', supports='Personality/landing-pad and resume distinction.'),
        dict(url='https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf', supports='Managed finally, leave, endfinally and region/stack constraints.'),
        dict(url='https://docs.washi.dev/asmresolver/guides/dotnet/managed-method-bodies.html', supports='Output-library handler table and label APIs; installed6.0.1 XML separately inspected.'),
    ]
    report = dict(status='READ_ONLY_BOUNDED_EXCEPTION_CONTRACT_IDENTIFIED_IMPLEMENTATION_NOT_STARTED',
        checks=len(checks), failures=sum(not row['passed'] for row in checks), tests=checks,
        native_evidence=str(native_path.relative_to(ROOT)), native_evidence_sha256=sha(native_path),
        exact_method='BundlesUtil.UnloadDependencies', exact_fde_bytes=384, protected_calls=protected,
        original_action_filters=[1, 0], original_cpp_rtti_name='22Il2CppExceptionWrapper', managed_catch_type_invented=False,
        entry_contract=dict(exception_data='X0 opaque unwind exception token; fresh entry definition', selector='W1 runtime selector, not prior MethodInfo',
            cfa='X29+16; prologue X29=SP+64 implies CFA=SP+80', enum_region='SP+8..SP+31 = CFA-72..CFA-49',
            saved_register_cfa_offsets={'X30': -8, 'X29': -16, 'X19': -24, 'X20': -32, 'X21': -48},
            installed_context_execution_verified=False),
        smallest_valid_future_slice=smallest_slice, missing_contracts=missing_contracts, unresolved=unresolved,
        proposed_test_groups=tests, upstream_code_locations=locations,
        current_isil_represents_exception_regions=False, current_generator_emits_eh_tables=False,
        output_library_can_emit_eh_tables=True, asmresolver_api_xml_sha256=sha(asm_xml_path),
        existing_v33_eh_inventory_sha256=sha(eh_inventory_path), existing_v33_bodies_without_eh=60744,
        exception_raiser_witness_sha256=sha(ROOT / 'reports/native-exception-boundary.json'),
        completed_parser_foundation=dict(path=str(parser_path.relative_to(ROOT)), sha256=sha(parser_path),
            synthetic_tests=parser['synthetic_tests'], original_evidence_checks=parser['integration_checks'],
            cfi_is_per_instruction_observation=True, finalized_unwind_rows_implemented=False,
            production_region_descriptor_or_emitter_implemented=False),
        primary_references=references, core_edited=False, production_eh_implemented=False,
        original_source_recovered=False, full_clean_decompile_ready=False,
        probe_source_sha256=sha(Path(__file__)),
        scope='Original native exception metadata/action/RTTI/CFI and current upstream pipeline inspection only. No exception edges were added, no catch type guessed, no game/native unwind/managed body executed and no production recovery built. A managed finally remains a conditional native-equivalence proposal in the managed-wrapper/non-null exception domain until typed storage, entry-state and behavior fixtures pass.')
    base = ROOT / 'reports/unload-exception-recovery-proposal-v35'
    destination(ROOT, base.with_suffix('.json')).write_text(json.dumps(report, indent=2) + '\n')
    lines = ['# Bounded UnloadDependencies exception recovery', '', report['status'], '',
             'Cpp2IL currently cannot represent or emit this exception region. AsmResolver can emit it; the recovery IR and pipeline contracts are missing. No production code changed.', '',
             f"The reusable metadata parser has passed {parser['synthetic_tests']} synthetic tests and {parser['integration_checks']} original-evidence checks. Its CFI results are per-instruction observations, including same-PC intermediate states; finalized unwind rows and context installation remain unimplemented. See `reports/exception-metadata-parser-v35.json` for exact hashes and results.", '',
             '| Original protected call | Native half-open range | Landing entry |', '|---|---|---|']
    lines += [f"| {row['semantic_role']} at {row['call']} | {row['start']}..{row['end_exclusive']} | {row['landing']} |" for row in protected]
    lines += ['', 'All three action 3 entries select the original Il2CppExceptionWrapper RTTI (filter 1) followed by cleanup 0. Its RTTI object is identical to the original managed exception raiser. Selector 1 enters begin-catch/end-catch, extracts the managed pointer, disposes the same Enumerator storage, and raises that pointer when non-null. Other selectors reach _Unwind_Resume without this Dispose. This does not justify a fabricated System.Exception catch type or foreign-exception finally.', '',
              'CFI gives CFA=X29+16. The prologue establishes X29=SP+64, so the 80-byte frame keeps its Enumerator at CFA-72..CFA-49. Handler entry must define new X0/W1 exception data and preserve the appropriate frame state; ordinary call-return/MethodInfo SSA values cannot stand in for it.', '',
              'Smallest future slice:', '']
    lines += [f'{index}. {text}' for index, text in enumerate(smallest_slice, 1)]
    lines += ['', 'Missing implementation contracts:', '']
    lines += [f"- **{row['area']}:** {row['gap']}" for row in missing_contracts]
    lines += ['', 'Unresolved before production acceptance:', '']
    lines += [f'- {text}' for text in unresolved]
    lines += ['', 'Fail-closed tests are proposed, not run:', '']
    lines += [f"- **{row['group']}:** " + '; '.join(row['cases']) + '.' for row in tests]
    lines += ['', 'Inspected upstream locations:', '']
    lines += [f"- {name}: `{row['path']}:{row['line']}` (exact file hash in JSON)." for name, row in locations.items()]
    lines += ['', 'Primary references:', '']
    lines += [f"- [{row['supports']}]({row['url']})" for row in references]
    lines += ['', report['scope'], '']
    destination(ROOT, base.with_suffix('.md')).write_text('\n'.join(lines))
    print(json.dumps({key: report[key] for key in ('status', 'checks', 'failures', 'current_isil_represents_exception_regions', 'current_generator_emits_eh_tables', 'production_eh_implemented')}))


if __name__ == '__main__':
    main()
