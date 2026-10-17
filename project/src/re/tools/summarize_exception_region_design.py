"""Evidence-backed region design; standalone synthetic infrastructure, no Core edits."""
from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
sys.path.insert(0, str(ROOT / 'tests'))
from usb_boundary import destination
from exception_regions import validate
from test_exception_regions import fixture


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8-sig'))


def main():
    output = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_exception_regions.py')
    tests = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    unit_log = destination(ROOT, ROOT / 'logs/exception-region-model-v36-tests.log')
    unit_log.write_text(output.getvalue(), encoding='utf-8')
    cfg_path = ROOT / 'reports/exception-graph-boundary-v36.json'
    cfg = load(str(cfg_path.relative_to(ROOT)))
    source_rows = []
    def location(relative, token, gap):
        path = ROOT / 'refs/Cpp2IL/Cpp2IL.Core' / relative
        text = path.read_text(encoding='utf-8-sig')
        if token not in text:
            raise ValueError('Inspected integration point changed: ' + relative)
        row = dict(path=str(path.relative_to(ROOT)), line=text[:text.index(token)].count('\n') + 1,
                   source_sha256=sha(path), current_behavior=gap)
        source_rows.append(row)
        return row
    location('InstructionSets/NewArmV8InstructionSet.cs', 'var addresses = new List<ulong>();',
             'Native address mapping is a local parallel list; one native instruction may lift to multiple ISIL operations. Synthetic entries use ulong.MaxValue. Bare instructions leave this method, so a persistent region/provenance sidecar is missing.')
    location('ISIL/Instruction.cs', 'public bool IsFallThrough',
             'Instruction instances and operands are mutable identity objects. The terminator/use/definition model has no Leave, EndFinally or Rethrow semantics.')
    location('ISIL/Instruction.cs', 'public bool IsStructurallyEqualTo',
             'Instruction identity is deliberately distinct from structural equality; indices are not safe persistent region anchors, and synthetic phi copies can share index -1.')
    location('Graphs/ISILControlFlowGraph.cs', '// Change branch targets to blocks',
             'CFG construction mutates instruction operands from instruction targets to Block identities; shallow list copies do not isolate analysis.')
    location('Graphs/ISILControlFlowGraph.cs', 'queue.Enqueue(EntryBlock);',
             'Instruction enumeration starts only at ordinary method entry, omitting disconnected handler roots.')
    location('Graphs/ISILControlFlowGraph.cs', 'public void RemoveUnreachableBlocks()',
             'Reachability uses only ordinary successor lists; no exception-region root or typed exceptional transfer is represented.')
    location('Graphs/ISILControlFlowGraph.cs', 'public void RemoveNops()',
             'Branch targets protect NOPs; protected/handler boundary anchors are not considered.')
    location('Graphs/ISILControlFlowGraph.cs', 'public void RemoveEmptyBlocks()',
             'Empty-block rewrites update normal predecessor/successor references only; region anchors would also require atomic remapping.')
    location('Graphs/ISILControlFlowGraph.cs', 'public void MergeCallBlocks()',
             'Call blocks merge without region membership or handler-root checks. MetadataResolver invokes this pass.')
    location('Model/Contexts/MethodAnalysisContext.cs', 'ControlFlowGraph = new ISILControlFlowGraph(ConvertedIsil);',
             'Attach and validate native region/provenance data before this CFG construction and before StackAnalyzer pruning.')
    location('Analysis/StackAnalyzer.cs', 'graph.RemoveUnreachableBlocks();',
             'Stack analysis immediately prunes ordinary-unreachable handlers, then seeds only EntryBlock with stack delta zero.')
    location('Analysis/StackAnalyzer.cs', 'private void CorrectOffsets',
             'Stack offsets rely on a per-instruction ordinary stack state. Handler frames need independently validated entry/storage state, not a borrowed normal call-return state.')
    location('Analysis/SsaForm.cs', 'ssa.Rename(graph.EntryBlock, dominatorInfo);',
             'SSA rename has one ordinary entry and positional normal predecessors; no fresh exception-entry definitions or exceptional memory state.')
    location('Analysis/SsaForm.cs', 'private static void InsertBeforeTerminator',
             'Phi removal emits normal predecessor copies. A thrown call cannot execute copies appended after its normal return; exceptional state requires a separate transfer contract.')
    location('IlGenerator.cs', '// Change branch targets to instructions',
             'Emitter mutates Block operands back to instruction targets; region anchors must survive this identity conversion.')
    location('IlGenerator.cs', 'var bridge = new CilInstruction(CilOpCodes.Br',
             'Ordinary bridges use br; region exits need explicit leave, and finally completion needs endfinally with an empty stack.')
    location('IlGenerator.cs', 'case OpCode.Throw:',
             'Current Throw can throw an existing managed object or construct one; it is not Rethrow or native _Unwind_Resume.')
    location('IlGenerator.cs', 'ilBranch.OpCode = CilOpCodes.Nop;',
             'Unresolved normal branch targets currently degrade to warnings/NOP. Region boundaries and illegal EH transfers must instead fail the entire candidate atomically.')
    location('OutputFormats/AsmResolverDllOutputFormatIlRecovery.cs', 'var aggregateLeaf = LegacyArm64AggregateLeaves.Describe(methodContext);',
             'A future exact whole-method descriptor/emitter could isolate one proved cleanup case here; this is a placement proposal, not implementation or permission to bypass missing native/typed evidence.')
    location('Model/Contexts/MethodAnalysisContext.cs', 'public void ReleaseAnalysisData()',
             'Any future region sidecar needs explicit lifecycle handling and evidence export before analysis data is released.')
    proof = validate(fixture())
    checks = [dict(name='standalone structural fixture suite', passed=tests.wasSuccessful() and not tests.skipped and tests.testsRun >= 30),
              dict(name='actual existing-Core pruning/clone boundary gates', passed=cfg['status'] == 'PASS_CURRENT_CORE_CFG_BOUNDARY_PROBE' and cfg['checks'] == 13 and cfg['failures'] == 0),
              dict(name='Core probe binds its source and v35 immutable tool provenance', passed=cfg['probe_source_sha256'] == sha(ROOT / 'src/re/ExceptionGraphBoundaryProbe/Program.cs')
                   and cfg['loaded_core_sha256'] == load('logs/cpp2il-nso-plain-frame-cfg-v35-result.json')['tool_assembly_sha256']['Cpp2IL.Core.dll']),
              dict(name='normal enumeration excludes retained handler nodes', passed=proof.handler_only_reachable == ('dispose', 'end') and 'dispose' not in proof.normal_reachable),
              dict(name='normal leave and exceptional dispatch remain distinct', passed=proof.leave_dispatches == (('leave', 'dispose', 'clear'),) and len(proof.exceptional_dispatches) == 3),
              dict(name='all production EH readiness remains false', passed=not proof.production_eh_ready and cfg['production_eh_ready'] is False and not cfg['core_built'] and not cfg['core_edited'])]
    interfaces = [
        dict(stage='Lifting/provenance', proposed='MethodRegionPlan sidecar on MethodAnalysisContext; stable boundary labels and NativeInstructionSpan(original method/body hash, RVA, lift ordinal). Keep 1-to-many native/ISIL mapping and explicit synthetic origins. Bind every protected throwpoint before native-address data is discarded.'),
        dict(stage='Typed entry', proposed='Separate NativeLandingEntry(X0 opaque unwind token, W1 selector, independently validated frame/storage and unknown volatile registers) from ManagedFinallyEntry(empty evaluation stack, runtime-owned pending dispatch). Fresh handler-entry values cannot reuse normal call destinations or MethodInfo registers. CFI parser observations alone cannot authorize frame installation.'),
        dict(stage='IR terminators', proposed='Leave(continuation, region), EndFinally(region), and Rethrow(catch region) require explicit IsFallThrough/use/definition/terminator handling. Rethrow is rejected until an actual managed catch scope is proved; it is not needed in a finally. Keep native Resume unsupported and distinct from managed Throw/Rethrow.'),
        dict(stage='CFG roots and partitions', proposed='Split at protected/handler boundaries and exceptional throwpoints. Keep normal successors/predecessors separate from instruction-specific exceptional transfers. Structural retention includes anchored handler roots; it must not fabricate normal flow into handlers. Do not merge across region partitions or delete boundary NOP/empty blocks without remapping all anchors.'),
        dict(stage='Stack and memory', proposed='Seed handler physical-frame state independently at a proved entry boundary. Preserve one typed live 24-byte Enumerator storage identity across acquisition, protected byref calls and cleanup; memory state is from the throwpoint after possible callee effects, not an unconditional pre-call snapshot. Unknown alias/overlap/escape/frame states reject.'),
        dict(stage='SSA/dataflow', proposed='Use a normal-flow forest plus explicit exceptional entry parameters/state joins, or initially bypass general SSA only for an exact complete typed method descriptor after all equivalence gates. Ordinary phi predecessor copies are not exceptional argument transfers. Calls produce a normal result only on their normal edge; exception-entry registers are fresh and byref storage effects remain conservative.'),
        dict(stage='Clone/rewrite contract', proposed='Clone instruction instances, remap every branch and region anchor to cloned identities, and clone mutable AddressOf/FieldReference/LocalVariable operand graphs when applicable. Current tiny probe validates only primitive/branch fixture cloning, not a general deep clone. Every rewrite must preserve region membership, labels and ordered side effects atomically.'),
        dict(stage='CIL layout', proposed='Emit acquisition outside try; one structured protected loop; leave to normal continuation; a separate Finally clause with Dispose and endfinally; post-finally class initialization/Clear only on normal completion. Finally has no catch type. Instruction-backed boundary labels must survive zero-IL nodes; do not use arbitrary original block order or normal br across region boundaries.'),
        dict(stage='Validation and failure', proposed='Validate serialized EH kind/bounds/labels and all control transfers, evaluation stack and exact typed operands in addition to MaxStack. Unsupported aliases, foreign dispatch, nested regions, changed native evidence, unresolved labels or inconsistent storage reject the whole method with preserved diagnostic evidence.'),
    ]
    unresolved = [
        'No native LSDA/RTTI action is converted into a managed finally or catch. Original selector 1/non-null managed-wrapper cleanup and foreign/unmatched-selector _Unwind_Resume have different behavior; foreign-exception cleanup stays unresolved.',
        'The v35 CFI API supplies ordered instruction-state observations, including intermediate states at one PC. It does not provide completed PC ranges or an executed SDK personality/unwinder context.',
        'The original null managed-payload branch and trace/raise semantics remain separate proof obligations. A finally propagates runtime-owned pending dispatch; an explicit managed Throw or Rethrow must not be substituted to guess native trace behavior.',
        'The original protected native table has three bounded call intervals. A future contiguous managed try must prove every additional included instruction is non-throwing or has equivalent handling; no action is widened from address proximity.',
        'Exact typed static fields, List/AssetBundle member identities, the 24-byte frame-storage lifetime and normal/cleanup initialization ordering must all be validated before a complete original method can be emitted.',
    ]
    future = [
        dict(state='PROPOSED_NOT_RUN', group='Native landing/context witnesses', cases=['All three unchanged landing entries with selector 1 and distinct non-null managed payloads', 'Original begin/end catch order, one Dispose and same-pointer raise', 'Selector 0/other reaches original resume boundary without fabricated Dispose', 'Separate null-payload behavior and actual installed unwind/frame context']),
        dict(state='PROPOSED_NOT_RUN', group='Serialized CIL structure', cases=['Exactly one Finally, no catch type, correct half-open instruction boundaries', 'Normal protected exits use leave, handler completes with endfinally', 'Empty finally entry stack and no branch/ret across region boundaries', 'Malformed/foreign/nested/changed descriptor rejects atomically']),
        dict(state='PROPOSED_NOT_RUN', group='Runtime side-effect/exception behavior', cases=['Empty/1/3/8 element normal loop and repeated invocation', 'Acquisition throws: no Dispose or Clear', 'MoveNext/Current/Unload throws: Dispose once, Clear absent, same exception identity', 'Dispose throws: replacement exception propagates, no Clear', 'Post-finally initialization/Clear throws: no duplicate Dispose', 'Trace and normal-result visibility checked independently']),
    ]
    report = dict(status='PASS_STANDALONE_REGION_DESIGN_FOUNDATION' if all(row['passed'] for row in checks) else 'FAIL_REGION_DESIGN_FOUNDATION',
        synthetic_model_tests=tests.testsRun, synthetic_failures=len(tests.failures), synthetic_errors=len(tests.errors),
        synthetic_skips=len(tests.skipped), evidence_checks=len(checks), evidence_failures=sum(not row['passed'] for row in checks), checks=checks,
        current_core_boundary_checks=cfg['checks'], current_core_boundary_report_sha256=sha(cfg_path),
        runtime_probe_core_sha256=cfg['loaded_core_sha256'], unit_log_sha256=sha(unit_log),
        model_source_sha256=sha(ROOT / 'src/tools/exception_regions.py'), unit_source_sha256=sha(ROOT / 'tests/test_exception_regions.py'),
        report_source_sha256=sha(Path(__file__)), standalone_validated_fixture=asdict(proof), upstream_code_audit=source_rows,
        proposed_core_contracts=interfaces, unresolved_original_semantics=unresolved, future_test_groups=future,
        original_contract_report_sha256=sha(ROOT / 'reports/unload-exception-recovery-proposal-v35.json'),
        primary_references=[
            dict(url='https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.br?view=net-10.0', claim='Ordinary branch cannot enter/leave protected and handler blocks.'),
            dict(url='https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.leave?view=net-10.0', claim='Leave clears the stack and executes surrounding finally blocks; it cannot exit finally.'),
            dict(url='https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.rethrow?view=net-10.0', claim='Rethrow belongs only to a catch body, not a finally.'),
            dict(url='https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf', claim='CLI exception-region and instruction semantics; the standalone checker is a conservative subset, not full CIL verification.'),
        ],
        core_edited=False, core_built=False, production_eh_ready=False, catch_or_finally_mapping_implemented=False,
        original_game_code_executed=False, actual_unwinding_executed=False, full_clean_decompile_ready=False,
        scope='New original infrastructure and concrete integration design only. Synthetic structural model tests and the separate actual existing-Core graph probe do not recover original handlers, validate operand types or prove game exception behavior.')
    base = ROOT / 'reports/exception-region-design-v36'
    destination(ROOT, base.with_suffix('.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    lines = ['# Exception region design foundation', '', report['status'], '',
             f"{tests.testsRun} structural model tests; {cfg['checks']} actual existing-Core graph checks; {report['evidence_failures']} design-evidence failures.", '',
             'The standalone immutable model keeps normal leave continuation, finally invocation and exceptional entry separate. Handler-only roots remain retained without ordinary predecessor edges. It accepts explicitly synthetic single-finally void plans and always reports production readiness false.', '',
             'Actual v35 Core evidence confirms that entry-only enumeration/pruning loses disconnected handler-shaped blocks. Building a CFG from a shallow list copy mutates shared branch instructions; remapping cloned fixture branch identities preserves the original. The probe does not establish general mutable-operand cloning.', '',
             'Required integration contracts:', '']
    lines += [f"- **{row['stage']}:** {row['proposed']}" for row in interfaces]
    lines += ['', 'Original behavior still unresolved:', ''] + ['- ' + text for text in unresolved]
    lines += ['', 'Future behavior/serialization gates are proposed, not run:', '']
    lines += [f"- **{row['group']}:** " + '; '.join(row['cases']) + '.' for row in future]
    lines += ['', 'Inspected upstream locations:', '']
    lines += [f"- `{row['path']}:{row['line']}`: {row['current_behavior']}" for row in source_rows]
    lines += ['', 'Primary references:', '']
    lines += [f"- [{row['claim']}]({row['url']})" for row in report['primary_references']]
    lines += ['', 'No Core edits/builds, original game execution, native unwinding or EH emission occurred. The complete decompile remains incomplete.', '']
    destination(ROOT, base.with_suffix('.md')).write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'synthetic_model_tests', 'evidence_checks', 'evidence_failures', 'current_core_boundary_checks', 'production_eh_ready')}))
    if report['evidence_failures']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
