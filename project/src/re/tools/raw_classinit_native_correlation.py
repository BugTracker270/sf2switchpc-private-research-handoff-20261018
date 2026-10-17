"""Correlate actual stage snapshots with original exact-FDE class-init call sites."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import capstone

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'src/tools'))
from usb_boundary import destination


def main():
    if len(sys.argv)>2 or len(sys.argv)==2 and sys.argv[1] not in ('--after','--v33','--v34'):raise ValueError('Optional --after/--v33/--v34 only')
    after=len(sys.argv)==2
    suffix=('v34' if sys.argv[1]=='--v34' else 'v33' if sys.argv[1]=='--v33' else 'v32-after') if after else 'v32'
    survey_path=ROOT/f'reports/raw-classinit-stage-survey-{suffix}.json'
    survey=json.loads(survey_path.read_text(encoding='utf-8'))
    if survey['known_helper']!='0xB2E720' or survey['managed_aliases_at_helper']:
        raise ValueError('Known native-helper identity differs')
    raw_path=ROOT/'analysis/nso/main-uncompressed.nso';raw=raw_path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!='bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original uncompressed NSO differs')
    wanted={int(row['rva'],16):row for row in survey['methods']}
    frames={}
    with (ROOT/'analysis/nso/unwind-inventory-v1/frames.jsonl').open() as stream:
        for line in stream:
            row=json.loads(line)
            if row['rva'] in wanted:
                if row['rva'] in frames:raise ValueError('Ambiguous native frame')
                frames[row['rva']]=row
    if set(frames)!=set(wanted):raise ValueError('Missing exact native frame')
    cs=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
    results=[]
    for rva,method in wanted.items():
        frame=frames[rva];body=raw[0x100+rva:0x100+frame['end_rva']]
        ins=list(cs.disasm(body,rva));calls=[]
        for index,instruction in enumerate(ins):
            if instruction.mnemonic=='bl' and instruction.op_str=='#0xb2e720':
                first=max(0,index-8);last=min(len(ins),index+5)
                window=body[ins[first].address-rva:ins[last-1].address-rva+4]
                calls.append(dict(rva=hex(instruction.address),target='0xB2E720',window_sha256=hashlib.sha256(window).hexdigest(),
                    preceding_opcodes=[i.mnemonic for i in ins[first:index]],following_opcodes=[i.mnemonic for i in ins[index+1:last]]))
        raw_calls=method['raw_native_class_init_calls']
        results.append(dict(method=method['method'],rva=method['rva'],exact_frame=frame,body_sha256=hashlib.sha256(body).hexdigest(),
            original_native_class_init_calls=len(calls),surviving_raw_isil_calls=raw_calls,
            original_calls_already_absent_before_metadata_resolution=len(calls)-raw_calls,native_call_sites=calls,
            captured_raw_calls=[dict(index=b['index'],raw_opcode=b['opcode'],raw_operands=b['operand_count'],unused_return=b['return_source_uses']==0,
                first_register=b['raw_argument_registers'][0],all_physical_registers=b['raw_argument_registers'],
                deep_operand_reads=b.get('return_deep_operand_reads'),resolved_origin=a['argument_origin'],after_fixpoint_target=a['target'],after_fixpoint_target_kind=a['target_kind'])
                for b,a in zip(method['before_metadata'],method['after_type_fixpoint'])]))
    if after:
        for method in survey['methods']:
            for call in method['after_type_fixpoint']:
                if not (call['target_kind']=='Immediate' and call['target']=='11724576'
                        or call['target'].endswith('RuntimeHelpers::RunClassConstructor') and call['opcode']=='CallVoid'):
                    raise ValueError('Known native initializer was resolved to an unrelated managed method')
    scheduling_gate=None
    if suffix in ('v33','v34'):
        reader=next(m for m in survey['methods'] if m['method']=='BinaryReaderNekki::ReadBoolean')
        unload=next(m for m in survey['methods'] if m['method']=='BundlesUtil::UnloadDependencies')
        if any(m['addend'] in (0x122,0xD4) for m in reader['remaining_runtime_class_memory_operands']):
            raise ValueError('Proven folded reader class guard still reads raw class flags')
        call=reader['after_type_fixpoint'][0]
        before=[f for f in reader['resolved_field_operands'] if f['opcode']=='Move' and f['index']<call['index']]
        if not any(f['field']=='<Position>k__BackingField' for f in before) or not any(f['field']=='_bytes' for f in before):
            raise ValueError('Scheduled original reader input field loads were lost')
        scheduling_gate=dict(status='PASS_ORIGINAL_SCHEDULED_FIELD_LOADS_PRESERVED_AND_RAW_GUARDS_REMOVED',
            reader_original_input_field_loads_before_class_request=[f['field'] for f in before],
            proven_callers_without_raw_class_flags=[reader['method']],
            unload_remaining_raw_class_flags=[m for m in unload['remaining_runtime_class_memory_operands'] if m['addend'] in (0x122,0xD4)],
            unload_limit='Normal path4A8478 branches directly to cold finished check4A84E0, entering the separately recognized sequential cold guard4A84D8 after its start. ReadBoolean scheduling correction does not fold this alternate-entry CFG shape; raw flags remain explicit.',
            scope='Actual production ISIL through the unchanged type fixpoint only. Original scheduled reader input field reads remain before the recovered class-constructor request and reader raw flag loads disappear. UnloadDependencies alternate-entry cold flags remain unresolved. Emitted source and whole-caller runtime remain separate gates.')
    phi_gate=None
    if suffix=='v34':
        proof_path=ROOT/'reports/class-metadata-phi-production-v34.json'
        proof=json.loads(proof_path.read_text())
        if proof['status']!='PASS_PRODUCTION_EDGE_AWARE_CLASS_METADATA_PHI_LOWERING' or proof['core_sha256']!=survey['core_sha256'] or not proof['production_lowering']:
            raise ValueError('Current production Phi proof gate is missing or differs')
        safe=next(m for m in survey['methods'] if m['method']=='BundlesUtil::GetAssetBundleSafe')
        if len(safe['after_type_fixpoint'])!=3 or any(c['opcode']!='CallVoid' or not c['target'].endswith('RuntimeHelpers::RunClassConstructor') for c in safe['after_type_fixpoint']):
            raise ValueError('The three original safe-bundle class requests did not all lower exactly')
        if proof['remaining_runtime_class_flag_loads']!=4 or len(proof['original_post_cctor_reload_indices'])!=3:
            raise ValueError('Original unresolved flags or required post-cctor reload chain changed')
        phi_gate=dict(status='PASS_EXACT_CLASS_PHI_LOWERING_WITH_POST_CCTOR_RELOADS_RETAINED',
            proof_sha256=hashlib.sha256(proof_path.read_bytes()).hexdigest(),
            get_safe_original_requests=3,get_safe_managed_requests=3,get_safe_raw_requests=0,
            get_safe_remaining_raw_class_flag_loads=4,
            scope='The exact metadata-origin Phi proof removes one raw helper request only. Original raw class flag checks and post-constructor field reloads remain; no broader CFG recovery or complete caller/runtime claim.')
    report=dict(status='READ_ONLY_CONFIRMED_RAW_CLASS_INIT_ABI_AND_FALSE_METHODINFO_RESOLUTION',
        survey_sha256=hashlib.sha256(survey_path.read_bytes()).hexdigest(),original_native_sha256=hashlib.sha256(raw).hexdigest(),methods=results,
        concrete_findings=[
            'All four surviving helper calls use exact unknown-callee ARM64 layout: target, unused result, X0-X7,V0-V7. Three have a unique Move root naming exact type metadata after the type fixpoint; one GetAssetBundleSafe class value is a Phi and remains outside the existing provenance rule.',
            'UnloadDependencies native class-init target is B2E720 with no managed aliases. ResolveCallsViaMethodInfo nevertheless changes its surviving raw helper call into List<AssetBundle>.Enumerator.Dispose using a stale MethodInfo operand. The X0 operand still represents the BundlesUtil class, not an enumerator receiver.',
            'Exact FDE inventory shows additional original class-init calls are already absent before metadata resolution. Correcting only the raw-call lowering cannot restore those effects; the old native class-macro removal also requires semantic replacement.'
        ],
        proposed_scope=[
            'Exclude the exact known opt-in legacy class-init helper from MethodInfo fallback resolution, preserving unknowns.',
            'Allow raw Call/CallVoid only when HasRawArgumentLayout proves X0-X7,V0-V7 and any result is a genuine unused local. Retain existing exact void-one-argument path.',
            'Keep the unique dominating exact metadata-origin class proof; reject Phi/unknown/dynamic origins, used returns, and mismatched or extra nonphysical semantic arguments.',
            'Emit CallVoid to the unique mscorlib RunClassConstructor(RuntimeTypeHandle) overload; discard only unused physical-register capture and return slot, never a semantic effect.',
            'Replace separately proven native class-init guard macros with semantic calls inside exact registered FDEs, preserving unrelated instructions; do not leave the old no-op path enabled for these accepted sites.'
        ],
        core_source_edited=False,scope='Read-only native instruction/call-site and production-stage observations. No emitted CIL, source changes, class-initializer execution, compilation success or whole-game behavior is certified by this report.')
    if after:
        report['status']='PASS_ACTUAL_CLASS_INIT_TARGETS_WITHOUT_FALSE_METHODINFO_ALIAS'
        report.pop('proposed_scope')
        report['implemented_scope']=[
            'The exact known legacy class-init helper is excluded from MethodInfo fallback; an unrelated stale MethodInfo cannot select Dispose or another managed method.',
            'Only exact Call18 raw X0-X7,V0-V7 captures with one unique unused X0 result may lower through the existing dominating exact class-metadata-origin proof. Raw CallVoid17 is rejected; the previously supported semantic CallVoid(class) path is retained.',
            'The original native request count is correlated to surviving IR requests in each selected caller. Proven requests lower to the existing void RunClassConstructor(RuntimeTypeHandle) contract; ambiguous Phi origins stay raw diagnostics.'
        ]
        report['concrete_findings']=['After approved implementation: all surviving class-init targets are either the exact managed void RunClassConstructor contract or remain the original raw helper; no stale MethodInfo selects an unrelated method. Detailed source/ABI/origin and native request counts remain observations, not whole-game semantics.']
        report['recovered_managed_requests']=sum(c['target'].endswith('RuntimeHelpers::RunClassConstructor') for m in survey['methods'] for c in m['after_type_fixpoint'])
        report['remaining_raw_requests']=sum(c['target_kind']=='Immediate' for m in survey['methods'] for c in m['after_type_fixpoint'])
        if scheduling_gate:report['scheduling_gate']=scheduling_gate
        if phi_gate:report['class_phi_gate']=phi_gate
    destination(ROOT,ROOT/f'reports/raw-classinit-native-correlation-{suffix}.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=report['status'],methods=[dict(method=r['method'],native=r['original_native_class_init_calls'],raw=r['surviving_raw_isil_calls'],already_absent=r['original_calls_already_absent_before_metadata_resolution']) for r in results])))


if __name__=='__main__':main()
