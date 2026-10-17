"""Hash-verified source observations and bounded class-init recovery review."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import re
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'src/tools'))
from usb_boundary import destination
from v30_diagnostic_delta import read, source_data

RUNS=('nso-value-this-box-v30','nso-static-getter-v31b')
MESSAGE="Cannot convert type 'System.Type' to 'nint'"


def inspect(run,assembly):
    all_rows=read(run,assembly)
    rows=[r for r in all_rows if r['code']=='CS0030' and r['message']==MESSAGE]
    texts,facts,_,gate=source_data(run,assembly,rows)
    counts=Counter(); helpers=Counter(); samples=[]
    for row in rows:
        lines=texts[row['file']]; index=row['line']-1
        # A small following window is a source correlation only. It is not a
        # general method parser or proof that all reported casts have one cause.
        end=min(index+19,len(lines))
        for i in range(index+1,end):
            if lines[i]=='\t}':end=i;break
        nearby='\n'.join(lines[index:end])
        if re.search(r'Il2CppClass<[^\n]+\+122\]',nearby) or re.search(r'Il2CppClass<[^\n]+\+D4\]',nearby):
            category='near_unrecovered_class_guard_122_or_D4'
        elif re.search(r'Il2CppClass<[^\n]+\+B8\]',nearby):
            category='near_runtime_class_static_storage_B8'
        else:category='other_type_pointer_use'
        counts[category]+=1
        if 'Method not found @B2E720' in nearby:helpers[category]+=1
        if len(samples)<12 or row['file'] in ('BinaryReaderNekki.cs','BundlesUtil.cs'):
            samples.append(dict(file=row['file'],line=row['line'],category=category,
                unresolved_known_class_helper_in_window='Method not found @B2E720' in nearby,
                source_sha256=facts[row['file']]['sha256']))
    return dict(canonical_all_errors=len(all_rows),canonical_type_to_nint_errors=len(rows),
        correlation_categories=dict(counts),unresolved_known_helper_nearby=dict(helpers),
        source_integrity=gate,samples=samples)


def main():
    assemblies={}
    for assembly in ('Assembly-CSharp-firstpass','Assembly-CSharp'):
        old,new=(inspect(run,assembly) for run in RUNS)
        assemblies[assembly]=dict(before=old,after=new,
            type_to_nint_delta=new['canonical_type_to_nint_errors']-old['canonical_type_to_nint_errors'])
    survey_path=ROOT/'reports/raw-classinit-stage-survey-v32-after.json'
    survey=json.loads(survey_path.read_text())
    current=next(m for m in survey['methods'] if m['method']=='BinaryReaderNekki::ReadBoolean')
    if len(current['after_type_fixpoint'])!=1 or current['after_type_fixpoint'][0]['target']!='System.Runtime.CompilerServices.RuntimeHelpers::RunClassConstructor':
        raise ValueError('ReadBoolean typed class-init request is not recovered')
    snapshot=ROOT/'analysis/il2cpp/raw-classinit-BinaryReaderNekki-ReadBoolean-after-type-v32-after.txt'
    ir=snapshot.read_text()
    if '+122]' not in ir or '+D4]' not in ir:raise ValueError('Expected residual class guard changed')
    raw=(ROOT/'analysis/nso/main-uncompressed.nso').read_bytes()
    if hashlib.sha256(raw).hexdigest()!='bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Native binary differs')
    # Original native window: exact class load, scheduled independent W21 load,
    # has_cctor/cctor_finished checks, known class initializer and join.
    window=raw[0x100+0xf0d3d4:0x100+0xf0d3f0]
    report=dict(status='READ_ONLY_TYPE_POINTER_DIAGNOSTIC_ROOT_AND_BOUNDED_PROPOSAL',
        source_modified=False,core_modified=False,whole_game_source_ready=False,
        before=RUNS[0],after=RUNS[1],assemblies=assemblies,
        actual_post_fix_observation=dict(method='BinaryReaderNekki::ReadBoolean',rva='0xF0D390',exact_fde_bytes=148,
            native_class_load='0xF0D3D4: LDR X0,[X8]',scheduled_load='0xF0D3D8: LDR W21,[X19,#0x14]',
            guard_start='0xF0D3DC',known_call='0xF0D3EC -> 0xB2E720',join='0xF0D3F0',
            native_window_sha256=hashlib.sha256(window).hexdigest(),
            post_fix_ir_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
            helper_call_lowered=True,raw_guard_memory_loads_still_present=['0x122','0xD4'],
            survey_sha256=hashlib.sha256(survey_path.read_bytes()).hexdigest(),core_sha256=survey['core_sha256']),
        precise_root=dict(file='refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64AllocationPattern.cs',method='FindClassLoad',
            issue='The backward class-load witness accepts ordinary 64-bit loads, selected FP loads and stack-zero/ADRP scheduling, but rejects the intervening unsigned-offset 32-bit LDR W21. Therefore the exact ordinary has_cctor/cctor_finished macro is not semantically folded. Its remaining raw Il2CppClass memory checks require an invalid System.Type-to-native-pointer conversion even after the raw helper itself now lowers correctly.',
            related_integration='NewArmV8InstructionSet.GetIsilFromMethod ordinary exact-FDE class-macro path'),
        bounded_proposal=[
            'Within the existing 16-byte backward witness only, admit the exact unsigned-offset 32-bit LDR form when its destination is not W0. Preserve this scheduled instruction and continue requiring the exact X0 class-slot load, has_cctor/cctor_finished offsets/branches, independently identified target and original FDE bounds.',
            'Emit the existing semantic class-init call plus jump only at the native guard start. Do not remove the scheduled W21 field read or replace class initialization with a no-op.',
            'Add original ReadBoolean acceptance and changed W0/writeback/extra-effect negative fixtures. Require post-fix original typed field-read and managed-call provenance, disappearance of both raw guard offsets, and unchanged known runtime initialization semantics.'
        ],
        review=[
            'The approved raw-call correction preserves exact target identity, verifies all 16 physical argument registers, checks one unused unique X0 result through all source/store-address operands, and requires a unique dominating exact represented-type metadata origin.',
            'The known-helper MethodInfo exclusion fixes an actual stale Enumerator.Dispose resolution without inventing a managed alias; ambiguous origins remain diagnostic.',
            'Current source observations include class-storage B8 and other type-pointer uses. They are not all class-initializer bugs, and this proposed guard fix cannot be assumed to remove every System.Type-to-nint diagnostic.',
            'Expected compiler impact is conditional: the raw-call correction removes unresolved helper calls and false aliases, while residual raw guard memory operations can keep the invalid pointer cast. Only a fresh unchanged source export/compiler run can establish the actual diagnostic delta.'
        ],
        limits='Read-only source/native/ISIL review. Correlation windows are categorized observations, not independent root causes. No v32 recovered DLL, whole-source build, whole-caller execution or gameplay claim is made by this report.')
    destination(ROOT,ROOT/'reports/raw-classinit-source-impact-v32.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(status=report['status'],assemblies={a:dict(before=v['before']['canonical_type_to_nint_errors'],after=v['after']['canonical_type_to_nint_errors'],delta=v['type_to_nint_delta'],categories=v['after']['correlation_categories']) for a,v in assemblies.items()})))


if __name__=='__main__':main()
