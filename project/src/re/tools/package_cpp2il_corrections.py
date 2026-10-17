"""Save one reproducible MIT tool patch against the pinned upstream commit."""
import difflib
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]
PIN='b5ad444b82267cb1e4b88b8b373c008105bdea52'
FILES=['Cpp2IL.Core/Utils/Arm64CallingConventionResolver.cs','Cpp2IL.Core/Utils/BaseCallingConventionResolver.cs',
    'Cpp2IL.Core/Analysis/MetadataAddressResolver.cs','Cpp2IL.Core/Analysis/MetadataResolver.cs',
    'Cpp2IL.Core/Analysis/InterfaceDispatchRecovery.cs',
    'Cpp2IL.Core/Utils/LegacyArm64AllocationPattern.cs','Cpp2IL.Core/Il2CppApiFunctions/NewArm64KeyFunctionAddresses.cs',
    'Cpp2IL.Core/Utils/LegacyArm64InitializationPattern.cs','Cpp2IL.Core/InstructionSets/NewArmV8InstructionSet.cs',
    'Cpp2IL.Core/Utils/LegacyArm64ExceptionRaiserPattern.cs','Cpp2IL.Core/Utils/LegacyArm64ThunkScanner.cs',
    'Cpp2IL.Core/Analysis/ThrowHelperRecovery.cs','Cpp2IL.Core/Utils/LegacyArm64ArrayAllocationPattern.cs',
    'Cpp2IL.Core/Analysis/LocalVariables.cs','Cpp2IL.Core/Utils/LegacyArm64ExceptionFactoryPattern.cs','Cpp2IL.Core/IlGenerator.cs',
    'Cpp2IL.Core/UninitializedObjectAllocation.cs','Cpp2IL.Core/ProcessingLayers/AttributeInjectorProcessingLayer.cs',
    'Cpp2IL.Core/Utils/LegacyArm64DefaultMemberPattern.cs','Cpp2IL.Core/Analysis/LegacyDefaultMemberRecovery.cs']

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',default='nso-allocation-identity-v13')
    parser.add_argument('--harness-log',default='logs/cpp2il-allocation-identity-v13-tests.log');args=parser.parse_args()
    if not re.fullmatch('[a-z0-9-]+',args.run):raise ValueError('Invalid recovery run')
    repo=ROOT/'refs/Cpp2IL';patch=[];files=[]
    actual=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    if actual!=PIN:raise ValueError('Unexpected upstream checkout')
    run=args.run
    harness=json.loads(destination(ROOT,ROOT/args.harness_log).read_text(encoding='utf-8-sig'))
    recovery=json.loads((ROOT/f'logs/cpp2il-{run}-result.json').read_text(encoding='utf-8-sig'))
    audit=json.loads((ROOT/f'analysis/il2cpp/cil-audit-{run}/summary.json').read_text(encoding='utf-8-sig'))
    exception=json.loads((ROOT/'reports/native-exception-boundary.json').read_text(encoding='utf-8-sig'))
    array=json.loads((ROOT/'reports/native-array-boundary.json').read_text(encoding='utf-8-sig'))
    stack=json.loads((ROOT/f'reports/cil-stack-audit-{run}.json').read_text(encoding='utf-8-sig'))
    identity=json.loads((ROOT/f'reports/recovered-allocation-identity-{run}.json').read_text(encoding='utf-8-sig'))
    empty_ctor_path=ROOT/f'reports/recovered-empty-object-ctor-{run}.json'
    empty_ctor=json.loads(empty_ctor_path.read_text(encoding='utf-8-sig')) if empty_ctor_path.exists() else {}
    if harness['failed'] or recovery['exit_code'] or any(row['malformed_il'] for row in audit['assemblies']):raise ValueError('Do not publish a patch without successful scope checks/recovery/audit')
    if stack['status']!='PASS_STACK_DEPTH_AND_HEADERS_ONLY':raise ValueError('Stack-depth/header gate failed; preserve diagnostic output')
    if identity['status']!='PASS_STATIC_ALLOCATION_IDENTITY_ONLY':raise ValueError('Allocation identity repair is not independently demonstrated')
    if harness['passed']>=158 and empty_ctor.get('status')!='PASS_SCOPED_PROVEN_NOOP_CTOR_REMOVAL':raise ValueError('New empty-constructor lowering requires its independent witness')
    member_path=ROOT/f'reports/recovered-default-member-{run}.json'
    member=json.loads(member_path.read_text(encoding='utf-8-sig')) if member_path.exists() else {}
    if harness['passed']>=192 and member.get('status')!='PASS_NATIVE_ARGUMENT_METADATA_AND_INDEXER_SOURCE_CORRELATION':raise ValueError('DefaultMember restoration requires native/metadata/source correlation')
    class_path=ROOT/f'reports/recovered-class-guards-{run}.json'
    class_guards=json.loads(class_path.read_text(encoding='utf-8-sig')) if class_path.exists() else {}
    if harness['passed']>=211 and class_guards.get('status')!='PASS_SCOPED_NATIVE_CLASS_GUARD_CIL_SOURCE_CORRELATION':raise ValueError('Expanded class guards require actual native/CIL/source correlation')
    boolean_path=ROOT/f'reports/recovered-boolean-setter-{run}.json'
    boolean=json.loads(boolean_path.read_text(encoding='utf-8-sig')) if boolean_path.exists() else {}
    if 'DestinationType(operand) == context.AppContext.SystemTypes.SystemBooleanType' in (repo/'Cpp2IL.Core/IlGenerator.cs').read_text(encoding='utf-8'):
        if boolean.get('status')!='PASS_RECOVERED_BOOLEAN_DECISIONS_VS_ORIGINAL_NATIVE':raise ValueError('Forwarded boolean lowering requires actual recovered/native decision comparisons')
    for name in FILES:
        result=subprocess.run(['git','-C',str(repo),'show',f'{PIN}:{name}'],capture_output=True)
        before=result.stdout.decode('utf-8') if result.returncode==0 else ''
        if result.returncode and name not in ['Cpp2IL.Core/Analysis/MetadataAddressResolver.cs','Cpp2IL.Core/Utils/LegacyArm64AllocationPattern.cs','Cpp2IL.Core/Utils/LegacyArm64InitializationPattern.cs','Cpp2IL.Core/Utils/LegacyArm64ExceptionRaiserPattern.cs','Cpp2IL.Core/Utils/LegacyArm64ThunkScanner.cs','Cpp2IL.Core/Utils/LegacyArm64ArrayAllocationPattern.cs','Cpp2IL.Core/Utils/LegacyArm64ExceptionFactoryPattern.cs','Cpp2IL.Core/UninitializedObjectAllocation.cs','Cpp2IL.Core/Utils/LegacyArm64DefaultMemberPattern.cs','Cpp2IL.Core/Analysis/LegacyDefaultMemberRecovery.cs']:raise ValueError('Upstream source missing')
        after=(repo/name).read_text(encoding='utf-8')
        patch.append(f'diff --git a/{name} b/{name}\n')
        if not before:patch.append('new file mode 100644\n')
        patch.extend(difflib.unified_diff(before.splitlines(keepends=True),after.splitlines(keepends=True),
            fromfile='a/'+name if before else '/dev/null',tofile='b/'+name))
        files.append(dict(path=name,sha256=hashlib.sha256((repo/name).read_bytes()).hexdigest()))
    output=destination(ROOT,ROOT/'src/re/tool-patches/cpp2il-sf2-recovery-corrections.patch')
    output.write_text(''.join(patch),encoding='utf-8',newline='\n')
    report=dict(upstream='https://github.com/SamboyCoding/Cpp2IL',commit=PIN,license='MIT',
        patch=str(output.relative_to(ROOT)),sha256=hashlib.sha256(output.read_bytes()).hexdigest(),files=files,recovery_run=run,processing_options=recovery.get('processors',[]),harness_passed=harness['passed'],
        default_member_recovery=member,
        class_guard_recovery=class_guards,
        forwarded_boolean_recovery=boolean,
        usage='Apply this complete patch once to the pinned checkout. Supersedes the earlier incremental ABI/metadata patches; do not apply both sets.',
        validation=f"{harness['passed']} address/slot/runtime-pattern/streaming-thunk/allocation-emission checks, {exception['checks']} original exception-pointer checks at supplied C++ boundaries, and {array['checks']} original array checks at explicit runtime boundaries. Fresh {run} recovery exits zero; syntax and stack-depth/header audits pass. Separate reference allocation preserves one independently witnessed static-field runtime identity without invoking an extra instance constructor. Empty Object constructor removal requires its native immediate-return witness and applies only outside managed instance constructors. Source marker view is explicitly partial and retains a separate tool-annotated output. Other original attributes, including serialization-relevant attributes, are omitted in this diagnostic view and remain a required recovery task. Stack-invalid or unresolved-allocation bodies remain diagnostic throw stubs. Remaining type/ABI/source-build and initialization limitations, plus earlier failure logs, are retained. Complete clean decompilation remains unproven.")
    destination(ROOT,ROOT/'reports/cpp2il-corrections-lock.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
