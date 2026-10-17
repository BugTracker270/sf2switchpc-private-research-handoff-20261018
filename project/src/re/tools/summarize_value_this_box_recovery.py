"""Record exact body selection/boxing evidence and unresolved recovered bodies."""
import argparse
import datetime
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]
RUN='nso-value-this-box-v30'

def read(name):
 p=ROOT/name
 return json.loads(p.read_text(encoding='utf-8-sig')) if p.exists() else {}

def brief(name):
 r=read(name)
 return dict(report=name,**{k:v for k,v in r.items() if v is None or isinstance(v,(str,int,float,bool))}) if r else dict(report=name,status='NOT_STARTED')

def compiler(run):
 r=read(f'reports/recovered-source-profile-legacy-reference-check-{run}.json')
 return [{k:a.get(k) for k in ['assembly','build_exit_code','unique_compiler_diagnostic_lines']} for a in r.get('assemblies',[])]

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--active-session',action='append',default=[])
 args=parser.parse_args()
 paths={
  'pointer_observations':'reports/value-this-pointer-observations.json',
  'body_selection':'reports/value-this-thunks-v30.json',
  'native_adjustor_equivalence':'reports/integer-aggregate-adjustor-native-proof.json',
  'native_boxing':'reports/native-scalar-boxing-v30.json',
  'boxing_ir':'reports/scalar-boxing-validation-v30.json',
  'liveness_before':'reports/addressed-storage-liveness-before-v30.json',
  'liveness_after':'reports/addressed-storage-liveness-after-v30.json',
  'recovered_boxing':f'reports/recovered-primitive-box-{RUN}.json',
  'recovered_value_this':f'reports/recovered-value-this-{RUN}.json'}
 evidence={k:brief(v) for k,v in paths.items()}
 required=['body_selection','native_adjustor_equivalence','native_boxing','boxing_ir','liveness_after','recovered_boxing']
 stack=read(f'reports/cil-stack-audit-{RUN}.json')
 audit=read(f'analysis/il2cpp/cil-audit-{RUN}/summary.json')
 syntax_ok=len(audit.get('assemblies',[]))==44 and not any(a.get('malformed_il',1) for a in audit.get('assemblies',[]))
 valid=all(evidence[k].get('status','').startswith('PASS') for k in required) and syntax_ok and stack.get('status')=='PASS_STACK_DEPTH_AND_HEADERS_ONLY'
 body=read(paths['recovered_value_this'])
 result=dict(status='SCOPED_BODY_SELECTION_AND_BOXING_VALIDATED_RUNTIME_GUARDS_UNRESOLVED' if valid else 'IN_PROGRESS',
  updated=datetime.datetime.now(datetime.timezone.utc).isoformat(),recovery_run=RUN,
  compiler_before=compiler('nso-native-leaves-v29'),compiler_after=compiler(RUN),evidence=evidence,
  recovered_value_this_blocked_calls=len(body.get('blocked_calls',[])),
  cil_assemblies_audited=len(audit.get('assemblies',[])),stack_status=stack.get('status','NOT_STARTED'),
  syntax_valid=syntax_ok,active_sessions=args.active_session,whole_game_source_ready=False,
  changes=['Select exact unboxed native FDE bodies for 287 unique value-this adjustors, keeping registered pointers and rejecting four ambiguous wrappers.',
   'Recognize the reviewed boxing helper only for concrete eligible primitive types with initialized typed storage and no original static constructor.',
   'Retain original initializing copies when addresses, array elements or array length operands read their storage; preserve storage identity.'],
  limits='Native boxing uses explicit GC-allocation/imported-memcpy boundaries. The CLR boxing expression validates one actual Int32 caller and its original input provenance; it does not certify all boxing callers or full method behavior. '
   'Value-this body selection and native boxed/unboxed equivalence do not certify recovered method execution: InternalDecrypt still has eight reachable runtime metadata/class-initialization diagnostics and its actual CIL probe runs zero cases. '
   'No fields are reinterpreted by an assumed header subtraction, no method body is filled with a default to pass tests, and full clean source remains incomplete. Compiler counts include cascades and are not completion percentages.')
 destination(ROOT,ROOT/'reports/value-this-box-source-recovery-v30.json').write_text(json.dumps(result,indent=2)+'\n')
 lines=['# Value-this bodies, primitive boxing and addressed storage','',result['status'],'',
  'Full clean decompilation remains incomplete. Actual recovered InternalDecrypt is still blocked by runtime initialization diagnostics.','',
  '| Source check | Firstpass diagnostic lines | Main diagnostic lines |','|---|---:|---:|']
 for label,rows in [('v29',result['compiler_before']),('v30',result['compiler_after'])]:
  counts={a['assembly']:a['unique_compiler_diagnostic_lines'] for a in rows}
  lines.append(f"| {label} | {counts.get('Assembly-CSharp-firstpass','pending')} | {counts.get('Assembly-CSharp','pending')} |")
 lines+=['','Corrections:','']+['- '+s for s in result['changes']]+['','Evidence:','']
 for key,item in evidence.items():lines.append(f"- [{key.replace('_',' ')}]({Path(item['report']).name}): {item.get('status','NOT_STARTED')}; {item.get('checks','not a numeric scope')} checks.")
 lines+=['',result['limits'],'']
 destination(ROOT,ROOT/'reports/value-this-box-source-recovery-v30.md').write_text('\n'.join(lines))
 state=read('analysis/continuation-state.json')
 state.setdefault('active_v30',{}).update(status=result['status'],run=RUN,sessions=args.active_session,
  report='reports/value-this-box-source-recovery-v30.json',compiler=result['compiler_after'],whole_game_source_ready=False)
 destination(ROOT,ROOT/'analysis/continuation-state.json').write_text(json.dumps(state,indent=2)+'\n')
 print(json.dumps({k:result[k] for k in ['status','compiler_after','recovered_value_this_blocked_calls','active_sessions']}))

if __name__=='__main__':main()
