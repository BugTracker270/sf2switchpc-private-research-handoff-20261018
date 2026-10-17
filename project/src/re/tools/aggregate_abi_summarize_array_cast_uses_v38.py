"""Conservative owner/type/count correlation of real array metadata casts."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(ROOT/'src/tools'))
from usb_boundary import destination
def path(relative):return destination(ROOT,ROOT/relative)
def sha(relative):return hashlib.sha256(path(relative).read_bytes()).hexdigest()
rows=json.loads(path('analysis/reconstruction/compiler-family-v38/array-cast-actual-ir-uses.json').read_text(encoding='utf-8-sig'))
assert sum(r['diagnostic_occurrences']for r in rows)==3355
aliases={'object':'System.Object','string':'System.String','byte':'System.Byte','sbyte':'System.SByte','bool':'System.Boolean','short':'System.Int16','ushort':'System.UInt16','int':'System.Int32','uint':'System.UInt32','long':'System.Int64','ulong':'System.UInt64','char':'System.Char','float':'System.Single','double':'System.Double'}
def normalize(name):
 base=name.split('[',1)[0]
 return aliases.get(base,base)+name[len(base):]
categories=Counter();group_counts=Counter();public=[]
for row in rows:
 expected=Counter({normalize(k):v for k,v in row['diagnostic_types'].items()})
 observed=Counter(row['genuine_array_types'])
 if row['status'].startswith('READ_ONLY') and row['all_casts_simple'] and expected==observed and row['genuine_runtime_class_projections']==row['diagnostic_occurrences']:
  category='REAL_X1_RUNTIME_ELEMENT_CLASS_PROJECTION_WITH_PHANTOM_CO_USE'if row['direct_array_phantom_captures'] else 'REAL_X1_RUNTIME_ELEMENT_CLASS_PROJECTION_NO_ARRAY_PHANTOM_CAPTURE'
 else:category='UNATTRIBUTED_DIAGNOSTIC_OCCURRENCES'
 categories[category]+=row['diagnostic_occurrences'];group_counts[category]+=1
 public.append(dict(assembly=row['assembly'],source=row['source'],declaration_line=row['declaration_line'],original_rva=row['registered_rva'],diagnostic_occurrences=row['diagnostic_occurrences'],classification=category,observed_original_helper_calls=row['helper_calls'],real_projection_definitions=row['genuine_runtime_class_projections'],direct_array_phantom_capture_uses=row['direct_array_phantom_captures'],source_type_histogram_matches=expected==observed,ir_mapping_status=row['status']))
genuine=sum(n for c,n in categories.items()if c.startswith('REAL_'))
report=dict(status='READ_ONLY_ARRAY_CAST_REAL_CLASS_PROJECTION_VS_CAPTURE_ATTRIBUTION',recovery_run='nso-virtual-companion-copy-v38',diagnostic_occurrences=3355,source_owner_groups=len(rows),categories=dict(categories),category_owner_groups=dict(group_counts),attributed_real_projection_occurrences=genuine,unattributed_occurrences=3355-genuine,proven_phantom_only_cast_occurrences=0,
 attribution_rule='Each attributed exported owner has a unique original metadata method candidate, exactly matching cast/type histogram and projection-definition count, simple array-to-nint source cast definitions, and actual emitter-input Memory[array+0] klass reads feeding the real IsInst X1 argument through exact+0x40 loads. Additional typed array captures at raw X2+ are recorded separately. No isolated cast is claimed to be caused solely by a phantom capture.',
 emitter_explanation='Current unknown numeric Call emits only its diagnostic, without loading any captured arguments. A genuine [array] klass projection is emitted as its array local into a RuntimeClass local lowered to IntPtr. The subsequent+0x40 target class read remains semantically needed by original X1, so ABI-only removal of X2+ does not recover or remove this real dynamic-class expression.',
 mapping_limits='Owner/type/count correlation, not a rewritten source-line-to-CIL debug map. Ambiguous source ownership/overload candidates, mismatched histograms/counts, incomplete graphs and other shapes remain unattributed; their actual exceptions are retained privately. Missing/ambiguous mappings deliberately throw inside the observation harness; two wording-only CommandNotFound errors at those rejection sites are also retained as unresolved, never counted as successful IR proof.',
 expected_v40_diagnostic_reduction='No promised reduction. Most attributed cast sites are real dynamic class projections. ABI identity/result typing is useful independent executable-dataflow correctness, while subsequent expression recovery requires a separate covariance/null/effect/exception-order proof.',
 groups=public,private_evidence='analysis/reconstruction/compiler-family-v38/array-cast-actual-ir-uses.json',private_evidence_sha256=sha('analysis/reconstruction/compiler-family-v38/array-cast-actual-ir-uses.json'),frozen_core_sha256='197403735d374bdde681ad203cdb3eb18e8cd9eef01897908a8c4f9e786ad99a',emitter_source_sha256=sha('analysis/il2cpp/virtual-companion-copy-v38-source-snapshot/refs/Cpp2IL/Cpp2IL.Core/IlGenerator.cs'),source_sha256=sha('src/re/tools/aggregate_abi_summarize_array_cast_uses_v38.py'),core_modified=False,core_built=False,original_game_or_native_functions_executed=0,full_clean_decompile_ready=False)
path('reports/array-cast-use-attribution-v38.json').write_text(json.dumps(report,indent=2)+'\n')
path('reports/array-cast-use-attribution-v38.md').write_text(f'# Array cast use attribution\n\nOf3,355 source cast diagnostics near Object::IsInst, conservative owner/type/count comparison attributes{genuine:,} to actual runtime array-class→element_class expressions feeding the real X1 argument;{3355-genuine:,} remain unattributed. No phantom-only cast attribution is proved.\n\nUnknown numeric calls do not load captured arguments in the current emitter. Removing raw X2+ captures therefore does not recover these genuine dynamic class expressions. Covariant runtime array identity, null behavior and original type-check-before-bounds ordering remain separate required proofs. The JSON distinguishes additional raw array captures from the real projection and retains all unresolved owner/shape cases. No source reduction, semantic lowering or whole-game readiness is claimed.\n')
print(json.dumps(dict(status=report['status'],categories=dict(categories),groups=dict(group_counts))))
