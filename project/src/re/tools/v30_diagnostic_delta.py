"""Read-only canonical compiler delta; source bytes remain unchanged."""
from collections import Counter
from pathlib import Path
import hashlib, json, re, sys
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'src/tools'))
from usb_boundary import destination
RUNS = ['nso-native-leaves-v29','nso-value-this-box-v30']
ERROR = re.compile(r'^(.*?)\((\d+),(\d+)\): error (CS\d+): (.*?)(?: \[.*\])?$')

def read(run, assembly):
    summary = json.loads((ROOT/f'reports/recovered-source-profile-legacy-reference-check-{run}.json').read_text(encoding='utf-8-sig'))
    expected = next(a['unique_compiler_diagnostic_lines'] for a in summary['assemblies'] if a['assembly']==assembly)
    log = ROOT/f'logs/source-profile-legacy-reference-build-{run}-{assembly}.log'
    seen = set(); rows = []
    with log.open(encoding='utf-8-sig',errors='replace') as stream:
        for line in stream:
            match = ERROR.match(line.rstrip())
            if not match: continue
            key = (match[1].strip().casefold(),int(match[2]),int(match[3]),match[4],match[5].strip())
            if key in seen: continue
            seen.add(key)
            path = Path(match[1].strip())
            if not path.is_absolute(): raise ValueError('Nonabsolute diagnostic path')
            root = ROOT/'analysis/il2cpp'/f'source-profile-project-build-{run}'/assembly
            relative = path.relative_to(root).as_posix()
            rows.append(dict(file=relative,line=int(match[2]),column=int(match[3]),code=match[4],message=match[5].strip()))
    if len(rows)!=expected: raise ValueError((run,assembly,len(rows),expected))
    return rows

def source_data(run, assembly, rows):
    manifest_path=ROOT/f'reports/recovered-source-profile-project-build-{run}.json'
    manifest=json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    export=next(a for a in manifest['assemblies'] if a['assembly']==assembly)
    base=ROOT/'analysis/il2cpp'/f'source-profile-project-build-{run}'/assembly
    indexed={(ROOT/r['path']).relative_to(base).as_posix():r for r in export['source_files']}
    texts={}; fingerprints={}
    for file in set(r['file'] for r in rows):
        row=indexed[file];payload=(base/file).read_bytes();sha=hashlib.sha256(payload).hexdigest()
        if len(payload)!=row['bytes'] or sha!=row['sha256']: raise ValueError('Source manifest differs: '+file)
        texts[file]=payload.decode('utf-8-sig').splitlines()
        fingerprints[file]=dict(sha256=sha,bytes=len(payload),lines=len(texts[file]))
    categories=Counter()
    for row in rows:
        line=texts[row['file']][row['line']-1]
        if row['code']=='CS0030' and "Cannot convert type 'int' to '" in row['message'] and '.Enumerator' in row['message'] and re.search(r'=\s*\([^;]*\)\s*0\s*;',line):
            categories['int_zero_cast_to_enumerator']+=1
        elif row['code']=='CS0030' and re.search(r"Cannot convert type '(.+)' to '\1\*'",row['message']):
            categories['value_cast_to_pointer_of_same_type']+=1
        elif row['code']=='CS0030' and "Cannot convert type 'int' to '" in row['message'] and re.search(r'=\s*\([^;]*\)\s*0\s*;',line):
            categories['int_zero_cast_to_other_nonprimitive']+=1
    return texts,fingerprints,dict(categories),dict(manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),diagnostic_source_files_hash_verified=len(texts))

def main():
    result=dict(status='READ_ONLY_CANONICAL_COMPILER_DELTA',source_modified=False,assemblies={})
    for assembly in ['Assembly-CSharp-firstpass','Assembly-CSharp']:
        old,new=(read(r,assembly) for r in RUNS)
        oldtext,oldfacts,oldcategories,oldgate=source_data(RUNS[0],assembly,old)
        newtext,newfacts,newcategories,newgate=source_data(RUNS[1],assembly,new)
        a=Counter(r['code'] for r in old); b=Counter(r['code'] for r in new)
        af=Counter(r['file'] for r in old); bf=Counter(r['file'] for r in new)
        semantic=lambda rows:Counter((r['file'],r['code'],r['message']) for r in rows)
        sa,sb=semantic(old),semantic(new)
        added=sb-sa; removed=sa-sb
        files=[]
        for file in sorted(set(af)|set(bf),key=lambda f:bf[f]-af[f],reverse=True)[:20]:
            files.append(dict(file=file,old=af[file],new=bf[file],delta=bf[file]-af[file],
                old_source=oldfacts.get(file),new_source=newfacts.get(file),
                new_diagnostic_categories=[dict(code=k[1],message=k[2],count=n) for k,n in added.items() if k[0]==file][:12]))
        result['assemblies'][assembly]=dict(old_unique=len(old),new_unique=len(new),delta=len(new)-len(old),
            counts_match_authoritative_summary=True,error_code_delta={c:b[c]-a[c] for c in sorted(set(a)|set(b)) if b[c]!=a[c]},
            semantic_added_occurrences=sum(added.values()),semantic_removed_occurrences=sum(removed.values()),
            source_integrity={RUNS[0]:oldgate,RUNS[1]:newgate},
            source_operand_categories={RUNS[0]:oldcategories,RUNS[1]:newcategories},
            top_added_messages=[dict(code=k[0],message=k[1],count=n) for k,n in Counter({(code,message):sum(count for (f,c,m),count in added.items() if c==code and m==message) for _,code,message in added}).most_common(15)],
            top_growing_files=files,
            added_codes={c:sum(n for k,n in added.items() if k[1]==c) for c in sorted(set(b))},
            removed_codes={c:sum(n for k,n in removed.items() if k[1]==c) for c in sorted(set(a))})
    result['methodology']='Canonical identities include stripped casefolded absolute path, line, column, CS code and stripped message. Semantic changes additionally compare multisets of relative file, code and message to avoid line-shift inflation; local-name changes can still alter messages. Source operand-category counts inspect actual diagnostic lines independently in each run. Every diagnostic-bearing source file is hash/size checked against the unchanged export manifest.'
    result['interpretation']={
        'whole_game_source_ready':False,
        'dominant_growth':'CS0030 grows by 616 firstpass and 555 main. Newly retained integer-zero initializers for aggregate storage and newly resolved value-this bodies/calls expose invalid typed operands. More diagnostics do not prove improved semantics.',
        'aggregate_storage':{'representative':'Nekki.SF2.Core.Fights.Fight.SetStage(StageType.Stage)',
            'new_source_initializer_line':2386,'new_source_get_enumerator_line':2426,'new_source_move_next_line':2429,
            'observation':'v30 explicitly casts integer zero to List<Model>.Enumerator, stores GetEnumerator into another local, then calls MoveNext/Current/Dispose on the zero-backed local. v29 already used a separate default local instead of the GetEnumerator result. The preserved initializer is newly invalid code; the aggregate return/storage-alias defect predates v30. Native/CIL fixture validation is delegated and is not claimed by this source-only observation.',
            'classification':'NEWLY_EXPOSED_INVALID_INITIALIZER_WITH_PRE_EXISTING_UNRESOLVED_AGGREGATE_ABI'},
        'new_body':{'representative':'nn.hid.GestureState.ToString','old_diagnostics':2,'new_diagnostics':29,
            'registered_thunk':'0x78BB0','exact_unboxed_body':'0x782D0','exact_fde_bytes':2268,
            'observation':'v29 exports a short unresolved-call wrapper. v30 exports the real large body containing array/boxing/class-init/native-pointer limitations; these new body diagnostics must remain failures. Accepted route is documented by value-this-thunks-v30.json (287 accepted bodies).',
            'classification':'NEW_BODY_EXPOSURE_WITH_UNRESOLVED_OPERAND_TYPES'},
        'resolved_call_regression_risk':{'representative':'CodeStage.AntiCheat.ObscuredTypes.ObscuredDecimal.RandomizeCryptoKey',
            'observation':'The previously unresolved adjusted value-this call now resolves to InternalDecrypt, while the caller source retains a plus-16 address adjustment and a value-to-pointer conversion. This is an invalid call/receiver sequence requiring correction. It is not certified as benign expansion merely because the old helper call was also unresolved.',
            'classification':'NEWLY_RESOLVED_CALL_EXPOSES_INVALID_VALUE_THIS_RECEIVER'},
        'limits':'No Core code changed or built in this audit. No gameplay/runtime parity, complete classification of all diagnostics, or compile-success claim. Native/actual CIL proof of the selected aggregate fixture is handled separately; source observations alone do not establish the required fix.'}
    path=destination(ROOT,ROOT/'reports/v30-diagnostic-delta-analysis.json')
    path.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
if __name__=='__main__': main()
