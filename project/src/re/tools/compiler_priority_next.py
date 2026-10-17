"""Stream compiler failures and correlate immutable exports with native helpers.

The report contains counts, hashes and metadata identities, never source dumps.
"""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'src/tools'))
from usb_boundary import destination

RUNS = ['nso-generic-ctor-v27', 'nso-native-leaves-v28', 'nso-native-leaves-v29']
ERROR = re.compile(r'^(.*?)\((\d+),(\d+)\): error (CS\d+): (.*?)(?: \[.*\])?$')
TARGETS = ['B4DA50', 'B5B390', 'B5B070', 'B04F60', 'B4D8B0']


def compiler(run):
    result = {}
    summary_path = ROOT/f'reports/recovered-source-profile-legacy-reference-check-{run}.json'
    if not summary_path.is_file(): return result
    canonical = json.loads(summary_path.read_text(encoding='utf-8-sig'))
    expected = {r['assembly']:r['unique_compiler_diagnostic_lines'] for r in canonical['assemblies']}
    for assembly in ['Assembly-CSharp-firstpass', 'Assembly-CSharp']:
        path = ROOT/f'logs/source-profile-legacy-reference-build-{run}-{assembly}.log'
        if not path.is_file(): continue
        seen = set(); codes = Counter(); messages = Counter()
        with path.open(encoding='utf-8-sig', errors='replace') as stream:
            for line in stream:
                match = ERROR.match(line.rstrip())
                if not match: continue
                key = (match[1].strip().casefold(), int(match[2]), int(match[3]), match[4], match[5].strip())
                if key in seen: continue
                seen.add(key); codes[match[4]] += 1; messages[(match[4], match[5])] += 1
        result[assembly] = dict(unique_error_diagnostics=len(seen), error_codes=dict(codes),
            top_messages=[dict(code=k[0], message=k[1], count=n) for k, n in messages.most_common(16)],
            log=str(path.relative_to(ROOT)))
        if len(seen) != expected[assembly]: raise ValueError('Compiler diagnostics do not match canonical summary: '+run+' / '+assembly)
        result[assembly]['matches_canonical_summary'] = True
    return result


def source(run):
    report = ROOT/f'reports/recovered-source-profile-project-build-{run}.json'
    if not report.is_file(): return dict(status='EXPORT_MANIFEST_NOT_YET_AVAILABLE')
    manifest = json.loads(report.read_text(encoding='utf-8-sig'))
    results = {}
    for assembly in manifest['assemblies']:
        pointers = Counter(); constructed = 0; files = 0; selected = None
        for row in assembly['source_files']:
            path = ROOT/row['path']
            payload = path.read_bytes()
            if len(payload) != row['bytes'] or hashlib.sha256(payload).hexdigest() != row['sha256']:
                raise ValueError('Recovered source differs from its immutable export manifest: '+row['path'])
            text = payload.decode('utf-8-sig')
            for target in TARGETS: pointers[target] += text.count('Method not found @'+target)
            count = len(re.findall(r'new\s+(?:System\.)?ArrayTypeMismatchException\s*\(\s*\)', text))
            constructed += count; files += 1
            if path.name == 'AuthenticationSample.cs':
                selected = dict(path=row['path'], sha256=row['sha256'], bytes=row['bytes'],
                    unresolved_factory_calls=text.count('Method not found @B4DA50'),
                    parameterless_array_mismatch_constructions=count)
        results[assembly['assembly']] = dict(source_manifest_hashes_verified=True, files_checked=files,
            unresolved_helper_calls=dict(pointers), parameterless_array_mismatch_constructions=constructed,
            selected_caller=selected)
    return results


def native_boxing():
    native = sqlite3.connect(ROOT/'analysis/nso/corpus.sqlite')
    metadata = sqlite3.connect(ROOT/'analysis/il2cpp/research.sqlite')
    names = defaultdict(list)
    for name, signature, rva in metadata.execute('select name,signature,rva from methods where name like ?', ('System.%',)):
        names[rva].append((name, signature))
    callers = set(row[0] for row in native.execute('select caller_rva from calls where callee_rva=?', (0xB5B070,)))
    symbols = [(rva, name, signature) for rva in sorted(callers) for name, signature in names[rva]]
    raw = (ROOT/'analysis/nso/main-uncompressed.nso').read_bytes()
    segments = [struct.unpack_from('<III', raw, offset) for offset in [0x10, 0x20, 0x30]]
    def read(rva, count):
        for offset, base, length in segments:
            if base <= rva and rva + count <= base + length:
                return raw[offset+rva-base:offset+rva-base+count]
        raise ValueError('Unmapped native bytes')
    def branch(word, pc):
        displacement = word & 0x3ffffff
        if displacement & 0x2000000: displacement -= 0x4000000
        return pc + displacement * 4
    anchors = []
    for wanted in ['System.Boolean$$System.IConvertible.ToType', 'System.Int32$$System.IConvertible.ToType', 'System.Double$$System.IConvertible.ToType']:
        matches = [(a, n, s) for a, rows in names.items() for n, s in rows if n == wanted]
        if len(matches) != 1: raise ValueError('Primitive metadata anchor is ambiguous')
        a, n, signature = matches[0]
        thunk = read(a, 8)
        adjustment, transfer = struct.unpack('<II', thunk)
        if adjustment != 0x91004000 or transfer & 0xfc000000 != 0x14000000:
            raise ValueError('Primitive anchor lacks exact +16 receiver adjustor thunk')
        body = branch(transfer, a + 4)
        indexed = native.execute('select corpus,offset,length from functions where rva=?', (body,)).fetchone()
        with (ROOT/indexed[0]).open('rb') as stream:
            stream.seek(indexed[1]); record = json.loads(stream.read(indexed[2]))
        if 'unwind_fde_rva' not in record or record['end_rva'] - body != 252:
            raise ValueError('Primitive anchor real body lacks the reviewed bounded frame')
        code = read(body, 252)
        calls = [body+i for i in range(0,len(code),4)
                 if (word:=struct.unpack_from('<I',code,i)[0]) & 0xfc000000 == 0x94000000
                 and branch(word, body+i) == 0xB5B070]
        if len(calls) != 1: raise ValueError('Primitive anchor does not agree on a unique boxing helper call')
        anchors.append(dict(rva=hex(a), name=n, signature=signature, adjustor_bytes=8,
            adjustor_sha256=hashlib.sha256(thunk).hexdigest(), receiver_adjustment=16,
            real_body_rva=hex(body), real_body_bytes=252, real_body_sha256=hashlib.sha256(code).hexdigest(),
            validated_unwind_fde_rva=record['unwind_fde_rva'], boxing_call_rva=hex(calls[0]), boxing_target_rva='0xB5B070'))
    return dict(rva='0xB5B070', reviewed_bytes=156,
        sha256=hashlib.sha256(read(0xB5B070, 156)).hexdigest(),
        distinct_direct_callers=len(callers), primitive_corlib_anchors=anchors,
        other_corlib_examples=[dict(rva=hex(a), name=n) for a, n, _ in symbols[:12]],
        observed_paths=[
            'Reference-type flag clear: reads *value and returns that existing object.',
            'Ordinary value type: queries size, allocates the exact class, copies instance_size minus 16 bytes from the supplied value address to object plus 16.',
            'Nullable value type: obtains its underlying class; absent hasValue returns null before allocation.'
        ],
        current_pipeline=dict(discovery='NewArm64KeyFunctionAddresses.AttemptInstructionAnalysisToFillGaps has no legacy boxing fallback.',
            lowering='KeyFunctionRecovery.cs:81 already lowers il2cpp_value_box/il2cpp_vm_object_box calls with typed class operands to OpCode.Box.',
            emitter='IlGenerator.cs OpCode.Box emits box and dereferences AddressOf(LocalVariable) as a value. Unknown address operands still need validation.'),
        proposed_fix='Add strict legacy vm::Object::Box discovery from three agreeing corlib anchors plus exact reviewed native witness, then enable existing Box lowering initially only for concrete non-nullable scalar primitives without a metadata .cctor and with known typed value storage.',
        required_acceptance=[
            'Reject mismatched helper bytes, nonzero nullable/reference-type behavior when the narrower lowering lacks its contract, unknown class operands and untyped addresses.',
            'Execute actual native scalar boxing payloads at explicit allocator/memcpy boundaries and compare recovered CIL box payloads, exact type and new identity.',
            'Retain unresolved generic/nullable/stack-address cases without substituting values or stubs; measure actual source change.'
        ],
        status='STATIC_NATIVE_CANDIDATE_NOT_IMPLEMENTED_OR_BEHAVIORALLY_VALIDATED')


def main():
    result = dict(status='READ_ONLY_COMPILER_PRIORITY_AND_SOURCE_CORRELATION',
        runs={run:dict(compiler=compiler(run), source=source(run)) for run in RUNS},
        recommended_candidate=native_boxing(),
        alternative=dict(rva='0xB5B390', meaning='Object instance-test helper with non-imported assignability and separate imported/COM paths.',
            why_not_first='No ISIL instance-test operation or key-function lowering currently exists; implementing it requires more pipeline surface than connecting the already present Box lowering.'),
        source_modified=False, scope='Counts are diagnostics and unresolved-call observations, not completion percentages. Every source file counted is byte/hash checked against its existing export manifest. Native helper semantics here are static candidates, not recovered executable parity.')
    path = destination(ROOT, ROOT/'reports/compiler-priority-next-v29.json')
    path.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(status=result['status'], report=str(path),
        runs={r:dict(source={a:dict(files_checked=s['files_checked'], unresolved_helper_calls=s['unresolved_helper_calls'],
                 array_mismatch_constructions=s['parameterless_array_mismatch_constructions']) for a,s in v['source'].items()},
            compiler={a:c['unique_error_diagnostics'] for a,c in v['compiler'].items()}) for r,v in result['runs'].items()},
        primitive_boxing_anchors=result['recommended_candidate']['primitive_corlib_anchors']), indent=2))


if __name__ == '__main__': main()
