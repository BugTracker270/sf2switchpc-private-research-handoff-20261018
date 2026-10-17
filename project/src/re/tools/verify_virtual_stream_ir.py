"""Verify scoped native virtual-call recovery through the full production IR pipeline."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    paths = dict(baseline='reports/virtual-stream-stage-survey-v36.json',
                 production='reports/virtual-stream-stage-survey-v36-after3.json',
                 contract='reports/virtual-dispatch-contract-v36.json',
                 native='reports/native-virtual-stream-prefix-v36.json',
                 review='reports/virtual-dispatch-independent-source-review-v36.json')
    data = {key: json.loads((ROOT / path).read_text(encoding='utf-8-sig')) for key, path in paths.items()}
    checks = 0

    def check(condition, message):
        nonlocal checks
        if not condition:
            raise ValueError(message)
        checks += 1

    current = data['production']
    core = sha(ROOT / 'refs/Cpp2IL/Cpp2IL.Core/bin/Release/net10.0/Cpp2IL.Core.dll')
    check(current['core_sha256'] == core == data['contract']['core_sha256'], 'Production/contract/Core hashes differ')
    check(data['contract']['status'] == 'PASS_NATIVE_VIRTUAL_WITNESS_AND_REAL_EMITTER_CLR_CONTRACT'
          and data['contract']['checks'] == 218 and data['contract']['cases'] == 99, 'Synthetic/CLR contract changed')
    check(current['registered_rva'] == '0x4A0D70' and current['slot'] == 19
          and current['metadata_target'] == 'System.IO.Stream::ReadByte', 'Original caller/slot/target changed')
    old = next(stage['calls'] for stage in data['baseline']['stages'] if stage['stage'] == 'simplified-ssa')
    check({row['index'] for row in old if row['opcode'] == 'Call'} == {26, 36}
          and all(not row.get('native_virtual_proof', False) for row in old), 'Baseline lost original direct-call limitation')
    for label in ('after-type', 'simplified-ssa', 'emitter-input'):
        calls = next(stage['calls'] for stage in current['stages'] if stage['stage'] == label)
        accepted = [row for row in calls if row['native_virtual_proof']]
        check({row['index'] for row in accepted} == {26, 36}
              and all(row['opcode'] == 'Call' and row['emission_proof_valid'] for row in accepted),
              'Exact root-bound proof did not survive ' + label)
        check({row['index'] for row in calls if row['opcode'] == 'IndirectCall' and not row['native_virtual_proof']} == {195, 231},
              'Unproved original dispatch changed in ' + label)
    native = data['native']
    binary = ROOT / 'analysis/nso/main-uncompressed.nso'
    check(sha(binary) == native['native_source_sha256'] == 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968', 'Native input differs')
    check(native['status'] == 'PASS_UNCHANGED_NATIVE_STREAM_OVERRIDE_AND_VIRTUAL_READER_PREFIX'
          and native['cases'] == 802 and native['checks'] == 9624 and native['failures'] == 0
          and native['original_native_virtual_calls'] == 1604, 'Original native dispatch oracle failed')
    with binary.open('rb') as stream:
        stream.seek(0x100 + 0x4A0D70)
        body = stream.read(956)
    check(hashlib.sha256(body).hexdigest() == native['reader_code_sha256'], 'Original caller exact body differs')
    sources = data['review']['reviewed_sources']
    check(len(sources) == 6 and all(sha(ROOT / row['path']) == row['sha256'] for row in sources), 'Independent source review snapshot differs')
    output = dict(status='PASS_SCOPED_NATIVE_VIRTUAL_PROOF_THROUGH_PRODUCTION_EMITTER_INPUT', checks=checks,
                  core_sha256=core, accepted_original_call_indices=[26, 36], unresolved_original_indirect_indices=[195, 231],
                  evidence={key: dict(path=path, sha256=sha(ROOT / path)) for key, path in paths.items()},
                  recovered_game_methods_invoked=0, recovered_cil_or_source_modified=False,
                  full_clean_decompile_ready=False, whole_game_source_ready=False, portable_game_ready=False,
                  scope='Two actual ReadByte dispatches retain exact original parameter-root proof through the complete unchanged production analysis pipeline and final emitter validation. Independent synthetic tests exercise real emitter callvirt/CallVoid/direct-base behavior and CLR override/null effects; original native fixtures exercise the reader prefix and MemoryStream override. These scopes do not execute the whole recovered reader. Later duplicate CFG edges, unrelated raw class-layout initialization and the surviving companion-load diagnostic remain separate limitations. IR does not retain integer load width; exact64-bit native Stream-site correlation is separate, not a general width-recovery claim.')
    destination(ROOT, ROOT / 'reports/virtual-stream-production-ir-v36.json').write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps(dict(status=output['status'], checks=checks, core_sha256=core)))


if __name__ == '__main__':
    main()
