"""Independent, synthetic-only malformed-input review of original metadata tooling."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from exception_metadata import CfiState, Cursor, MetadataError, Span, UnsupportedMetadata, parse_cfi, parse_lsda
from usb_boundary import destination


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reader(data, base=0x2000, observations=None):
    def read(at, size):
        if observations is not None:
            observations.append((at, size))
        if not base <= at <= at + size <= base + len(data):
            raise AssertionError('Parser read outside supplied metadata')
        return bytes(data[at - base:at - base + size])
    return read


def expect_rejection(data, parse, expected, text=None):
    try:
        parse(data)
    except expected as error:
        if text and text not in str(error):
            raise AssertionError('Rejection did not identify expected condition') from error
    else:
        raise AssertionError('Malformed or unsupported input was accepted')


def main():
    checks = []
    def check(name, action):
        action()
        checks.append(dict(name=name, status='PASS'))

    def lsda(data, **options):
        return parse_lsda(reader(data), Span(0x2000, 0x2000 + len(data)), Span(0x1000, 0x1100), **options)

    def cfi(data, **options):
        return parse_cfi(reader(data), Span(0x2000, 0x2000 + len(data)), Span(0x1000, 0x1020), **options)

    # Two distinct zero-filter records link to one another. This is not only
    # the self-loop shape already exercised by the owner's fixtures.
    table = struct.pack('<III', 0x20, 8, 0x80) + b'\x01'
    cycle = b'\xff\xff\x03\x0d' + table + b'\x00\x01\x00\x7d'
    check('two-node signed action backlink cycle rejects', lambda: expect_rejection(cycle, lsda, MetadataError, 'Cyclic'))

    # Type pointer is intentionally indirect and points beyond the LSDA span.
    # The bounded parser must report a reference without implicitly reading it.
    typed_table = struct.pack('<III', 0x20, 8, 0x80) + b'\x01'
    typed = bytearray(b'\xff\x9c\x00\x03\x0d' + typed_table + b'\x01\x00' + bytes(8))
    typed[2] = len(typed) - 3
    field_at = 0x2000 + len(typed) - 8
    struct.pack_into('<q', typed, len(typed) - 8, 0xDEAD0000 - field_at)
    def indirect_boundary():
        reads = []
        result = parse_lsda(reader(typed, observations=reads), Span(0x2000, 0x2000 + len(typed)), Span(0x1000, 0x1100))
        pointer = result.type_entries[1]
        assert pointer.indirect and pointer.reference == 0xDEAD0000
        assert all(0x2000 <= at <= at + size <= 0x2000 + len(typed) for at, size in reads)
    check('indirect type entry remains explicit and is never implicitly dereferenced', indirect_boundary)

    check('unsupported CFI restore does not invent an initial register rule',
          lambda: expect_rejection(b'\xc1', cfi, UnsupportedMetadata))
    check('CFI advance crossing exact function end rejects',
          lambda: expect_rejection(b'\x02\x21', cfi, MetadataError))
    check('CFI saved offset multiplication obeys configured budget',
          lambda: expect_rejection(b'\x93\x05', lambda d: cfi(d, max_stack_offset=16), MetadataError))

    def same_pc_state_observations():
        steps, state = cfi(b'\x0c\x1f\x00\x0e\x10\x93\x02')
        assert [step.pc for step in steps] == [0x1000] * 3
        assert [step.state.cfa_offset for step in steps] == [0, 16, 16]
        assert state.cfa_register == 31 and dict(state.saved) == {19: -8}
    check('same-PC CFI state changes remain ordered observations', same_pc_state_observations)

    check('CFI operation budget rejects repeated zero-progress instructions',
          lambda: expect_rejection(b'\x00' * 5, lambda d: cfi(d, max_steps=4), MetadataError))
    check('LEB overflow in action displacement rejects before any outside read',
          lambda: expect_rejection(b'\xff\xff\x03\x0d' + table + b'\x00' + b'\x80' * 10,
                                   lsda, MetadataError))
    check('malformed host-side initial saved-rule container rejects with MetadataError',
          lambda: expect_rejection(b'', lambda d: cfi(d, initial=CfiState(31, 0, None)), MetadataError))

    report = dict(status='PASS_INDEPENDENT_BOUNDED_EXCEPTION_METADATA_INFRASTRUCTURE_REVIEW',
                  checks=len(checks), tests=checks,
                  parser_sha256=sha(ROOT / 'src/tools/exception_metadata.py'),
                  owner_tests_sha256=sha(ROOT / 'tests/test_exception_metadata.py'),
                  adapter_sha256=sha(ROOT / 'src/re/tools/inspect_unload_exception_contract.py'),
                  review_probe_sha256=sha(Path(__file__)),
                  findings=[], resolved_review_findings=[dict(
                      issue='Malformed host-side CfiState saved=None previously raised TypeError rather than MetadataError',
                      severity='minor API robustness', original_native_path_affected=False,
                      original_trace='logs/exception-metadata-malformed-initial-review-v35.log',
                      resolution='Parser owner added strict initial saved-rule container validation; independent ninth check requires MetadataError')],
                  source_edited=False, core_built=False,
                  proprietary_inputs_read=False, guest_execution_performed=False,
                  scope=('Independent static review and synthetic boundary checks only. LSDA action displacement is based at the displacement operand; '
                         'cycles, record/type overlap and configured limits fail closed. Fixed-width type-table pointers retain explicit indirection '
                         'for a separate checked resolver. Supported CFI opcodes produce ordered instruction/state observations, including '
                         'intermediate states at the same PC, rather than complete PC-range unwind rows. Unsupported restore/state-stack/expression '
                         'operations reject. This does not validate actual unwinding, landing-pad execution, exception matching or managed EH recovery.'))
    output = destination(ROOT, ROOT / 'reports/exception-metadata-independent-review-v35.json')
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], checks=len(checks))))


if __name__ == '__main__':
    main()
