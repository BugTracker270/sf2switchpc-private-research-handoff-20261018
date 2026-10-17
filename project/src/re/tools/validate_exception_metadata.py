"""Record synthetic parser gates and separately bind original local metadata evidence.

The parser unit suite itself has no proprietary-input dependency. This optional
integration command also reads the authorized local image; original instructions
remain under ignored analysis, and no unwind or managed code is executed.
"""
import contextlib
import hashlib
import importlib
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination
from native_unwind_inventory import Image


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


class Results(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def startTest(self, test):
        self.records.append(dict(name=test.id(), passed=False))
        super().startTest(test)

    def addSuccess(self, test):
        self.records[-1]['passed'] = True
        super().addSuccess(test)


def main():
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_exception_metadata.py')
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output, resultclass=Results, verbosity=2).run(suite)
    log = destination(ROOT, ROOT / 'logs/exception-metadata-v35-unit-tests.log')
    log.write_text(output.getvalue(), encoding='utf-8')
    if not result.wasSuccessful() or result.skipped:
        raise RuntimeError('Synthetic parser suite failed; exact log preserved at ' + str(log))
    # Refresh the positive evidence through the same reusable parser being tested.
    inspection_output = io.StringIO()
    with contextlib.redirect_stdout(inspection_output):
        importlib.import_module('inspect_unload_exception_contract').main()
    destination(ROOT, ROOT / 'logs/unload-exception-contract-v35-inspection.log').write_text(inspection_output.getvalue(), encoding='utf-8')
    native_path = ROOT / 'analysis/reconstruction/unload-exception-contract-v35/native-evidence.json'
    initial_path = native_path.with_name('native-evidence-initial.json')
    native, initial = load(native_path), load(initial_path)
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    image = Image(source.read_bytes())
    checks = []

    def check(name, passed):
        checks.append(dict(name=name, passed=bool(passed)))

    check('synthetic suite has no failures/errors/skips', result.wasSuccessful() and not result.skipped
          and result.testsRun == len(result.records) and all(row['passed'] for row in result.records))
    for key in ('original_native_sha256', 'exact_frame', 'lsda', 'action_chains', 'types', 'plt_imports',
                'personality_slot', 'raiser_rtti_slot'):
        check('reusable parser agrees with prior independent inspection: ' + key, native[key] == initial[key])
    row_keys = ('record', 'at', 'effective_pc', 'operation', 'state')
    def common_cfi(evidence):
        return [{key: row[key] for key in row_keys} for row in evidence['cfi_rows']]
    check('all original CIE/FDE CFI steps agree with prior inspection', common_cfi(native) == common_cfi(initial))
    parser = ROOT / 'src/tools/exception_metadata.py'
    inspector = ROOT / 'src/re/tools/inspect_unload_exception_contract.py'
    check('positive evidence binds current reusable parser and adapter', native['reusable_parser_sha256'] == sha(parser)
          and native['probe_source_sha256'] == sha(inspector) and native['reusable_parser_original_lsda_agrees_with_independent_inventory'])
    check('exact original native image', sha(source) == native['original_native_sha256']
          == 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968')
    code_sha = hashlib.sha256(image.read(0x4A83A0, 384)).hexdigest()
    check('exact original 384-byte caller body', code_sha == '0fd52a9b449be83e29a7424dab0003da060929dbe574320d54ecfac5121483f2')
    frame = native['exact_frame']
    cie_start = next(int(row['at'], 16) for row in native['cfi_rows'] if row['record'] == 'CIE')
    cie_end = frame['cie_rva'] + 32
    # The exact reviewed CIE has a three-byte program; reject changed boundaries.
    check('reviewed CIE/FDE program lengths', cie_end - cie_start == 3 and frame['fde_end_rva'] - frame['cfi_start'] == 15)
    check('exact protected table and parsed action scope', len(native['lsda']['call_sites']) == 5
          and sum(row['landing'] is not None for row in native['lsda']['call_sites']) == 3
          and list(native['action_chains']) == ['3']
          and [row['type_filter'] for row in native['action_chains']['3']] == [1, 0]
          and list(native['types']) == ['1'])
    failures = sum(not row['passed'] for row in checks)
    report = dict(
        status='PASS_BOUNDED_EXCEPTION_METADATA_PARSER' if failures == 0 else 'FAIL_EXCEPTION_METADATA_PARSER_EVIDENCE',
        synthetic_tests=result.testsRun, synthetic_failures=len(result.failures), synthetic_errors=len(result.errors),
        synthetic_skips=len(result.skipped), synthetic_test_results=result.records,
        integration_checks=len(checks), integration_failures=failures, integration_results=checks,
        parser_path=str(parser.relative_to(ROOT)), parser_sha256=sha(parser),
        unit_test_path='tests/test_exception_metadata.py', unit_test_source_sha256=sha(ROOT / 'tests/test_exception_metadata.py'),
        unit_log=str(log.relative_to(ROOT)), unit_log_sha256=sha(log),
        integration_adapter_sha256=sha(inspector), validation_source_sha256=sha(Path(__file__)),
        native_source_sha256=native['original_native_sha256'], original_code_sha256=code_sha,
        original_lsda_sha256=hashlib.sha256(image.read(0x2FE4DA8, 84)).hexdigest(),
        original_cie_program_sha256=hashlib.sha256(image.read(cie_start, 3)).hexdigest(),
        original_fde_program_sha256=hashlib.sha256(image.read(frame['cfi_start'], 15)).hexdigest(),
        private_native_evidence=str(native_path.relative_to(ROOT)), private_native_evidence_sha256=sha(native_path),
        prior_independent_evidence_sha256=sha(initial_path),
        observed_original=dict(protected_ranges=3, action_filters=[1, 0], type_entries=1,
            native_cpp_type='22Il2CppExceptionWrapper', cfi_steps=len(native['cfi_rows']),
            cfa='X29 + 16', saved_register_cfa_offsets=native['cfi_rows'][-1]['state']['saved']),
        implemented_contract=[
            '64-bit bounded cursor/LEB and explicit absolute/PC-relative/indirect pointer references; encoded zero remains null.',
            'Bounded unsigned-32 call-site ranges, fixed-width type table, signed action back-links and shared chains.',
            'Reject cycles, overlapping records/ranges, truncated/outside type entries, negative exception specifications and unsupported forms.',
            'Narrow per-instruction CFI state observations with bounded registers/PC/stack, validated initial state and explicit unsupported opcodes; shared-PC intermediate observations are not finalized unwind rows.',
            'Caller-supplied checked relocation resolution plus bounded simple C++ class RTTI name reading; no managed catch inference.',
        ],
        unsupported_contract=[
            'General LSDA encodings, exception specifications and arbitrary C++ inheritance/RTTI structures.',
            'General DWARF CFI expressions, remember/restore, stack unwinding or SDK personality execution.',
            'EH-aware ISIL/SSA, managed region emission, game exception behavior or portable source completeness.',
        ],
        core_edited=False, core_built=False, original_image_modified=False, runtime_code_executed=False,
        production_eh_implemented=False, full_clean_decompile_ready=False,
        scope='Original local metadata decoding plus synthetic malformed-input infrastructure. Counts are parser/evidence gates, not recovered method or gameplay coverage.')
    base = ROOT / 'reports/exception-metadata-parser-v35'
    destination(ROOT, base.with_suffix('.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    lines = ['# Bounded exception metadata parser', '', report['status'], '',
             f"{report['synthetic_tests']} synthetic tests and {report['integration_checks']} original-evidence checks; {failures} integration failures.", '',
             'The reusable parser reads a bounded LSDA/action/type-table subset, explicit encoded pointer references, a narrow CFI state program and simple C++ RTTI names. The unit suite requires no game files.', '',
             'Its original-input adapter reproduces the earlier independent UnloadDependencies inspection: three protected ranges, a typed-wrapper action followed by cleanup, the same native wrapper RTTI, and the same CFA/saved-register states. Full original instructions remain in ignored local analysis.', '',
             'Implemented contracts:', '']
    lines += ['- ' + text for text in report['implemented_contract']]
    lines += ['', 'Remaining scope:', '']
    lines += ['- ' + text for text in report['unsupported_contract']]
    lines += ['', 'No Core code changed or built. No unwind or recovered game method executed, and no exception region was emitted. Full clean decompilation remains incomplete.', '',
              'Run the synthetic suite alone with `python -m unittest discover -s tests -p test_exception_metadata.py -v`. Run the USB-local integration with `python src/re/tools/validate_exception_metadata.py`.', '']
    destination(ROOT, base.with_suffix('.md')).write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'synthetic_tests', 'synthetic_failures', 'synthetic_errors', 'integration_checks', 'integration_failures')}))
    if failures:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
