"""Sanitized exact-release Class::Init ABI/effects evidence; no lowering or Core edit."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8-sig'))


def function(text, signature):
    start = text.index(signature)
    brace = text.index('{', start)
    depth = 0
    for index in range(brace, len(text)):
        depth += (text[index] == '{') - (text[index] == '}')
        if depth == 0:
            return text[start:index + 1], text[:start].count('\n') + 1
    raise ValueError('Reviewed function body missing end')


def main():
    base = ROOT / 'tools/unity-2018.1.9f1/common-runtime-source/Editor/Data/il2cpp/libil2cpp'
    files = {str(path.relative_to(base)).replace('\\', '/'): path for path in base.rglob('*') if path.is_file()}
    texts = {name: path.read_text(encoding='utf-8-sig') for name, path in files.items()}
    archive = load('reports/unity-2018.1.9f1-archive-provenance.json')
    extracted = load('reports/unity-2018.1.9f1-common-runtime-source.json')
    native_path = 'analysis/reconstruction/class-layout-runtime-source-v37/native.json'
    native = load(native_path)
    original, locked, lock, unlock, cctor_native = native['methods']
    assertion = load('analysis/reconstruction/class-layout-runtime-source-v37/assertion-identity.json')
    fast = load('reports/native-class-layout-bool-v37.json')
    init_source, init_line = function(texts['vm/Class.cpp'], 'bool Class::Init(Il2CppClass *klass)')
    locked_source, locked_line = function(texts['vm/Class.cpp'], 'static bool InitLocked(Il2CppClass *klass, const FastAutoLock& lock)\n    {')
    cctor_source, cctor_line = function(texts['vm/Runtime.cpp'], 'void Runtime::ClassInit(Il2CppClass *klass)')
    checks = []
    def check(name, ok):
        checks.append(dict(name=name, passed=bool(ok)))
    check('exact official release/revision and published MD5', archive['release'] == '2018.1.9f1'
          and archive['revision'] == '24bbd83e8b9e' and archive['actual_md5'] == archive['expected_md5'] == '2b59d01b17b0f7acf2ff36a083bdd0d2')
    check('archive size discrepancy is explicit and digest unchanged', archive['downloaded_bytes'] == 596405520
          and archive['expected_bytes'] == 596405248 and archive['api_size_delta_bytes'] == 272
          and archive['local_sha256'] == 'ce666b2de60716cb5564b53317b56f0b82eddbea7afb3462ef51d5e121833c96')
    check('selected common source/license extraction verified', extracted['file_count'] == 14
          and extracted['extraction_exit_code'] == 0 and all(sha(ROOT / row['path']) == row['sha256'] for row in extracted['files']))
    check('official declaration is one class argument and Boolean return', 'static bool Init(Il2CppClass *klass);' in texts['vm/Class.h'])
    check('normal source return is true, including initialized case', init_line == 1441
          and init_source.count('return true;') == 1 and 'return false' not in init_source and 'InitLocked(klass, lock);' in init_source)
    instructions = {int(row['rva'], 16): row for row in original['instructions']}
    check('complete original wrapper is the exact 140-byte exception frame', original['bytes'] == 140
          and original['end'] == '0xb04fec' and original['sha256'] == '496575374643a8ca7a9f1181d685de0fa4ac68574a3cc50c315d52d74a4d7dd3')
    check('original returns true in W0', instructions[0xB04FA4]['mnemonic'] == 'mov' and instructions[0xB04FA4]['operands'] == 'w0, #1')
    check('second InitLocked argument is constructed local lock address', instructions[0xB04F8C]['mnemonic'] == 'add'
          and instructions[0xB04F8C]['operands'] == 'x1, sp, #8' and instructions[0xB04F90]['operands'] == 'x0, x19'
          and instructions[0xB04F94]['operands'] == '#0xb06570')
    check('exact null assertion maps to official source line/function', assertion['expression'] == 'klass'
          and assertion['source_function'] == 'Init' and assertion['source_path'].endswith('Class.cpp') and assertion['source_line'] == 1443
          and texts['vm/Class.cpp'].splitlines()[1442].strip() == 'IL2CPP_ASSERT(klass);')
    check('initialized native oracle is unchanged and has no function replacements', fast['cases'] == 512 and fast['checks'] == 3584
          and fast['code_unmodified'] and fast['guest_function_replacements'] == 0 and fast['null_assert_boundary_cases'] == 1)
    check('metadata InitLocked effects are retained', all(token in locked_source for token in ('klass->init_pending = true;', 'SetupMethodsLocked', 'SetupFieldsLocked', 'SetupVTable',
          'SetupGCDescriptor', 'SetupEventsLocked', 'SetupPropertiesLocked', 'klass->initialized = true;', 'klass->init_pending = false;')))
    check('managed constructor invocation is a distinct runtime function', cctor_line == 742
          and 'klass->has_cctor' in cctor_source and 'vm::Runtime::Invoke(cctor' in cctor_source
          and 'Runtime::ClassInit' not in init_source and 'Runtime::Invoke' not in locked_source)
    check('mutex/RAII source and original unwind cleanup retained', all(token in texts['os/Mutex.h'] for token in ('m_Mutex->Lock();', '~FastAutoLock()', 'm_Mutex->Unlock();'))
          and instructions[0xB04FDC]['operands'] == '#0xb7dca0' and instructions[0xB04FE4]['operands'] == '#0x2373058')
    check('prior 112-byte oracle is explicitly narrower', native['prior_initialized_path_range']['bytes'] == 112 and original['bytes'] == 140)
    check('source bit order agrees with native initialized-bit observation', 'uint8_t valuetype : 1;\n    uint8_t initialized : 1;' in texts['il2cpp-class-internals.h']
          and instructions[0xB04F74]['operands'] == 'w8, [x19, #0x121]' and instructions[0xB04F78]['operands'] == 'w8, #1, #0xb04fa0')
    private = destination(ROOT, ROOT / 'analysis/reconstruction/class-layout-runtime-source-v37/source-comparison.json')
    private.write_text(json.dumps(dict(common_source_archive_sha256=archive['local_sha256'],
        class_init=dict(line=init_line, body=init_source), init_locked=dict(line=locked_line, body=locked_source),
        managed_cctor=dict(line=cctor_line, body=cctor_source), source_files={name:sha(path) for name, path in files.items()}), indent=2) + '\n', encoding='utf-8')
    locations = []
    for name, token in (('vm/Class.h', 'static bool Init(Il2CppClass *klass);'), ('vm/Class.cpp', 'bool Class::Init(Il2CppClass *klass)'),
                        ('vm/Class.cpp', 'static bool InitLocked(Il2CppClass *klass, const FastAutoLock& lock)\n    {'),
                        ('vm/Runtime.cpp', 'void Runtime::ClassInit(Il2CppClass *klass)'), ('os/Mutex.h', 'struct FastAutoLock'),
                        ('il2cpp-class-internals.h', 'uint8_t initialized : 1;')):
        locations.append(dict(path=str(files[name].relative_to(ROOT)), line=texts[name][:texts[name].index(token)].count('\n') + 1,
                              sha256=sha(files[name])))
    report = dict(status='PASS_EXACT_COMMON_RUNTIME_CLASS_INIT_BOOL_ABI_AND_EFFECTS' if all(row['passed'] for row in checks) else 'FAIL_CLASS_LAYOUT_SOURCE_CORRELATION',
        checks=len(checks), failures=sum(not row['passed'] for row in checks), tests=checks,
        source_release=archive['release'], source_revision=archive['revision'], archive_sha256=archive['local_sha256'],
        archive_provenance_sha256=sha(ROOT / 'reports/unity-2018.1.9f1-archive-provenance.json'),
        source_locations=locations, all_common_source_file_hashes={name:sha(path) for name, path in files.items()},
        supplemental_headers_extraction_log_sha256=sha(ROOT / 'logs/unity-2018.1.9f1-layout-headers-extraction.log'),
        original_native_source_sha256=native['source_sha256'], exact_wrapper_rva='0xb04f60', exact_wrapper_bytes=140,
        exact_wrapper_sha256=original['sha256'], exact_init_locked_rva=locked['start'], exact_init_locked_bytes=locked['bytes'],
        exact_init_locked_sha256=locked['sha256'], distinct_managed_cctor_rva=cctor_native['start'],
        abi=dict(explicit_arguments=1, argument='Il2CppClass* klass in X0', return_type='bool', normal_result=True,
                 incoming_x1_is_argument=False, void_return_supported=False, second_internal_argument='InitLocked receives the locally constructed lock address in X1'),
        effect_contract=[
            'Assert a non-null class pointer; initialized classes return true without metadata writes on the measured path.',
            'For an uninitialized class, acquire the metadata mutex and run InitLocked with RAII unlock on normal/exceptional paths.',
            'InitLocked recursively prepares generic/array-element/parent metadata, methods, interfaces/vtable, hierarchy, fields, events/properties/nested types, GC descriptors and generic context as applicable; it changes initialization state and statistics.',
            'Managed .cctor execution belongs to the distinct Runtime::ClassInit path with constructor-state guards and Runtime::Invoke; Class::Init must not be translated as RunClassConstructor.',
        ],
        failures_and_limits=[
            'Normal return is true; null input reaches a native assertion boundary, not a measured false return or managed NullReferenceException.',
            'Uninitialized setup may allocate and call other runtime metadata helpers. Their complete failure behavior is not executed here. The original wrapper has real cleanup/unwind instructions; those effects are not removable.',
            'The shipped common source is from the exact official Windows editor release. Platform-specific SDK/compiler implementation equivalence is not assumed; original native instructions independently anchor the wrapper signature, source assertion line and behavior.',
            'The 512-case native witness executes only the already-initialized path. One null case stops before the imported assertion; actual assertion termination, locks, InitLocked, unwinding and managed .cctor are outside that execution witness.',
            'ABI correction can reject phantom incoming X1 arguments without erasing the helper. A managed metadata-readiness translation still requires a separate contract and .cctor-negative CLR evidence; none is implemented.',
        ],
        prior_witness_correction='Earlier 112-byte fixtures were bounded initialized-path witnesses; exact FDE is 140 bytes, including cleanup. The initial new null guard expected a qualified function name; actual native assertion stores Init. Both failed logs are preserved and the final check uses that exact captured name.',
        native_initialized_witness_sha256=sha(ROOT / 'reports/native-class-layout-bool-v37.json'),
        private_comparison_sha256=sha(private), probe_source_sha256=sha(Path(__file__)),
        public_unity_source_copied=False, proprietary_sources_uploaded=False, installer_executed=False,
        core_edited=False, core_built=False, helper_suppressed=False, managed_translation_implemented=False,
        full_clean_decompile_ready=False)
    base_report = ROOT / 'reports/class-layout-runtime-source-v37'
    destination(ROOT, base_report.with_suffix('.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    lines = ['# Exact common runtime class-layout initialization', '', report['status'], '',
             'B04F60 matches the exact-release common runtime `bool Class::Init(Il2CppClass*)`: one class pointer in X0 and true on normal return. A void-return interpretation is unsupported. Incoming X1 is not a second managed argument.', '',
             f"{len(checks)} source/native checks passed; original initialized-path witness: 512 cases / 3,584 checks, plus one stopped null-assert boundary. Exact native FDE is 140 bytes, including unlock/resume cleanup; prior 112-byte fixtures covered a narrower initialized path.", '',
             'The official archive matches its published MD5. Its actual size exceeds the API catalog byte count by 272; both observations and the local SHA-256 are recorded. Only common runtime sources and a license reference were extracted as local ignored data. The installer was never executed.', '',
             'Preserved effects:', '']
    lines += ['- ' + text for text in report['effect_contract']]
    lines += ['', 'Limits and unresolved translation:', ''] + ['- ' + text for text in report['failures_and_limits']]
    lines += ['', 'Exact source locations/hashes are in the JSON. Detailed source excerpts and original instructions remain in ignored local analysis. No Core changes, helper removal or managed translation occurred.', '']
    destination(ROOT, base_report.with_suffix('.md')).write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'checks', 'failures', 'abi', 'managed_translation_implemented')}))
    if report['failures']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
