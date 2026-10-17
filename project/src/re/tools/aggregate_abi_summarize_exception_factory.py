"""Fail-closed sanitized ABI/effect proposal for the exact overflow factory."""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def main():
    def read(relative):
        return json.loads((ROOT / relative).read_text(encoding='utf-8-sig'))

    def sha(relative):
        return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()

    inventory_path = 'reports/exception-factory-native-source-inventory-v37.json'
    inventory = read(inventory_path)
    native = read(inventory['private_native_path'])
    dependencies = read(inventory['private_dependencies_path'])
    paths = {Path(row['path']).name: row['path'] for row in inventory['source_files']}
    header = (ROOT / paths['Exception.h']).read_text(encoding='utf-8-sig')
    source = (ROOT / paths['Exception.cpp']).read_text(encoding='utf-8-sig')
    rows = {row['address']: row for row in native['instructions']}
    getter = dependencies['dependencies'][0]
    tail = dependencies['dependencies'][1]
    before_x1_write = [row for row in native['instructions'] if row['address'] < 0xB4D978]
    checks = {
        'exact_original_helper_frame52_and_hash': inventory['helper_rva'] == '0xb4d960' and inventory['helper_end'] == '0xb4d994' and inventory['helper_bytes'] == 52 and inventory['helper_sha256'] == '3b5fd1d3de5b03792cd3309198170fba22c09b9434a348fa01330c20d8709f3f',
        'exact_official_release_revision_archive': inventory['source_release'] == '2018.1.9f1' and inventory['source_revision'] == '24bbd83e8b9e' and inventory['source_archive_sha256'] == 'ce666b2de60716cb5564b53317b56f0b82eddbea7afb3462ef51d5e121833c96',
        'source_pair_hashes_retained': all(sha(row['path']) == row['sha256'] for row in inventory['source_files']),
        'official_one_char_pointer_exception_return_declaration': 'static Il2CppException* GetOverflowException(const char* msg);' in header,
        'official_overload_forwards_message_to_named_factory': bool(re.search(r'Il2CppException\* Exception::GetOverflowException\(const char\* msg\)\s*\{\s*return FromNameMsg\(vm::Image::GetCorlib\(\), "System", "OverflowException", msg\);\s*\}', source)),
        'original_namespace_and_exception_name_match': dependencies['constants'] == {'0x2cbf925': 'System', '0x2cc3783': 'OverflowException'},
        'incoming_message_x0_saved_and_forwarded_to_x3': rows[0xB4D96C]['operands'] == 'x19, x0' and rows[0xB4D988]['operands'] == 'x3, x19',
        'incoming_x1_never_read_before_internal_definition': all(not {'x1', 'w1'} & set(row['register_reads']) for row in before_x1_write),
        'corlib_getter_is_exact_read_only16byte_leaf': getter['bytes'] == 16 and getter['sha256'] == '963ae7b0935b32a1dee79fb9b805e3e6b0c088e405a85003c97f7dcaa2641500' and [row['mnemonic'] for row in getter['instructions']] == ['adrp', 'ldr', 'ldr', 'ret'],
        'tail_target_is_exact324byte_exception_factory': rows[0xB4D990]['operands'] == '#0xb4d660' and tail['bytes'] == 324 and tail['sha256'] == '0152ef5e8f3afbf556d322183f8ecca2c457ec92757115a2dbd514b40b0df0a7',
        'native_tail_has_allocation_initialization_message_store_and_cleanup': all(any(row['operands'] == target and row['mnemonic'] == 'bl' for row in tail['instructions']) for target in ('#0xb5b110', '#0xb2e3c0', '#0xb68250', '#0x2373058')) and any(row['mnemonic'] == 'str' and row['operands'] == 'x0, [x19, #0x20]' for row in tail['instructions']),
        'official_effects_include_object_init_and_optional_message': all(text in source for text in ('Object::New(exceptionClass)', 'Runtime::ObjectInit((Il2CppObject*)ex)', 'IL2CPP_OBJECT_SETREF(ex, message, String::NewUtf16(msg))')),
        'original_reader_call_has_one_original_message_pointer': inventory['reader_call_rva'] == '0x4a0fd4' and any(row['mnemonic'] == 'adrp' and row['operands'] == 'x0, #0x2cb7000' for row in dependencies['reader_call_window']) and any(row['mnemonic'] == 'add' and row['operands'] == 'x0, x0, #0x786' for row in dependencies['reader_call_window']),
    }
    status = 'PASS_NATIVE_AND_OFFICIAL_SOURCE_OVERFLOW_FACTORY_ABI_PROPOSAL' if all(checks.values()) else 'EXCEPTION_FACTORY_ABI_PROPOSAL_FAILED'
    report = dict(status=status, checks=len(checks), tests=checks, helper_rva=inventory['helper_rva'], helper_end=inventory['helper_end'], helper_bytes=inventory['helper_bytes'], helper_sha256=inventory['helper_sha256'],
        inventory_report=inventory_path, inventory_report_sha256=sha(inventory_path), source_files=inventory['source_files'],
        source_locations=[dict(path=paths['Exception.h'], line=59), dict(path=paths['Exception.cpp'], line=375), dict(path=paths['Exception.cpp'], line=244), dict(path=paths['Exception.cpp'], line=254)],
        abi=dict(explicit_arguments=1, incoming_x0='const char* optional UTF-8 message pointer', return_x0='Il2CppException*', incoming_x1_is_argument=False, incoming_x2_x7_are_arguments=False, native_call_returns=True),
        semantic_effects=['Look up the named exception class in corlib.', 'Convert a non-null UTF-8 message to UTF-16.', 'Allocate the exception and run its managed object initializer.', 'Create/store the nonempty message using the original managed-reference operation.', 'Retain allocation/constructor/conversion failure and cleanup/unwind paths. The wrapper returns an exception; the caller performs the separate throw.'],
        bounded_implementation_proposal='Image/FDE/full52byte hash gate the exact numeric helper before alias lookup; retain a Call with its X0 reference result and sole original X0 pointer argument. Remove only unconsumed incoming phantom register arguments. Keep numeric unresolved helper diagnostics and the later actual Throw; do not replace with new OverflowException, erase effects, fold conditions or claim runtime semantics.',
        expected_reader_consequence='The current emitter-input raw call202 consumes stale X1v145 through this phantom ABI argument. Correcting this exact signature may let ordinary dead-code analysis remove that use and the +260 companion load; it is a prediction until a fresh unchanged production-stage/recovered-CIL report proves it.',
        native_helper_executed=False, core_edited=False, managed_factory_translation_implemented=False, runtime_parity_proven=False, full_clean_decompile_ready=False,
        limits=['The official source is the exact common Windows-editor release; platform/compiler equivalence is not assumed. Original ARM64 wrapper constants and register flow independently anchor this signature.', 'Existing native-array tests supplied this factory as an explicit boundary and do not prove original factory execution.', 'The pointer must remain a native message pointer at the ABI layer. No System.String conversion is invented.', 'Factory construction, managed initializer effects, GC, allocation failures and unwinding remain unexecuted and unrecovered.'])
    destination(ROOT, ROOT / 'reports/exception-factory-abi-proposal-v37.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    destination(ROOT, ROOT / 'reports/exception-factory-abi-proposal-v37.md').write_text(
        '# Overflow factory ABI evidence\n\n'
        'Original helper0xB4D960 has an exact52-byte frame and matches the official2018.1.9f1 common-runtime declaration '
        '`Il2CppException* GetOverflowException(const char* msg)`. Its incoming X0 is the message pointer; incoming X1 is never read. '
        'The wrapper constructs namespace/type arguments internally and tail-calls the original exception factory.\n\n'
        'A narrow ABI-only correction may keep the numeric Call/result and sole X0 argument, allowing dead phantom-register uses to disappear. '
        'It must preserve the diagnostic, returned exception and separate throw. The source/native factory allocates, initializes and sets a message, '
        'with cleanup paths; translating or erasing it is outside this proposal.\n\n'
        'Thirteen static evidence checks pass. No original factory execution, Core edit, managed translation or full source readiness is claimed. '
        'The expected removal of the remaining Stream companion load needs a new production-stage/CIL result.\n', encoding='utf-8')
    print(json.dumps(dict(status=status, checks=len(checks), failures=sum(not value for value in checks.values()))))
    if not all(checks.values()):
        raise SystemExit(2)


if __name__ == '__main__':
    main()
