"""Correlate an exact original boxing argument with independent metadata output."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def main():
    path = ROOT / 'reports/scalar-boxing-metadata-v30.json'
    raw_report = path.read_bytes()
    metadata = json.loads(raw_report)
    if (metadata['status'] != 'SCALAR_BOXING_METADATA_OBSERVATIONS_ONLY'
            or metadata['binary_sha256'] != '94af5c70b20f0ae063c640b83578100459050f68f520088a9eb2e2aea234f238'
            or metadata['metadata_sha256'] != 'f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85'):
        raise ValueError('Original metadata report differs')
    caller = metadata['selected_caller']
    if caller['type'] != 'FyberPlugin.User' or caller['name'] != 'SetAge' or caller['underlying_pointer'] != '0xF230F0':
        raise ValueError('Selected caller differs')
    calls = caller['unresolved_box_calls']
    if len(calls) != 1 or calls[0]['arguments'][:2] != [
        dict(kind='TypeAnalysisContext', type='System.Int32', address_of_type=None),
        dict(kind='AddressOf', type=None, address_of_type='System.Int32'),
    ]:
        raise ValueError('Selected class and typed source-address identities differ')
    primitive = next(row for row in metadata['primitives'] if row['type'] == 'System.Int32')
    if (not primitive['value_type'] or primitive['instance_size'] != 20 or primitive['native_size'] != 4
            or primitive['has_static_constructor']):
        raise ValueError('Actual primitive layout or initialization differs')
    binary = (ROOT / 'analysis/nso/main-uncompressed.nso').read_bytes()
    binary_hash = hashlib.sha256(binary).hexdigest()
    if binary_hash != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original native input differs')
    window = binary[0x100 + 0xF23130:0x100 + 0xF23148]
    if (window.hex() != 'f30f00b9a85201d008d545f9000140f9e1330091cbdff097'
            or binary[0x100 + 0xF23110:0x100 + 0xF23114].hex() != 'f303012a'):
        raise ValueError('Original argument copy/type slot/boxing call witness differs')
    report = dict(status='PASS_SCOPED_NATIVE_BOX_ARGUMENT_TYPE_PROVENANCE',
        caller='FyberPlugin.User::SetAge(System.Int32)', caller_rva='0xF230F0', boxing_call_rva='0xF23144',
        native_source_sha256=binary_hash, native_input_window_sha256=hashlib.sha256(window).hexdigest(),
        metadata_observation_sha256=hashlib.sha256(raw_report).hexdigest(), metadata_observation_source=str(path.relative_to(ROOT)),
        selected_native_type='System.Int32', selected_typed_source_address='System.Int32',
        input_provenance='native W1 -> W19 -> [SP+0xC]; X1 points to that same four-byte source slot at the boxing call',
        native_type_info_slot='0x3979BA8', primitive_value_type=True, primitive_boxed_size=20,
        primitive_payload_size=4, primitive_has_static_constructor=False, original_native_executed=False,
        whole_game_source_ready=False,
        scope='Static correlation of exact unchanged native instructions with the independent pre-lowering Cpp2IL metadata/operand observations for one boxing call. This establishes the selected primitive class and typed payload-address provenance; it does not execute native allocation/GC or prove recovered operand copy semantics, which require the separate recovered-expression test.')
    destination(ROOT, ROOT / 'reports/boxing-input-provenance-v29.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
