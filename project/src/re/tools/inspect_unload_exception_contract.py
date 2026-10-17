"""Read original UnloadDependencies LSDA actions, RTTI/import identity and bounded CFI."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination
from native_unwind_inventory import Image
from exception_metadata import Span, parse_lsda, parse_cfi, PointerValue, read_class_type_info


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    raw = source.read_bytes()
    if digest(raw) != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original native source differs')
    image = Image(raw)
    witness = json.loads((ROOT / 'analysis/reconstruction/class-guard-cfg-v35/native-witness.json').read_text())
    method = next(row for row in witness['methods'] if row['name'] == 'BundlesUtil::UnloadDependencies')
    frame, cie, lsda = method['exact_frame'], method['cie'], method['exception_call_site_inventory']
    module = struct.unpack('<I', image.read(4, 4))[0]
    dynamic = module + struct.unpack('<i', image.read(module + 4, 4))[0]
    tags = {}
    for index in range(4096):
        tag, value = struct.unpack('<qQ', image.read(dynamic + index * 16, 16))
        if tag == 0:
            break
        tags[tag] = value
    else:
        raise ValueError('Unterminated bounded dynamic table')
    ro_file, ro_rva, _ = image.segments[1]
    strings_relative, strings_size = struct.unpack_from('<II', raw, 0x90)
    symbols_relative, symbols_size = struct.unpack_from('<II', raw, 0x98)
    strings = raw[ro_file + strings_relative:ro_file + strings_relative + strings_size]
    def symbol(index):
        if not 0 <= index * 24 < symbols_size:
            raise ValueError('Symbol index out of original table')
        at = ro_rva + symbols_relative + index * 24
        name, info, other, section, value, size = struct.unpack('<IBBHQQ', image.read(at, 24))
        end = strings.find(b'\0', name)
        if not 0 <= name <= end < len(strings):
            raise ValueError('Symbol name out of original table')
        return dict(index=index, name=strings[name:end].decode(), section=section, value=hex(value), size=size)
    relocations = {}
    for address_tag, size_tag in ((7, 8), (23, 2)):
        start, length = tags.get(address_tag, 0), tags.get(size_tag, 0)
        if length % 24:
            raise ValueError('Unreviewed relocation layout')
        for offset in range(0, length, 24):
            address, info, addend = struct.unpack('<QQq', image.read(start + offset, 24))
            record = dict(address=hex(address), kind=info & 0xFFFFFFFF, addend=addend,
                          symbol=symbol(info >> 32) if info >> 32 else None)
            if address in relocations and relocations[address] != record:
                raise ValueError('Conflicting relocation records')
            relocations[address] = record
    def pointer(address):
        value = struct.unpack('<Q', image.read(address, 8))[0]
        relocation = relocations.get(address)
        if relocation and relocation['kind'] == 1027:
            if value not in (0, relocation['addend']):
                raise ValueError('Raw pointer and relative relocation disagree')
            value = relocation['addend']
        return dict(address=hex(address), raw_or_relative_value=hex(value), relocation=relocation)
    def resolved_pointer(address):
        record = pointer(address)
        relocation = record['relocation']
        if relocation and relocation['kind'] in (257, 1026) and relocation['symbol'] and relocation['symbol']['section'] == 0:
            return PointerValue(None, relocation['symbol']['name'], relocation['addend'])
        if relocation and relocation['kind'] != 1027:
            raise ValueError('Pointer relocation outside reviewed direct/relative/import subset')
        return PointerValue(int(record['raw_or_relative_value'], 16))
    parsed = parse_lsda(image.read, Span(0x2FE4DA8, 0x2FE4DFC), Span(frame['rva'], frame['end_rva']))
    parsed_sites = [dict(start=hex(row.start), end=hex(row.end), landing=hex(row.landing) if row.landing else None,
                         action=row.action) for row in parsed.call_sites]
    if (parsed_sites != lsda['call_sites'] or parsed.call_site_table != Span(int(lsda['table_start'], 16), int(lsda['table_end'], 16))
            or parsed.type_table != int(lsda['type_table'], 16) or parsed.type_encoding != lsda['type_encoding']
            or digest(image.read(parsed.call_site_table.start, parsed.call_site_table.end - parsed.call_site_table.start)) != lsda['table_sha256']):
        raise ValueError('Reusable LSDA parser disagrees with independent original inventory')
    def type_entry(index, encoded):
        if encoded.encoding != 0x9C or not encoded.indirect:
            raise ValueError('Only original indirect PC-relative sdata8 type table reviewed')
        slot = encoded.reference
        record = dict(index=index, encoded_at=hex(encoded.field_address), displacement=encoded.raw_value,
                      indirect_slot=hex(slot) if slot else None)
        if slot:
            resolved = pointer(slot)
            record['slot_pointer'] = resolved
            value = resolved_pointer(slot)
            if value.symbol is not None or value.value is None or value.value == 0:
                raise ValueError('Original wrapper RTTI does not resolve to a direct object')
            info = read_class_type_info(image.read, Span(value.value, value.value + 16),
                                        Span(ro_rva, ro_rva + image.segments[1][2]), resolved_pointer)
            record['rtti_vtable'] = pointer(value.value)
            record['rtti_name_pointer'] = pointer(value.value + 8)
            record['rtti_name'] = info.name
        return record
    actions = {entry: [dict(address=hex(row.address), type_filter=row.type_filter, next_offset=row.next_offset,
                            next_offset_base=hex(row.next_offset_base)) for row in chain]
               for entry, chain in parsed.action_chains.items()}
    types = {index: type_entry(index, encoded) for index, encoded in parsed.type_entries.items()}
    entries = json.loads((ROOT / 'analysis/nso/validated-plt-entries.json').read_text())
    plt = {row['rva']: row for row in entries}
    imports = {}
    for address in (0x2373038, 0x2373048, 0x2373058):
        got = plt[address]['got_rva']
        relocation = relocations.get(got)
        imports[hex(address)] = dict(got_rva=hex(got), relocation=relocation)
    cfi_rows = []
    state = None
    for label, start, end in (('CIE', cie['cfi_start'], cie['end_rva']), ('FDE', frame['cfi_start'], frame['fde_end_rva'])):
        steps, state = parse_cfi(image.read, Span(start, end), Span(frame['rva'], frame['end_rva']), initial=state,
                                 code_alignment=cie['code_alignment'], data_alignment=cie['data_alignment'])
        cfi_rows.extend(dict(record=label, at=hex(row.address), effective_pc=hex(row.pc), operation=row.operation,
                             state=dict(cfa_register=row.state.cfa_register, cfa_offset=row.state.cfa_offset,
                                        saved=dict(row.state.saved))) for row in steps)
    report = dict(status='READ_ONLY_BOUNDED_LSDA_ACTION_RTTI_IMPORT_AND_CFI_EVIDENCE', original_native_sha256=digest(raw),
        exact_frame=frame, lsda=lsda, action_chains=actions, types=types, plt_imports=imports,
        personality_slot=pointer(cie['personality']['reference']), cfi_rows=cfi_rows,
        raiser_rtti_slot=pointer(0x397B170),
        private_original_instructions=method['instructions'],
        source_modified=False, core_modified=False, native_or_managed_execution_performed=False,
        probe_source_sha256=digest(Path(__file__).read_bytes()),
        reusable_parser_sha256=digest((ROOT / 'src/tools/exception_metadata.py').read_bytes()),
        reusable_parser_original_lsda_agrees_with_independent_inventory=True)
    output = destination(ROOT, ROOT / 'analysis/reconstruction/unload-exception-contract-v35/native-evidence.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'action_chains', 'types', 'plt_imports', 'personality_slot', 'raiser_rtti_slot', 'cfi_rows')}))


if __name__ == '__main__':
    main()
