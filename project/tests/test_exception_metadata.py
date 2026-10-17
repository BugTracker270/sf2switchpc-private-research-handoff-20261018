"""Synthetic fixtures only: no proprietary input is needed for parser tests."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/tools'))
from exception_metadata import (Span, Cursor, MetadataError, UnsupportedMetadata, parse_lsda,
                                encoded_pointer, parse_cfi, CfiState, PointerValue, read_class_type_info)


def reader(data, base=0x2000):
    def read(address, size):
        if not base <= address <= address + size <= base + len(data):
            raise MetadataError('Synthetic memory read outside image')
        return bytes(data[address - base:address - base + size])
    return read


def fixture(rows=None):
    rows = rows or [(0x20, 8, 0x80, 3)]
    table = b''.join(struct.pack('<III', *row[:3]) + bytes([row[3]]) for row in rows)
    if len(table) >= 128:
        raise ValueError('Fixture uses one-byte table length')
    data = bytearray(b'\xff\x9c\x00\x03' + bytes([len(table)]) + table + b'\x00\x00\x01\x7d' + bytes(8))
    data[2] = len(data) - 3
    action = 5 + len(table)
    struct.pack_into('<q', data, action + 4, 0x3000 - (0x2000 + action + 4))
    return data, action


def parse(data, **kwargs):
    return parse_lsda(reader(data), Span(0x2000, 0x2000 + len(data)), Span(0x1000, 0x1100), **kwargs)


class LsdaTests(unittest.TestCase):
    def test_valid_typed_action_backlink_and_cleanup(self):
        data, action = fixture()
        result = parse(data)
        self.assertEqual((result.call_sites[0].start, result.call_sites[0].end, result.call_sites[0].landing), (0x1020, 0x1028, 0x1080))
        self.assertEqual([item.type_filter for item in result.action_chains[3]], [1, 0])
        self.assertEqual(result.action_chains[3][0].next_offset_base + result.action_chains[3][0].next_offset, 0x2000 + action)
        self.assertEqual(result.type_entries[1].reference, 0x3000)
        self.assertTrue(result.type_entries[1].indirect)

    def test_shared_action_chain_multiple_call_sites(self):
        data, _ = fixture([(0x20, 8, 0x80, 3), (0x40, 8, 0x90, 3)])
        self.assertEqual(len(parse(data).call_sites), 2)

    def test_zero_encoded_type_reference_is_catch_all_not_pc(self):
        data, action = fixture()
        data[action + 4:] = bytes(8)
        self.assertIsNone(parse(data).type_entries[1].reference)

    def test_cleanup_only_without_type_table(self):
        table = struct.pack('<III', 0x20, 8, 0x80) + b'\x01'
        data = b'\xff\xff\x03\x0d' + table + b'\x00\x00'
        result = parse(data)
        self.assertEqual(result.action_chains[1][0].type_filter, 0)
        self.assertFalse(result.type_entries)

    def test_no_landing_without_action(self):
        table = struct.pack('<III', 0, 0x100, 0) + b'\x00'
        result = parse(b'\xff\xff\x03\x0d' + table)
        self.assertIsNone(result.call_sites[0].landing)

    def test_truncated_header_and_table(self):
        data, _ = fixture()
        for length in (0, 1, 2, 4, 8, len(data) - 1):
            with self.subTest(length=length), self.assertRaises(MetadataError):
                parse(data[:length])

    def test_type_table_base_outside_metadata(self):
        data, _ = fixture()
        data[2] = 127
        with self.assertRaises(MetadataError): parse(data)

    def test_variable_width_type_encoding_unsupported(self):
        data, _ = fixture()
        data[1] = 0x91
        with self.assertRaises(UnsupportedMetadata): parse(data)

    def test_unknown_call_encoding_unsupported(self):
        data, _ = fixture()
        data[3] = 0x13
        with self.assertRaises(UnsupportedMetadata): parse(data)

    def test_range_outside_function(self):
        data, _ = fixture()
        struct.pack_into('<I', data, 5, 0x100)
        with self.assertRaises(MetadataError): parse(data)

    def test_zero_and_unaligned_ranges(self):
        for length in (0, 7):
            data, _ = fixture()
            struct.pack_into('<I', data, 9, length)
            with self.subTest(length=length), self.assertRaises(MetadataError): parse(data)

    def test_overlapping_or_unsorted_ranges(self):
        for second in (0x24, 0x10):
            data, _ = fixture([(0x20, 8, 0x80, 3), (second, 8, 0x90, 3)])
            with self.subTest(second=second), self.assertRaises(MetadataError): parse(data)

    def test_landing_outside_or_unaligned(self):
        for landing in (0x100, 0x81):
            data, _ = fixture()
            struct.pack_into('<I', data, 13, landing)
            with self.subTest(landing=landing), self.assertRaises(MetadataError): parse(data)

    def test_action_without_landing(self):
        data, _ = fixture()
        struct.pack_into('<I', data, 13, 0)
        with self.assertRaises(MetadataError): parse(data)

    def test_cyclic_action_chain(self):
        data, action = fixture()
        data[action + 3] = 0x7f
        with self.assertRaisesRegex(MetadataError, 'Cyclic'): parse(data)

    def test_action_offset_out_of_bounds(self):
        data, action = fixture()
        data[action + 3] = 0x70
        with self.assertRaises(MetadataError): parse(data)

    def test_action_records_overlap(self):
        data, action = fixture()
        data[action + 2], data[action + 3] = 0, 0x7e
        with self.assertRaises(MetadataError): parse(data)

    def test_typed_action_points_outside_type_table(self):
        data, action = fixture()
        data[action + 2] = 20
        with self.assertRaises(MetadataError): parse(data)

    def test_type_table_overlaps_action_record(self):
        data, action = fixture()
        data[2] -= 2
        data[action + 3] = 0
        data[action + 4:] = bytes(8)
        with self.assertRaisesRegex(MetadataError, 'overlaps allocated'): parse(data)

    def test_exception_specification_not_guessed(self):
        data, action = fixture()
        data[action + 2] = 0x7f
        with self.assertRaises(UnsupportedMetadata): parse(data)

    def test_configured_entry_chain_and_byte_limits(self):
        data, _ = fixture([(0x20, 8, 0x80, 3), (0x40, 8, 0x90, 3)])
        for options in ({'max_call_sites': 1}, {'max_chain': 1}, {'max_bytes': 4}):
            with self.subTest(options=options), self.assertRaises(MetadataError): parse(data, **options)

    def test_invalid_configuration_rejected(self):
        data, _ = fixture()
        for options in ({'max_call_sites': 0}, {'max_chain': -1}, {'max_bytes': 1.5}, {'code_alignment': '4'}):
            with self.subTest(options=options), self.assertRaises(MetadataError): parse(data, **options)


class CursorAndCfiTests(unittest.TestCase):
    def test_span_and_truncated_reader(self):
        with self.assertRaises(MetadataError): Span(-1, 0)
        with self.assertRaises(MetadataError): Span(0, 1 << 65)
        with self.assertRaises(MetadataError): Cursor(lambda at, size: b'', Span(0, 1)).take(1)

    def test_leb_64bit_overflow_and_truncation(self):
        for data, signed in ((b'\xff' * 10, False), (b'\x80' * 9 + b'\x02', True), (b'\x80', False)):
            with self.subTest(data=data), self.assertRaises(MetadataError):
                Cursor(reader(data, 0), Span(0, len(data))).leb(signed)

    def test_pc_relative_zero_and_address_overflow(self):
        zero = encoded_pointer(Cursor(reader(bytes(8)), Span(0x2000, 0x2008)), 0x9c)
        self.assertIsNone(zero.reference)
        data = struct.pack('<Q', (1 << 64) - 1)
        with self.assertRaises(MetadataError): encoded_pointer(Cursor(reader(data), Span(0x2000, 0x2008)), 0x14)

    def test_encoding_must_be_a_byte(self):
        for encoding in (-1, 0x19c, '0x9c'):
            with self.subTest(encoding=encoding), self.assertRaises(MetadataError):
                encoded_pointer(Cursor(reader(bytes(8)), Span(0x2000, 0x2008)), encoding)

    def test_cfi_cie_and_frame_state(self):
        cie = b'\x0c\x1f\x00'
        steps, state = parse_cfi(reader(cie), Span(0x2000, 0x2003), Span(0x1000, 0x1100))
        self.assertEqual((state.cfa_register, state.cfa_offset), (31, 0))
        fde = b'\x54\x0c\x1d\x10\x9e\x02\x9d\x04\x93\x06\x94\x08\x95\x0c\x00'
        steps, state = parse_cfi(reader(fde), Span(0x2000, 0x2000 + len(fde)), Span(0x1000, 0x1100), initial=state)
        self.assertEqual((state.cfa_register, state.cfa_offset), (29, 16))
        self.assertEqual(dict(state.saved), {19: -24, 20: -32, 21: -48, 29: -16, 30: -8})
        self.assertTrue(all(step.pc == 0x1014 for step in steps))

    def test_cfi_unknown_opcode_and_truncation(self):
        for data in (b'\x10', b'\x0c\x1f', b'\x0e\x80'):
            with self.subTest(data=data), self.assertRaises(MetadataError):
                parse_cfi(reader(data), Span(0x2000, 0x2000 + len(data)), Span(0x1000, 0x1100))

    def test_cfi_out_of_frame_register_and_stack_limits(self):
        for data, options in ((b'\x7f', {}), (b'\x0c\x20\x10', {}), (b'\x0c\x1f\x40', {'max_stack_offset': 16})):
            with self.subTest(data=data), self.assertRaises(MetadataError):
                parse_cfi(reader(data), Span(0x2000, 0x2000 + len(data)), Span(0x1000, 0x1020), **options)

    def test_initial_cfi_state_is_validated_even_for_empty_program(self):
        states = (CfiState(32, 0), CfiState(None, 0), CfiState(31, None), CfiState(31, -1),
                  CfiState(31, 0, ((19, -8), (19, -16))), CfiState(31, 0, ((32, 0),)),
                  CfiState(31, 0, ((19, -(1 << 21)),)), CfiState(31, 0, ((19,),)), 'bad-state')
        for initial in states:
            with self.subTest(initial=initial), self.assertRaises(MetadataError):
                parse_cfi(reader(b''), Span(0x2000, 0x2000), Span(0x1000, 0x1020), initial=initial)

    def test_cfi_initial_saved_register_container_is_validated(self):
        for saved in (None, [], {}, ''):
            with self.subTest(saved=saved), self.assertRaisesRegex(MetadataError, 'saved-register container'):
                parse_cfi(reader(b''), Span(0x2000, 0x2000), Span(0x1000, 0x1020), initial=CfiState(31, 0, saved))

    def test_cfi_invalid_configuration_and_undefined_cfa_updates(self):
        for options in ({'max_steps': 0}, {'max_register': 32}, {'max_stack_offset': -1}, {'code_alignment': '1'}, {'data_alignment': 0}):
            with self.subTest(options=options), self.assertRaises(MetadataError):
                parse_cfi(reader(b''), Span(0x2000, 0x2000), Span(0x1000, 0x1020), **options)
        for data in (b'\x0d\x1f', b'\x0e\x08'):
            with self.subTest(data=data), self.assertRaises(MetadataError):
                parse_cfi(reader(data), Span(0x2000, 0x2000 + len(data)), Span(0x1000, 0x1020))

    def test_valid_empty_cfi_preserves_initial_state(self):
        initial = CfiState(31, 0, ((19, -8),))
        steps, state = parse_cfi(reader(b''), Span(0x2000, 0x2000), Span(0x1000, 0x1020), initial=initial)
        self.assertEqual(steps, ())
        self.assertEqual(state, initial)


class RttiTests(unittest.TestCase):
    def resolve(self, address):
        return PointerValue(16, '_ZTVN10__cxxabiv117__class_type_infoE', 16) if address == 0x2000 else PointerValue(0x3000)

    def test_bounded_simple_class_info_preserves_raw_native_name(self):
        data = b'22Il2CppExceptionWrapper\x00'
        result = read_class_type_info(reader(data, 0x3000), Span(0x2000, 0x2010), Span(0x3000, 0x3000 + len(data)), self.resolve)
        self.assertEqual(result.name, '22Il2CppExceptionWrapper')

    def test_wrong_vtable_is_not_treated_as_class_info(self):
        with self.assertRaises(UnsupportedMetadata):
            read_class_type_info(reader(b'x\0', 0x3000), Span(0x2000, 0x2010), Span(0x3000, 0x3002), lambda at: PointerValue(0))

    def test_unterminated_nonascii_and_out_of_bounds_names(self):
        for data in (b'abc', b'\xff\0', b''):
            with self.subTest(data=data), self.assertRaises(MetadataError):
                read_class_type_info(reader(data, 0x3000), Span(0x2000, 0x2010), Span(0x3000, 0x3000 + len(data)), self.resolve)

    def test_imported_name_and_short_object_unsupported(self):
        with self.assertRaises(MetadataError):
            read_class_type_info(reader(b'x\0', 0x3000), Span(0x2000, 0x2008), Span(0x3000, 0x3002), self.resolve)
        with self.assertRaises(UnsupportedMetadata):
            read_class_type_info(reader(b'x\0', 0x3000), Span(0x2000, 0x2010), Span(0x3000, 0x3002),
                lambda at: self.resolve(at) if at == 0x2000 else PointerValue(None, 'unresolved_name'))

    def test_invalid_name_limit(self):
        for limit in (0, 4097, '256'):
            with self.subTest(limit=limit), self.assertRaises(MetadataError):
                read_class_type_info(reader(b'x\0', 0x3000), Span(0x2000, 0x2010), Span(0x3000, 0x3002), self.resolve, max_name_bytes=limit)


if __name__ == '__main__':
    unittest.main()
