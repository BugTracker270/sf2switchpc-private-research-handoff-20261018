import math
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/re/tools'))
from decode_ai_tables import Cursor,parse_archive,parse_holder,parse_shift

def names(kind,values):
    raw=[s.encode('ascii') for s in values]
    return struct.pack('<'+kind,len(raw))+bytes(map(len,raw))+b''.join(raw)

def holder():
    # One table/frame/interval, two ordered distance boundaries, one iframe.
    return (names('H',['Idle','Kick'])+names('h',['Fist'])+
        struct.pack('<7I',1,1,1,1,1,2,1)+struct.pack('<Hh2hiH',0,2,-10,20,9,1)+
        struct.pack('<3H',1,0,1)+b'result\0'+struct.pack('<Hh3H',1,5,1,2,1))

class AiTablesTests(unittest.TestCase):
    def test_complete_nested_schema_and_values(self):
        row=parse_holder(holder(),True)
        table=row['entries'][0]['groups'][0]['tables'][0]
        self.assertEqual(table['first_frame'],5)
        self.assertEqual(table['frames'],[[dict(animation='Kick',distances=[-20.0,40.0],interframes=[9])]])
    def test_truncated_nested_fields_rejected(self):
        raw=holder()
        for end in range(len(raw)):
            with self.assertRaises((ValueError,UnicodeDecodeError),msg=str(end)):parse_holder(raw[:end])
    def test_pool_overclaim_rejected(self):
        raw=bytearray(holder());start=len(names('H',['Idle','Kick'])+names('h',['Fist']))
        struct.pack_into('<I',raw,start+4,2)
        with self.assertRaisesRegex(ValueError,'Pool groups'):parse_holder(raw)
    def test_dictionary_index_rejected(self):
        raw=bytearray(holder());start=len(names('H',['Idle','Kick'])+names('h',['Fist']))+28
        struct.pack_into('<H',raw,start,2)
        with self.assertRaisesRegex(ValueError,'Index'):parse_holder(raw)
    def test_trailing_data_rejected(self):
        with self.assertRaisesRegex(ValueError,'Unconsumed'):parse_holder(holder()+b'\0')
    def test_archive_has_multiple_table_types(self):
        raw=b''.join(struct.pack('<I',t)+b'A\0B\0'+struct.pack('<I',len(holder()))+holder() for t in [1,0])
        blocks=parse_archive(raw,2)
        self.assertEqual([b['table_type'] for b in blocks],[1,0])
        self.assertEqual(blocks[1]['offset'],len(raw)//2)
    def test_archive_wrong_name_count_rejected(self):
        raw=struct.pack('<I',1)+b'A\0B\0'+struct.pack('<I',len(holder()))+holder()
        with self.assertRaises(ValueError):parse_archive(raw,1)
    def test_shift_float_grid(self):
        payload=struct.pack('<I',2)+b'Left\0Right\0'+struct.pack('<4f',1,2,3,4)
        raw=struct.pack('<I',1)+b'Kick\0'+struct.pack('<I',len(payload))+payload
        row=parse_shift(raw,True)['animations'][0]
        self.assertEqual(row,dict(animation='Kick',nodes=['Left','Right'],frames=2,values=[1,2,3,4]))
    def test_shift_nonfinite_and_dimension_errors(self):
        for values in [struct.pack('<f',math.nan),b'\0']:
            payload=struct.pack('<I',1)+b'Node\0'+values
            raw=struct.pack('<I',1)+b'Kick\0'+struct.pack('<I',len(payload))+payload
            with self.assertRaises(ValueError):parse_shift(raw)
    def test_unterminated_string_and_negative_count(self):
        with self.assertRaisesRegex(ValueError,'Unterminated'):Cursor(b'abc').zero_string()
        with self.assertRaisesRegex(ValueError,'Negative'):Cursor(b'\xff\xff').names('h')

if __name__=='__main__':unittest.main()
