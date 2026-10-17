import importlib.util
from pathlib import Path
import struct
import unittest

spec=importlib.util.spec_from_file_location('native_unwind_inventory',Path(__file__).resolve().parents[1]/'src/re/tools/native_unwind_inventory.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class BytesImage:
    def __init__(self,data):self.data=data
    def read(self,address,count):
        if address<0 or address+count>len(self.data):raise ValueError('Outside fixture')
        return self.data[address:address+count]

class UnwindEncodingTests(unittest.TestCase):
    def cursor(self,data,start=0):return module.Cursor(BytesImage(data),start,len(data))
    def test_relative_pointer_uses_operand_address(self):
        cursor=self.cursor(b'xxxx'+struct.pack('<i',-3),4)
        self.assertEqual(cursor.encoded(0x1b),1)
    def test_table_pointer_uses_header_base(self):self.assertEqual(self.cursor(struct.pack('<i',-8)).encoded(0x3b,100),92)
    def test_unsigned_count(self):self.assertEqual(self.cursor(struct.pack('<I',152904)).encoded(3),152904)
    def test_leb_sign_and_continuation(self):
        self.assertEqual(self.cursor(bytes.fromhex('e58e26')).leb(),624485)
        self.assertEqual(self.cursor(bytes.fromhex('9bf159')).leb(True),-624485)
    def test_leb_overflow_and_truncation(self):
        for data in (b'\x80',b'\xff'*10+b'\0',b'\xff'*9+b'\x02'):
            with self.subTest(data=data),self.assertRaises(ValueError):self.cursor(data).leb()
    def test_pointer_modes_fail_closed(self):
        for encoding in (0xff,0x9b,0x2b,0x4b,0x5b,0x07,0x3b):
            with self.subTest(encoding=encoding),self.assertRaises(ValueError):self.cursor(b'\0'*8).encoded(encoding)
    def test_read_does_not_cross_record(self):
        with self.assertRaises(ValueError):self.cursor(b'\0\0').number('I')
    def test_cie_augmentation_encoding(self):
        payload=struct.pack('<I',0)+b'\x01zR\0\x01\x78\x1e\x01\x1b\x0c\x1f\0'
        image=BytesImage(struct.pack('<I',len(payload))+payload)
        row=module.cie(image,0,0,len(image.data))
        self.assertEqual((row['augmentation'],row['pointer_encoding'],row['code_alignment'],row['data_alignment'],row['return_register']),('zR',0x1b,1,-8,30))
    def test_invalid_cie_and_extended_record(self):
        for data in (struct.pack('<II',4,1),struct.pack('<I',0xffffffff)+b'\0'*12,struct.pack('<I',100)+b'\0'*8):
            with self.subTest(data=data),self.assertRaises(ValueError):module.cie(BytesImage(data),0,0,len(data))
    def frame_fixture(self,pc=0x100,size=16):
        cdata=struct.pack('<I',0)+b'\x01zR\0\x01\x78\x1e\x01\x1b\x0c\x1f\0'
        cie_data=struct.pack('<I',len(cdata))+cdata;address=len(cie_data);pc_field=address+8
        fdata=struct.pack('<IiiB',address+4,pc-pc_field,size,0)
        image=BytesImage(cie_data+struct.pack('<I',len(fdata))+fdata);image.segments=[(0,0x100,0x1000)]
        return image,address
    def test_fde_matches_search_entry_and_cie_relative_pc(self):
        image,address=self.frame_fixture();cache={};row=module.fde(image,address,0x100,0,len(image.data),cache)
        self.assertEqual((row['rva'],row['end_rva'],row['cie_rva']),(0x100,0x110,0))
        self.assertEqual(len(cache),1)
    def test_fde_rejects_disagreeing_or_unaligned_range(self):
        image,address=self.frame_fixture()
        with self.assertRaises(ValueError):module.fde(image,address,0x104,0,len(image.data),{})
        image,address=self.frame_fixture(size=15)
        with self.assertRaises(ValueError):module.fde(image,address,0x100,0,len(image.data),{})
    def test_mod0_backward_relative_offsets(self):
        raw=bytearray(128);struct.pack_into('<I',raw,4,96)
        struct.pack_into('<4s6i',raw,96,b'MOD0',0,0,0,-64,-44,0)
        struct.pack_into('<4Biiii',raw,32,1,0x1b,3,0x3b,16,1,-16,40)
        cdata=struct.pack('<I',0)+b'\x01zR\0\x01\x78\x1e\x01\x1b\x0c\x1f\0'
        raw[52:72]=struct.pack('<I',len(cdata))+cdata
        fdata=struct.pack('<IiiB',24,-64,16,0);raw[72:89]=struct.pack('<I',len(fdata))+fdata
        image=BytesImage(raw);image.segments=[(0,0,32),(32,32,96)]
        row=module.inventory(image)
        self.assertEqual((row['header_start'],row['validated_records'] if 'validated_records' in row else len(row['frames'])),(32,1))
        self.assertEqual(row['errors'],[])

if __name__=='__main__':unittest.main()
