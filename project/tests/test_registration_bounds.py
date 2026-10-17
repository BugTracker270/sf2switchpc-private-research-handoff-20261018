import importlib.util
from pathlib import Path
import struct
import unittest
spec=importlib.util.spec_from_file_location('verify_registration_tables',Path(__file__).resolve().parents[1]/'src/re/tools/verify_registration_tables.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

def image():
    data=bytearray(304);data[:4]=b'NSO0'
    for header,file_offset,rva in [(0x10,256,0),(0x20,272,0x1000),(0x30,288,0x2000)]:
        struct.pack_into('<III',data,header,file_offset,rva,16)
    struct.pack_into('<I',data,0x3c,16)
    struct.pack_into('<Q',data,272,0x2008)
    return data

class RegistrationBoundsTests(unittest.TestCase):
    def test_pointer_table(self):
        reader=module.Image(image())
        self.assertEqual(reader.pointers(0x1000,1),[0x2008])
        self.assertTrue(reader.executable(12));self.assertFalse(reader.executable(16))
    def test_bss_is_memory_but_not_file_backed(self):
        reader=module.Image(image());self.assertTrue(reader.writable(0x2018))
        with self.assertRaises(ValueError):reader.read(0x2018,8)
    def test_cross_segment_and_large_count_rejected(self):
        reader=module.Image(image())
        with self.assertRaises(ValueError):reader.read(0x1008,16)
        with self.assertRaises(ValueError):reader.pointers(0x1000,10000001)
    def test_bad_file_extent_rejected(self):
        data=image();struct.pack_into('<I',data,0x18,100000)
        with self.assertRaises(ValueError):module.Image(data)

if __name__=='__main__':unittest.main()
