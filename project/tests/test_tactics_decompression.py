import importlib.util
import lzma
from pathlib import Path
import struct
import unittest
spec=importlib.util.spec_from_file_location('recover_tactics',Path(__file__).resolve().parents[1]/'src/re/tools/recover_tactics.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

def compressed(data):
    return lzma.compress(data,format=lzma.FORMAT_ALONE)

class TacticsTests(unittest.TestCase):
    def test_complete_stream(self):
        data=struct.pack('<I',1)+b'Fists\0Knives\0'+bytes(range(64))
        self.assertEqual(module.decompress(compressed(data)),data)
        self.assertEqual(module.header(data)['weapon_identifiers'],['Fists','Knives'])
    def test_size_limit(self):
        data=compressed(b'0123456789')
        with self.assertRaises(ValueError):module.decompress(data,maximum=8)
    def test_trailing_stream_rejected(self):
        with self.assertRaises(ValueError):module.decompress(compressed(b'abc')+b'junk')
    def test_wrong_length_rejected(self):
        data=bytearray(compressed(b'abc'));struct.pack_into('<Q',data,5,2)
        with self.assertRaises((ValueError,lzma.LZMAError)):module.decompress(bytes(data))
    def test_missing_name_terminator(self):
        with self.assertRaises(ValueError):module.header(struct.pack('<I',1)+b'no_terminator')
    def test_version_two_has_one_weapon_identifier(self):
        result=module.header(struct.pack('<I',2)+b'Fists\0'+struct.pack('<I',300))
        self.assertEqual(result['weapon_identifiers'],['Fists'])

if __name__=='__main__':unittest.main()
