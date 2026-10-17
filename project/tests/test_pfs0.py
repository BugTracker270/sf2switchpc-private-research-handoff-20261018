import io
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'/'tools'))
from inspect_pfs0 import parse_pfs0, inspect_nca_header
from usb_boundary import destination

def fixture(names=('a.nca',),bodies=(b'test',)):
    strings=b''
    table=b''
    offset=0
    for name,body in zip(names,bodies):
        table+=struct.pack('<QQII',offset,len(body),len(strings),0)
        strings+=name.encode()+b'\0'
        offset+=len(body)
    return struct.pack('<4sIII',b'PFS0',len(names),len(strings),0)+table+strings+b''.join(bodies)

class ContainerTests(unittest.TestCase):
    def parse(self,data): return parse_pfs0(io.BytesIO(data),len(data))
    def test_valid_offsets(self):
        data=fixture()
        entry=self.parse(data)['entries'][0]
        self.assertEqual(data[entry['offset']:],b'test')
    def test_multiple_entries(self): self.assertEqual(self.parse(fixture(('a','b'),(b'xx',b'yyy')))['file_count'],2)
    def test_bad_magic(self):
        with self.assertRaises(ValueError): self.parse(b'FAIL'+fixture()[4:])
    def test_truncated(self):
        for length in (0,15,20,len(fixture())-1):
            with self.subTest(length=length),self.assertRaises(ValueError): self.parse(fixture()[:length])
    def test_unsafe_names(self):
        for name in ('../escape','a/b','a\\b','file:stream','CON.txt','NUL','trailing.','..'):
            with self.subTest(name=name),self.assertRaises(ValueError): self.parse(fixture((name,)))
    def test_duplicate_names(self):
        with self.assertRaises(ValueError): self.parse(fixture(('A','a'),(b'a',b'b')))
    def test_overlap(self):
        data=bytearray(fixture(('a','b'),(b'aa',b'bb')))
        struct.pack_into('<Q',data,40,0)
        with self.assertRaises(ValueError): self.parse(data)
    def test_unterminated_string(self):
        data=bytearray(fixture());data[-5]=65
        with self.assertRaises(ValueError): self.parse(data)
    def test_encrypted_header_unknown(self): self.assertEqual(inspect_nca_header(io.BytesIO(b'\0'*0x400),0,0x400)['content_type'],'UNKNOWN')
    def test_plaintext_header(self):
        data=bytearray(0x400);data[0x200:0x204]=b'NCA3';data[0x205]=0
        self.assertEqual(inspect_nca_header(io.BytesIO(data),0,len(data))['content_type'],'Program')
    def test_output_boundary(self):
        root=Path(__file__).resolve().parents[1]
        self.assertEqual(destination(root,root/'reports'/'safe.json'),root/'reports'/'safe.json')
        for path in (root,root.parent/'bad',root/'..'/'escape',root/'cache'/'file:stream'):
            with self.subTest(path=path),self.assertRaises(ValueError): destination(root,path)

if __name__=='__main__': unittest.main()
