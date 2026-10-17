import io
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'/'re'/'tools'))
from unity_v17_manifest import parse,text_payload

def sample():
    metadata=bytearray(b'2018.1.9f1\0'+struct.pack('<i?i',38,False,1))
    metadata+=struct.pack('<i?h',49,False,-1)+bytes(16)+struct.pack('<i',1)
    while (20+len(metadata))%4:metadata+=b'\0'
    payload=struct.pack('<i',4)+b'test'+struct.pack('<i',3)+b'abc'+b'\0'
    metadata+=struct.pack('<qIIi',7,0,len(payload),0)+struct.pack('<ii',0,0)+b'\0'
    while (20+len(metadata))%4:metadata+=b'\0'
    offset=20+len(metadata)
    return struct.pack('>IIII',len(metadata),offset+len(payload),17,offset)+bytes(4)+metadata+payload

class UnityManifestTests(unittest.TestCase):
    def test_object_offsets_and_text_bytes(self):
        data=sample();stream=io.BytesIO(data);report=parse(stream,len(data))
        self.assertEqual(report['objects'][0]['path_id'],7)
        name,offset,size=text_payload(stream,report['objects'][0],'<')
        self.assertEqual((name,data[offset:offset+size]),('test',b'abc'))
    def test_truncation(self):
        data=sample()
        with self.assertRaises(ValueError):parse(io.BytesIO(data[:-1]),len(data)-1)
    def test_unsupported_version(self):
        data=bytearray(sample());struct.pack_into('>I',data,8,22)
        with self.assertRaises(ValueError):parse(io.BytesIO(data),len(data))
    def test_object_bounds(self):
        data=bytearray(sample());where=data.index(struct.pack('<qIIi',7,0,16,0))
        struct.pack_into('<I',data,where+8,99999999)
        with self.assertRaises(ValueError):parse(io.BytesIO(data),len(data))

if __name__=='__main__':unittest.main()
