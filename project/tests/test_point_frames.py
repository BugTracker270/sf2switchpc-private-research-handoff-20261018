from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'/'re'/'tools'))
from catalog_game_content import decode_point_frames,looks_xml

class PointFrameTests(unittest.TestCase):
    def fixture(self):return struct.pack('<iBi3fBi3f',2,1,1,1.,2.,3.,1,1,4.,5.,6.)
    def test_exact_frame_counts(self):self.assertEqual(decode_point_frames(self.fixture())['frames'],2)
    def test_truncated(self):
        for size in (0,3,4,8,len(self.fixture())-1):
            with self.subTest(size=size),self.assertRaises(ValueError):decode_point_frames(self.fixture()[:size])
    def test_trailing_data(self):
        with self.assertRaises(ValueError):decode_point_frames(self.fixture()+b'X')
    def test_nonfinite(self):
        data=bytearray(self.fixture());struct.pack_into('<f',data,9,float('nan'))
        with self.assertRaises(ValueError):decode_point_frames(data)
    def test_sixty_frames_is_binary_not_xml(self):
        frame=struct.pack('<Bi3f',1,1,1.,2.,3.)
        data=struct.pack('<i',60)+frame*60
        self.assertFalse(looks_xml(data))
        self.assertEqual(decode_point_frames(data)['frames'],60)

if __name__=='__main__':unittest.main()
