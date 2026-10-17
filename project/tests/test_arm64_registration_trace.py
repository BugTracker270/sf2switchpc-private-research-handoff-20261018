import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('trace_registrations',Path(__file__).resolve().parents[1]/'src/re/tools/trace_registrations.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class Arm64TraceTests(unittest.TestCase):
    def test_sign_extension(self):
        self.assertEqual(module.signed(0x3ffffff,26),-1)
        self.assertEqual(module.signed(1,26),1)
    def test_adrp_zero_and_negative_page(self):
        self.assertEqual(module.adrp_target(0x90000000,0x1234),0x1000)
        self.assertEqual(module.adrp_target(0xf0ffffe1,0x2004),0x1000)
        self.assertIsNone(module.adrp_target(0xd503201f,0x2000))
    def test_add_and_page_shift(self):
        self.assertEqual(module.add_immediate(0x91084000),(0,0,0x210))
        self.assertEqual(module.add_immediate(0x91400421),(1,1,4096))
        self.assertIsNone(module.add_immediate(0xd65f03c0))

if __name__=='__main__':unittest.main()
