import importlib.util
from pathlib import Path
import struct
import sys
import unittest

path=Path(__file__).resolve().parents[1]/'src/re/tools/audit_native_text_partition.py'
sys.path.insert(0,str(path.parent))
spec=importlib.util.spec_from_file_location('text_partition',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class NativeTextPartitionTests(unittest.TestCase):
    def test_exact_conservation_and_exclusive_ends(self):
        rows=module.partition(0,32,[(4,12,'FDE'),(16,24,'PLT')])
        self.assertEqual(rows,[(0,4,'RESIDUAL'),(4,12,'FDE'),(12,16,'RESIDUAL'),(16,24,'PLT'),(24,32,'RESIDUAL')])

    def test_invalid_inventory_is_rejected(self):
        for rows in ([(0,8,'FDE'),(4,12,'PLT')],[(0,20,'FDE')],[(4,4,'FDE')],[(-4,4,'FDE')]):
            with self.assertRaises(ValueError):module.partition(0,16,rows)

    def test_word_observations_do_not_drop_other_bytes(self):
        result=module.words(struct.pack('<IIII',0,0xd503201f,0,0xe7ffdefe))
        self.assertEqual((result['zero_bytes'],result['nop_bytes'],result['other_bytes']),(8,4,4))
        with self.assertRaises(ValueError):module.words(b'abc')
