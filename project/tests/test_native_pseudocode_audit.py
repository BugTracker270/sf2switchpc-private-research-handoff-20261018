import importlib.util
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/'src/re/tools/audit_native_pseudocode.py'
spec=importlib.util.spec_from_file_location('native_pseudocode_audit',path)
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)

class NativePseudocodeAuditTests(unittest.TestCase):
    def test_partial_success_is_visible(self):
        row={'status':'PSEUDOCODE_EXPORTED','pseudocode':'/* WARNING: Bad instruction */\nhalt_baddata();'}
        result=audit.observations(row)
        self.assertEqual(result['markers']['bad_instruction_or_data'],2)
        self.assertEqual(result['markers']['warning_comments'],1)

    def test_listing_bounds_are_half_open(self):
        row={'assembly':'7100000100\t00000000\tnop\n7100000104\t00000000\tnop\n7100000108\t00000000\tret\n'}
        result=audit.observations(row,(0x100,0x108))
        self.assertEqual(result['listing_instructions'],3)
        self.assertEqual(result['listing_outside_frame'],1)
        self.assertEqual(result['outside_examples'],['0x108'])

    def test_no_frame_does_not_invent_a_boundary_failure(self):
        self.assertEqual(audit.observations({'assembly':'7100000100\t00000000\tret\n'})['listing_outside_frame'],0)
