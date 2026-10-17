import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('inspect_move_inheritance',Path(__file__).resolve().parents[1]/'src/re/tools/inspect_move_inheritance.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

def row(**attributes):return {'attributes':attributes}

class TemplateTests(unittest.TestCase):
    def test_multiple_parents_preserve_ambiguity(self):
        result=module.inspect({'templates':[row(Name='A',FileName='a.bytes'),row(Name='B',FileName='b.bytes')],
            'moves':[row(Name='M',Template='A|B')]})
        self.assertEqual(result['classification_counts'],{'AMBIGUOUS_FILES':1})
        self.assertEqual(result['moves_without_explicit_file'][0]['file_candidates'],['a.bytes','b.bytes'])
    def test_missing_parent_and_cycle_are_recorded(self):
        result=module.inspect({'templates':[row(Name='A',Template='B'),row(Name='B',Template='A')],
            'moves':[row(Name='M',Template='Unknown')]})
        self.assertTrue(result['cycles'])
        self.assertEqual(result['missing_template_references'],[{'owner':'M','missing':'Unknown'}])
    def test_physics_flag_does_not_invent_file(self):
        result=module.inspect({'templates':[row(Name='A',Physics='1')],'moves':[row(Name='M',Template='A')]})
        self.assertEqual(result['moves_without_explicit_file'][0]['file_candidates'],[])
        self.assertEqual(result['moves_without_explicit_file'][0]['observed_flags'],{'Physics':['1']})

if __name__=='__main__':unittest.main()
