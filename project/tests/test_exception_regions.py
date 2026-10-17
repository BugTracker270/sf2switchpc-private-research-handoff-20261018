"""Synthetic structural plans; no game, Core, native unwinder or CIL execution."""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/tools'))
from exception_regions import (Node, NormalTransfer as N, ExceptionalTransfer as E, FinallyEntry,
                               Region, Plan, RegionError, validate, clone_plan)


def fixture():
    nodes = (Node('acquire', 'call', may_throw=True, normal_result='enumerator'), Node('pre', 'nop'),
             Node('next', 'call', 0, 1, True, 'condition'), Node('test', 'brtrue', 1, 0),
             Node('leave', 'leave'), Node('current', 'call', 0, 1, True, 'item'),
             Node('unload', 'call', 1, 0, True), Node('loop', 'br'), Node('dispose', 'call', may_throw=True),
             Node('end', 'endfinally'), Node('clear', 'call', may_throw=True), Node('return', 'ret'))
    normal = (N('acquire', 'pre', 'fallthrough'), N('pre', 'next', 'fallthrough'), N('next', 'test', 'fallthrough'),
              N('test', 'current', 'branch'), N('test', 'leave', 'branch'), N('leave', 'clear', 'leave'),
              N('current', 'unload', 'fallthrough'), N('unload', 'loop', 'fallthrough'), N('loop', 'next', 'branch'),
              N('dispose', 'end', 'fallthrough'), N('clear', 'return', 'fallthrough'))
    entry = FinallyEntry(storage_ids=('enumerator',))
    return Plan(nodes, normal, tuple(E(source, 'dispose', entry) for source in ('next', 'current', 'unload')),
                (Region('next', 'dispose', 'dispose', 'clear'),), 'acquire', ('enumerator',))


def node_change(plan, original_key, **kwargs):
    return replace(plan, nodes=tuple(replace(row, **kwargs) if row.key == original_key else row for row in plan.nodes))


class RegionPlanTests(unittest.TestCase):
    def test_valid_plan_keeps_handler_separate_from_normal_reachability(self):
        plan = fixture()
        proof = validate(plan)
        self.assertNotIn('dispose', proof.normal_reachable)
        self.assertNotIn('end', proof.normal_reachable)
        self.assertEqual(proof.handler_only_reachable, ('dispose', 'end'))
        self.assertEqual(proof.retained, tuple(node.key for node in plan.nodes))
        self.assertEqual(proof.leave_dispatches, (('leave', 'dispose', 'clear'),))
        self.assertEqual(len(proof.exceptional_dispatches), 3)
        self.assertFalse(proof.production_eh_ready)

    def test_leave_keeps_finally_even_without_a_throwing_protected_call(self):
        plan = fixture()
        for key in ('next', 'current', 'unload'):
            plan = node_change(plan, key, may_throw=False)
        proof = validate(replace(plan, exceptional=()))
        self.assertEqual(proof.handler_roots, ('dispose',))
        self.assertEqual(proof.handler_only_reachable, ('dispose', 'end'))

    def test_clone_has_fresh_nodes_edges_entries_and_unchanged_anchors(self):
        plan = fixture()
        before = repr(plan)
        cloned = clone_plan(plan)
        self.assertEqual(cloned, plan)
        self.assertEqual(validate(cloned), validate(plan))
        self.assertTrue(all(left is not right for left, right in zip(plan.nodes, cloned.nodes)))
        self.assertTrue(all(left is not right for left, right in zip(plan.normal, cloned.normal)))
        self.assertTrue(all(left.entry is not right.entry for left, right in zip(plan.exceptional, cloned.exceptional)))
        self.assertIsNot(plan.regions[0], cloned.regions[0])
        self.assertEqual(repr(plan), before)

    def test_model_and_container_are_immutable(self):
        plan = fixture()
        with self.assertRaises(FrozenInstanceError): plan.nodes[0].op = 'ret'
        with self.assertRaises(RegionError): validate(replace(plan, nodes=list(plan.nodes)))

    def test_all_collection_shapes_are_validated_before_use(self):
        plan = fixture()
        for field in ('nodes', 'normal', 'exceptional', 'regions', 'storage_ids'):
            with self.subTest(field=field), self.assertRaisesRegex(RegionError, 'immutable tuples'):
                validate(replace(plan, **{field: None}))

    def test_finally_entry_collection_shapes_are_validated(self):
        plan = fixture()
        for field in ('evaluation_stack', 'visible_values', 'storage_ids'):
            edge = replace(plan.exceptional[0], entry=replace(plan.exceptional[0].entry, **{field: None}))
            with self.subTest(field=field), self.assertRaisesRegex(RegionError, 'immutable tuples'):
                validate(replace(plan, exceptional=(edge,) + plan.exceptional[1:]))

    def test_native_or_inferred_production_input_is_rejected(self):
        for kind in ('native', 'recovered', 'managed_wrapper_nonnull'):
            with self.subTest(kind=kind), self.assertRaises(RegionError): validate(replace(fixture(), source_kind=kind))

    def test_duplicate_or_reserved_instruction_identities(self):
        for key in ('next', '$end', ''):
            with self.subTest(key=key), self.assertRaises(RegionError): validate(node_change(fixture(), 'pre', key=key))

    def test_multiple_nested_or_overlapping_regions_reject(self):
        plan = fixture()
        for region in (plan.regions[0], Region('current', 'loop', 'loop', 'end')):
            with self.subTest(region=region), self.assertRaises(RegionError):
                validate(replace(plan, regions=plan.regions + (region,)))

    def test_empty_or_overlapping_single_region(self):
        plan = fixture()
        for region in (Region('next', 'next', 'dispose', 'clear'), Region('next', 'end', 'dispose', 'clear')):
            with self.subTest(region=region), self.assertRaises(RegionError): validate(replace(plan, regions=(region,)))

    def test_unknown_boundary_and_transfer_target(self):
        plan = fixture()
        with self.assertRaises(RegionError): validate(replace(plan, regions=(replace(plan.regions[0], handler_end='missing'),)))
        with self.assertRaises(RegionError): validate(replace(plan, normal=(replace(plan.normal[0], target='missing'),) + plan.normal[1:]))

    def test_catch_type_or_filter_is_not_inferred(self):
        plan = fixture()
        for region in (replace(plan.regions[0], catch_type='System.Exception'), replace(plan.regions[0], kind='catch'), replace(plan.regions[0], kind='filter')):
            with self.subTest(region=region), self.assertRaises(RegionError): validate(replace(plan, regions=(region,)))

    def test_duplicate_normal_transfer(self):
        plan = fixture()
        with self.assertRaises(RegionError): validate(replace(plan, normal=plan.normal + (plan.normal[0],)))

    def test_branch_cannot_replace_leave_across_try_exit(self):
        plan = node_change(fixture(), 'leave', op='br')
        normal = tuple(replace(row, kind='branch') if row.source == 'leave' else row for row in plan.normal)
        with self.assertRaisesRegex(RegionError, 'branch crosses'): validate(replace(plan, normal=normal))

    def test_ordinary_branch_cannot_enter_handler(self):
        plan = fixture()
        normal = tuple(replace(row, target='dispose') if row.source == 'loop' else row for row in plan.normal)
        with self.assertRaisesRegex(RegionError, 'branch crosses'): validate(replace(plan, normal=normal))

    def test_explicit_branch_cannot_enter_try_from_outside(self):
        plan = node_change(fixture(), 'pre', op='br')
        normal = tuple(replace(row, kind='branch') if row.source == 'pre' else row for row in plan.normal)
        with self.assertRaises(RegionError): validate(replace(plan, normal=normal))

    def test_fallthrough_cannot_exit_try_into_handler(self):
        plan = node_change(fixture(), 'loop', op='nop')
        normal = tuple(replace(row, target='dispose', kind='fallthrough') if row.source == 'loop' else row for row in plan.normal)
        with self.assertRaisesRegex(RegionError, 'Fallthrough crosses'): validate(replace(plan, normal=normal))

    def test_ret_inside_try_rejects(self):
        plan = node_change(fixture(), 'leave', op='ret')
        with self.assertRaisesRegex(RegionError, 'Ret cannot'): validate(replace(plan, normal=tuple(row for row in plan.normal if row.source != 'leave')))

    def test_leave_inside_finally_rejects(self):
        plan = node_change(fixture(), 'end', op='leave')
        with self.assertRaisesRegex(RegionError, 'Leave must'): validate(replace(plan, normal=plan.normal + (N('end', 'clear', 'leave'),)))

    def test_rethrow_inside_finally_does_not_invent_catch_scope(self):
        with self.assertRaisesRegex(RegionError, 'Rethrow requires'): validate(node_change(fixture(), 'end', op='rethrow'))

    def test_endfinally_outside_handler_rejects(self):
        with self.assertRaises(RegionError): validate(node_change(fixture(), 'return', op='endfinally'))

    def test_finally_cannot_fallthrough_to_continuation(self):
        plan = node_change(fixture(), 'end', op='nop')
        with self.assertRaises(RegionError): validate(replace(plan, normal=plan.normal + (N('end', 'clear', 'fallthrough'),)))

    def test_missing_protected_exception_transfer(self):
        plan = fixture()
        with self.assertRaisesRegex(RegionError, 'Missing exceptional'): validate(replace(plan, exceptional=plan.exceptional[:-1]))

    def test_duplicate_exception_transfer(self):
        plan = fixture()
        with self.assertRaises(RegionError): validate(replace(plan, exceptional=plan.exceptional + (plan.exceptional[0],)))

    def test_acquisition_dispose_and_clear_do_not_become_protected(self):
        plan = fixture()
        for key in ('acquire', 'dispose', 'clear'):
            with self.subTest(key=key), self.assertRaises(RegionError):
                validate(replace(plan, exceptional=plan.exceptional + (replace(plan.exceptional[0], source=key),)))

    def test_exceptional_target_must_be_exact_handler_entry(self):
        plan = fixture()
        with self.assertRaises(RegionError): validate(replace(plan, exceptional=(replace(plan.exceptional[0], target='end'),) + plan.exceptional[1:]))

    def test_native_register_entry_is_not_a_managed_finally_stack(self):
        plan = fixture()
        for entry in (FinallyEntry(kind='native_landing', storage_ids=plan.storage_ids),
                      FinallyEntry(evaluation_stack=('exception',), storage_ids=plan.storage_ids),
                      FinallyEntry(visible_values=('X0_unwind', 'W1_selector'), storage_ids=plan.storage_ids)):
            with self.subTest(entry=entry), self.assertRaises(RegionError):
                validate(replace(plan, exceptional=(replace(plan.exceptional[0], entry=entry),) + plan.exceptional[1:]))

    def test_post_call_result_or_dispatch_object_cannot_leak_to_handler(self):
        plan = fixture()
        cases = (replace(plan.exceptional[0], phase='after_normal_result'),
                 replace(plan.exceptional[0], entry=replace(plan.exceptional[0].entry, normal_result_visible=True)),
                 replace(plan.exceptional[0], entry=replace(plan.exceptional[0].entry, pending_exception='X0')))
        for edge in cases:
            with self.subTest(edge=edge), self.assertRaises(RegionError): validate(replace(plan, exceptional=(edge,) + plan.exceptional[1:]))

    def test_pre_call_snapshot_or_other_buffer_identity_rejects(self):
        plan = fixture()
        for entry in (replace(plan.exceptional[0].entry, memory_source='before_call'),
                      replace(plan.exceptional[0].entry, storage_ids=('copy',))):
            with self.subTest(entry=entry), self.assertRaisesRegex(RegionError, 'storage'):
                validate(replace(plan, exceptional=(replace(plan.exceptional[0], entry=entry),) + plan.exceptional[1:]))

    def test_stack_join_mismatch_and_nonempty_finally_entry(self):
        for key, changes in (('unload', {'stack_in': 0}), ('dispose', {'stack_in': 1}), ('return', {'stack_in': 1})):
            with self.subTest(key=key), self.assertRaises(RegionError): validate(node_change(fixture(), key, **changes))

    def test_unsupported_op_throw_shape_and_throw_contract(self):
        for key, changes in (('loop', {'op': 'native_resume'}), ('loop', {'may_throw': True}), ('end', {'op': 'throw'})):
            with self.subTest(key=key), self.assertRaises(RegionError): validate(node_change(fixture(), key, **changes))

    def test_limits_record_shapes_and_entry_are_checked(self):
        plan = fixture()
        for options in ({'max_nodes': 5}, {'max_transfers': 2}, {'max_stack': 0}):
            with self.subTest(options=options), self.assertRaises(RegionError): validate(plan, **options)
        with self.assertRaises(RegionError): validate(replace(plan, entry='dispose'))
        with self.assertRaises(RegionError): validate(replace(plan, nodes=(None,) + plan.nodes[1:]))


if __name__ == '__main__':
    unittest.main()
