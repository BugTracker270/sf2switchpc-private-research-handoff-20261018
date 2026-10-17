"""Independent synthetic-only review of structural finally-region contracts."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
sys.path.insert(0, str(ROOT / 'tests'))
from usb_boundary import destination
from exception_regions import RegionError, validate, clone_plan
from test_exception_regions import fixture, node_change, N


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    tests = []
    def check(name, function):
        function()
        tests.append(dict(name=name, status='PASS'))
    def rejects(plan):
        try:
            validate(plan)
        except RegionError:
            return
        raise AssertionError('Unsupported structural plan was accepted')
    plan = fixture()
    def modify_normal(source, **changes):
        return replace(plan, normal=tuple(replace(edge, **changes) if edge.source == source else edge for edge in plan.normal))

    check('leave cannot continue inside handler', lambda: rejects(modify_normal('leave', target='dispose')))
    check('leave cannot continue inside protected region', lambda: rejects(modify_normal('leave', target='next')))
    check('exceptional entry cannot expose a synthetic call result even without native token names',
          lambda: rejects(replace(plan, exceptional=(replace(plan.exceptional[0], entry=replace(plan.exceptional[0].entry,
              visible_values=('condition',))),) + plan.exceptional[1:])))
    check('duplicate storage identity rejects', lambda: rejects(replace(plan, storage_ids=('enumerator', 'enumerator'))))
    check('finally end cannot retain an evaluation-stack value', lambda: rejects(node_change(plan, 'end', stack_in=1, stack_out=1)))
    check('conditional branch cannot enter handler through a separate successor',
          lambda: rejects(replace(plan, normal=tuple(replace(edge, target='dispose') if edge.source == 'test' and edge.target == 'current'
              else edge for edge in plan.normal))))
    def retained_without_exceptional_calls():
        no_throws = plan
        for key in ('next', 'current', 'unload'):
            no_throws = node_change(no_throws, key, may_throw=False)
        proof = validate(replace(no_throws, exceptional=()))
        assert proof.handler_roots == ('dispose',) and proof.handler_only_reachable == ('dispose', 'end')
        assert proof.leave_dispatches == (('leave', 'dispose', 'clear'),)
        assert not proof.production_eh_ready
    check('normal leave retains finally root independently of exceptional transfers', retained_without_exceptional_calls)
    def clone_storage_and_phase():
        cloned = clone_plan(plan)
        assert cloned == plan and cloned is not plan
        assert all(a is not b and a.entry is not b.entry for a, b in zip(plan.exceptional, cloned.exceptional))
        assert all(edge.entry.storage_ids == ('enumerator',) and edge.phase == 'before_normal_result' for edge in cloned.exceptional)
        assert validate(cloned) == validate(plan) and not validate(cloned).production_eh_ready
    check('fresh clone preserves exceptional storage identities and pre-result phase', clone_storage_and_phase)

    report = dict(status='PASS_INDEPENDENT_SYNTHETIC_EXCEPTION_REGION_STRUCTURAL_REVIEW', checks=len(tests), tests=tests,
        region_source_sha256=digest(ROOT / 'src/tools/exception_regions.py'),
        owner_test_source_sha256=digest(ROOT / 'tests/test_exception_regions.py'),
        review_source_sha256=digest(Path(__file__)), findings=[], source_edited=False, core_built=False,
        proprietary_inputs_read=False, guest_execution_performed=False, production_eh_ready=False,
        scope=('Static review and disjoint synthetic structural fixtures only. Explicit immutable tuple/model shape checks, '
               'normal versus exceptional entry/continuation separation, exact storage identities, pre-result exception phase '
               'and clone anchors are checked within the single-finally/void contract. Stack heights and throw/effect flags '
               'remain supplied contracts; no instruction typing, SSA, native mapping, CLR emission, unwinder or behavioral '
               'equivalence is inferred. No unsafe structural acceptance was found in that stated subset.'))
    destination(ROOT, ROOT / 'reports/exception-region-independent-review-v36.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], checks=len(tests))))


if __name__ == '__main__':
    main()
