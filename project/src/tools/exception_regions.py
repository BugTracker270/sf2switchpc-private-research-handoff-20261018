"""Immutable structural cleanup plans, deliberately separate from Cpp2IL.

Only explicitly synthetic, single-finally, void-method plans are accepted. This
checks control/entry/storage contracts; it neither translates native EH metadata
nor emits CIL, verifies CIL operand types, runs SSA or proves game equivalence.
"""
from dataclasses import dataclass, fields, replace


class RegionError(ValueError):
    pass


@dataclass(frozen=True)
class Node:
    key: str
    op: str
    stack_in: int = 0
    stack_out: int = 0
    may_throw: bool = False
    normal_result: str | None = None


@dataclass(frozen=True)
class NormalTransfer:
    source: str
    target: str
    kind: str


@dataclass(frozen=True)
class FinallyEntry:
    kind: str = 'managed_finally'
    evaluation_stack: tuple[str, ...] = ()
    visible_values: tuple[str, ...] = ()
    memory_source: str = 'throwpoint_after_effects'
    storage_ids: tuple[str, ...] = ()
    normal_result_visible: bool = False
    pending_exception: str = 'runtime_owned'


@dataclass(frozen=True)
class ExceptionalTransfer:
    source: str
    target: str
    entry: FinallyEntry
    phase: str = 'before_normal_result'


@dataclass(frozen=True)
class Region:
    try_start: str
    try_end: str
    handler_start: str
    handler_end: str
    kind: str = 'finally'
    catch_type: str | None = None


@dataclass(frozen=True)
class Plan:
    nodes: tuple[Node, ...]
    normal: tuple[NormalTransfer, ...]
    exceptional: tuple[ExceptionalTransfer, ...]
    regions: tuple[Region, ...]
    entry: str
    storage_ids: tuple[str, ...] = ()
    source_kind: str = 'synthetic'


@dataclass(frozen=True)
class ValidatedPlan:
    normal_reachable: tuple[str, ...]
    handler_roots: tuple[str, ...]
    handler_only_reachable: tuple[str, ...]
    retained: tuple[str, ...]
    leave_dispatches: tuple[tuple[str, str, str], ...]
    exceptional_dispatches: tuple[tuple[str, str, str], ...]
    production_eh_ready: bool = False


_MODEL_TYPES = (Node, NormalTransfer, FinallyEntry, ExceptionalTransfer, Region, Plan)


def _immutable(value):
    if type(value) in (str, int, bool, type(None)):
        return
    if type(value) is tuple:
        for item in value:
            _immutable(item)
        return
    if type(value) in _MODEL_TYPES:
        for field in fields(value):
            _immutable(getattr(value, field.name))
        return
    raise RegionError('Plan contains a mutable or unsupported value')


def validate(plan: Plan, *, max_nodes=256, max_transfers=1024, max_stack=64):
    """Validate a small conservative structural subset, never production readiness.

    Normal leave continuation and finally invocation are distinct: a leave's
    ordinary target remains its continuation, and a separate dispatch names the
    handler. No exceptional predecessor is merged into an ordinary successor list.
    """
    if type(plan) is not Plan:
        raise RegionError('Expected a Plan')
    _immutable(plan)
    if any(type(value) is not tuple for value in (plan.nodes, plan.normal, plan.exceptional, plan.regions, plan.storage_ids)):
        raise RegionError('Plan record collections must be immutable tuples')
    if any(type(value) is not int or value < 1 for value in (max_nodes, max_transfers, max_stack)):
        raise RegionError('Invalid structural limits')
    if plan.source_kind != 'synthetic':
        raise RegionError('Original/native-to-managed mapping is not implemented')
    if not 0 < len(plan.nodes) <= max_nodes or len(plan.normal) + len(plan.exceptional) > max_transfers:
        raise RegionError('Plan exceeds structural limits')
    if len(plan.regions) != 1:
        raise RegionError('Nested or multiple/overlapping regions are unsupported')
    if any(type(row) is not Node for row in plan.nodes) or any(type(row) is not NormalTransfer for row in plan.normal):
        raise RegionError('Invalid node/normal-transfer record')
    if any(type(row) is not ExceptionalTransfer for row in plan.exceptional) or type(plan.regions[0]) is not Region:
        raise RegionError('Invalid exception/region record')
    keys = [row.key for row in plan.nodes]
    if any(type(key) is not str or not key or len(key) > 128 or key == '$end' for key in keys) or len(set(keys)) != len(keys):
        raise RegionError('Duplicate, invalid or reserved instruction identity')
    if len(set(plan.storage_ids)) != len(plan.storage_ids) or any(type(key) is not str or not key for key in plan.storage_ids):
        raise RegionError('Invalid storage identities')
    positions = {key: index for index, key in enumerate(keys)}
    boundaries = dict(positions, **{'$end': len(keys)})
    nodes = dict(zip(keys, plan.nodes))
    region = plan.regions[0]
    if region.kind != 'finally' or region.catch_type is not None:
        raise RegionError('Only finally without a catch type is supported')
    if any(anchor not in boundaries for anchor in (region.try_start, region.try_end, region.handler_start, region.handler_end)):
        raise RegionError('Dangling protected/handler boundary')
    start, end, handler, handler_end = (boundaries[anchor] for anchor in (region.try_start, region.try_end, region.handler_start, region.handler_end))
    if not 0 <= start < end == handler < handler_end <= len(keys):
        raise RegionError('Empty, overlapping or unsupported region layout')
    if plan.entry != keys[0] or handler <= 0 < handler_end:
        raise RegionError('Entry must be the first instruction outside the handler')
    if plan.nodes[0].stack_in != 0 or nodes[region.handler_start].stack_in != 0:
        raise RegionError('Method/finally entry stack must be empty')

    def zone(key):
        index = positions[key]
        return 'try' if start <= index < end else 'handler' if handler <= index < handler_end else 'outside'

    outgoing = {key: [] for key in keys}
    seen = set()
    for edge in plan.normal:
        if edge.source not in nodes or edge.target not in nodes or edge in seen:
            raise RegionError('Dangling or duplicate normal transfer')
        seen.add(edge)
        outgoing[edge.source].append(edge)
    allowed = {'nop', 'call', 'br', 'brtrue', 'leave', 'endfinally', 'ret', 'throw'}
    for node in plan.nodes:
        if node.op == 'rethrow':
            raise RegionError('Rethrow requires a catch scope; none is inferred')
        if node.op not in allowed:
            raise RegionError('Unsupported instruction operation')
        if any(type(value) is not int or not 0 <= value <= max_stack for value in (node.stack_in, node.stack_out)):
            raise RegionError('Invalid evaluation stack height')
        if type(node.may_throw) is not bool or node.may_throw and node.op not in ('call', 'throw'):
            raise RegionError('Unsupported throwing-instruction contract')
        if node.normal_result is not None and (node.op != 'call' or type(node.normal_result) is not str or not node.normal_result):
            raise RegionError('Only a call may define a normal result')
        edges = outgoing[node.key]
        expected = 2 if node.op == 'brtrue' else 0 if node.op in ('ret', 'endfinally', 'throw') else 1
        if len(edges) != expected:
            raise RegionError('Wrong normal transfer count')
        if node.op in ('ret', 'endfinally') and (node.stack_in != 0 or node.stack_out != 0):
            raise RegionError('Void terminal requires an empty stack')
        if node.op == 'ret' and zone(node.key) != 'outside':
            raise RegionError('Ret cannot exit a protected/handler region')
        if node.op == 'endfinally' and zone(node.key) != 'handler':
            raise RegionError('Endfinally outside finally handler')
        if node.op == 'throw' and (node.stack_in != 1 or node.stack_out != 0 or not node.may_throw):
            raise RegionError('Throw must consume its exception value')
        if node.op in ('nop', 'br') and node.stack_in != node.stack_out:
            raise RegionError('Unexpected stack change for nop/branch')
        if node.op == 'brtrue' and node.stack_in != node.stack_out + 1:
            raise RegionError('Conditional branch must consume one condition')
        for edge in edges:
            source_zone, target_zone = zone(edge.source), zone(edge.target)
            if nodes[edge.target].stack_in != node.stack_out:
                raise RegionError('Evaluation stack mismatch at normal merge')
            if node.op == 'leave':
                if edge.kind != 'leave' or source_zone != 'try' or target_zone != 'outside' or node.stack_out != 0:
                    raise RegionError('Leave must exit try with an empty continuation stack')
            elif node.op in ('br', 'brtrue'):
                if edge.kind != 'branch' or source_zone != target_zone:
                    raise RegionError('Ordinary branch crosses a region boundary')
            else:
                permitted_entry = source_zone == 'outside' and edge.target == region.try_start
                if edge.kind != 'fallthrough' or positions[edge.target] != positions[edge.source] + 1:
                    raise RegionError('Invalid physical fallthrough')
                if source_zone != target_zone and not permitted_entry:
                    raise RegionError('Fallthrough crosses a handler/protected exit')
    if plan.nodes[handler_end - 1].op != 'endfinally':
        raise RegionError('Finally must terminate with endfinally in this subset')
    expected_exceptional = {node.key for node in plan.nodes if node.may_throw and zone(node.key) == 'try'}
    actual_exceptional = set()
    for edge in plan.exceptional:
        if edge.source not in expected_exceptional or edge.source in actual_exceptional or edge.target != region.handler_start:
            raise RegionError('Wrong, missing-scope or duplicate exceptional transfer')
        actual_exceptional.add(edge.source)
        entry = edge.entry
        if type(entry) is not FinallyEntry:
            raise RegionError('Invalid finally-entry record')
        if any(type(value) is not tuple for value in (entry.evaluation_stack, entry.visible_values, entry.storage_ids)):
            raise RegionError('Finally-entry collections must be immutable tuples')
        if entry.kind != 'managed_finally' or entry.evaluation_stack or entry.visible_values:
            raise RegionError('Finally entry cannot expose native tokens or a stack exception value')
        if (edge.phase != 'before_normal_result' or entry.normal_result_visible is not False
                or entry.pending_exception != 'runtime_owned'):
            raise RegionError('Normal call result is not an exceptional-entry value')
        if entry.memory_source != 'throwpoint_after_effects' or entry.storage_ids != plan.storage_ids:
            raise RegionError('Exceptional storage must retain throwpoint identity/effects')
    if actual_exceptional != expected_exceptional:
        raise RegionError('Missing exceptional transfer for a protected throwing operation')

    def closure(roots):
        reached, pending = set(), list(roots)
        while pending:
            key = pending.pop()
            if key in reached:
                continue
            reached.add(key)
            pending.extend(edge.target for edge in outgoing[key])
        return reached
    normal = closure((plan.entry,))
    leaves = tuple((edge.source, region.handler_start, edge.target) for edge in plan.normal if edge.kind == 'leave')
    if not leaves:
        raise RegionError('This subset requires a normal leave/continuation')
    roots = (region.handler_start,)
    retained = normal | closure(roots)
    if retained != set(keys):
        raise RegionError('Unreachable unanchored instructions are unsupported')
    ordered = lambda subset: tuple(key for key in keys if key in subset)
    dispatches = tuple((edge.source, edge.target, 'propagate_runtime_pending') for edge in plan.exceptional)
    return ValidatedPlan(ordered(normal), roots, ordered(retained - normal), ordered(retained), leaves, dispatches)


def clone_plan(plan: Plan):
    """Fresh identity objects; immutable label keys preserve every anchor/transfer."""
    validate(plan)
    cloned = replace(plan, nodes=tuple(replace(node) for node in plan.nodes),
        normal=tuple(replace(edge) for edge in plan.normal),
        exceptional=tuple(replace(edge, entry=replace(edge.entry)) for edge in plan.exceptional),
        regions=tuple(replace(region) for region in plan.regions))
    validate(cloned)
    return cloned
