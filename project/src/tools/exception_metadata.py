"""Bounded data parsers for a narrow DWARF/Itanium exception-metadata subset.

No unwinding, CFG construction, managed catch inference or guest-code execution
occurs here. Indirect encodings remain explicit references until a caller supplies
a checked relocation resolver. Unsupported forms fail closed.
"""
from dataclasses import dataclass
import struct
from typing import Callable

Read = Callable[[int, int], bytes]
MAX_ADDRESS = (1 << 64) - 1


class MetadataError(ValueError):
    pass


class UnsupportedMetadata(MetadataError):
    pass


@dataclass(frozen=True)
class Span:
    start: int
    end: int

    def __post_init__(self):
        if not isinstance(self.start, int) or not isinstance(self.end, int) or not 0 <= self.start <= self.end <= MAX_ADDRESS + 1:
            raise MetadataError('Invalid bounded address span')

    def require(self, address, size):
        if not isinstance(address, int) or not isinstance(size, int) or size < 0 or not self.start <= address <= address + size <= self.end:
            raise MetadataError('Read/target outside bounded span')


class Cursor:
    def __init__(self, read: Read, span: Span):
        self.read, self.span, self.position = read, span, span.start

    def take(self, size):
        self.span.require(self.position, size)
        data = self.read(self.position, size)
        if not isinstance(data, bytes) or len(data) != size:
            raise MetadataError('Reader returned truncated or non-byte data')
        self.position += size
        return data

    def number(self, form):
        return struct.unpack('<' + form, self.take(struct.calcsize('<' + form)))[0]

    def leb(self, signed=False):
        value = 0
        for shift in range(0, 70, 7):
            byte = self.number('B')
            value |= (byte & 127) << shift
            if byte < 128:
                if signed and byte & 64:
                    value -= 1 << (shift + 7)
                if not (-(1 << 63) <= value < (1 << 63) if signed else 0 <= value <= MAX_ADDRESS):
                    raise MetadataError('LEB128 exceeds 64-bit range')
                return value
        raise MetadataError('Unterminated LEB128')


@dataclass(frozen=True)
class EncodedPointer:
    encoding: int
    field_address: int
    raw_value: int
    reference: int | None
    indirect: bool


_FORMS = {0: 'Q', 2: 'H', 3: 'I', 4: 'Q', 10: 'h', 11: 'i', 12: 'q'}


def encoded_pointer(cursor: Cursor, encoding: int):
    if not isinstance(encoding, int) or not 0 <= encoding <= 255:
        raise MetadataError('Pointer encoding is not a byte')
    if encoding == 255:
        raise UnsupportedMetadata('Omitted pointer is not an encoded field')
    form, application = encoding & 15, encoding & 112
    if application not in (0, 16):
        raise UnsupportedMetadata('Only absolute and PC-relative references supported')
    at = cursor.position
    if form in _FORMS:
        raw = cursor.number(_FORMS[form])
    elif form in (1, 9):
        raw = cursor.leb(form == 9)
    else:
        raise UnsupportedMetadata('Unsupported pointer data form')
    reference = None if raw == 0 else raw + (at if application == 16 else 0)
    if reference is not None and not 0 <= reference <= MAX_ADDRESS:
        raise MetadataError('Encoded reference overflows address range')
    return EncodedPointer(encoding, at, raw, reference, bool(encoding & 128))


@dataclass(frozen=True)
class CallSite:
    start: int
    end: int
    landing: int | None
    action: int


@dataclass(frozen=True)
class Action:
    address: int
    end: int
    type_filter: int
    next_offset_base: int
    next_offset: int


@dataclass(frozen=True)
class Lsda:
    metadata_span: Span
    landing_pad_base: int
    type_encoding: int
    type_table: int | None
    call_site_encoding: int
    call_site_table: Span
    call_sites: tuple[CallSite, ...]
    action_chains: dict[int, tuple[Action, ...]]
    type_entries: dict[int, EncodedPointer]


def parse_lsda(read: Read, metadata: Span, function: Span, *, code_alignment=4,
               max_bytes=4096, max_call_sites=256, max_chain=32):
    if any(not isinstance(value, int) or value < 1 for value in (code_alignment, max_bytes, max_call_sites, max_chain)):
        raise MetadataError('Invalid LSDA limits')
    if metadata.end - metadata.start > max_bytes or function.start == function.end:
        raise MetadataError('LSDA/function limits exceeded')
    cursor = Cursor(read, metadata)
    lp_encoding = cursor.number('B')
    if lp_encoding == 255:
        lp_start = function.start
    else:
        pointer = encoded_pointer(cursor, lp_encoding)
        if pointer.indirect or pointer.reference != function.start:
            raise UnsupportedMetadata('Nonlocal/indirect landing-pad base unsupported')
        lp_start = pointer.reference
    type_encoding = cursor.number('B')
    type_table, entry_size = None, None
    if type_encoding != 255:
        if type_encoding & 15 not in _FORMS or type_encoding & 112 not in (0, 16):
            raise UnsupportedMetadata('Type table requires a fixed-width supported pointer form')
        entry_size = struct.calcsize('<' + _FORMS[type_encoding & 15])
        offset = cursor.leb()
        type_table = cursor.position + offset
        metadata.require(type_table, 0)
    call_encoding = cursor.number('B')
    if call_encoding != 3:
        raise UnsupportedMetadata('Only original unsigned-32 call-site encoding supported')
    table_size = cursor.leb()
    table = Span(cursor.position, cursor.position + table_size)
    metadata.require(table.start, table_size)
    cursor.span = table
    sites = []
    while cursor.position < table.end:
        if len(sites) >= max_call_sites:
            raise MetadataError('Call-site limit exceeded')
        start, size, landing, action = cursor.number('I'), cursor.number('I'), cursor.number('I'), cursor.leb()
        begin, end = lp_start + start, lp_start + start + size
        function.require(begin, size)
        if size == 0 or begin % code_alignment or end % code_alignment or sites and begin < sites[-1].end:
            raise MetadataError('Empty, unaligned or overlapping/unsorted protected range')
        target = lp_start + landing if landing else None
        if target is not None:
            function.require(target, 1)
            if target % code_alignment:
                raise MetadataError('Unaligned landing entry')
        elif action:
            raise MetadataError('Action without a landing entry')
        sites.append(CallSite(begin, end, target, action))
    action_end = type_table if type_table is not None else metadata.end
    if table.end > action_end:
        raise MetadataError('Call-site table overlaps type-table base')
    action_span = Span(table.end, action_end)
    records, chains, types = {}, {}, {}
    for entry in sorted({site.action for site in sites if site.action}):
        address, seen, chain = action_span.start + entry - 1, set(), []
        while True:
            if address in seen:
                raise MetadataError('Cyclic action chain')
            if len(chain) >= max_chain:
                raise MetadataError('Action-chain limit exceeded')
            action_span.require(address, 1)
            seen.add(address)
            current = Cursor(read, Span(address, action_span.end))
            type_filter = current.leb(True)
            offset_base = current.position
            next_offset = current.leb(True)
            record = Action(address, current.position, type_filter, offset_base, next_offset)
            records[address] = record
            chain.append(record)
            if type_filter < 0:
                raise UnsupportedMetadata('Exception-specification actions unsupported')
            if type_filter > 0:
                if type_table is None or entry_size is None:
                    raise MetadataError('Typed action without a type table')
                at = type_table - type_filter * entry_size
                action_span.require(at, entry_size)
                pointer = encoded_pointer(Cursor(read, Span(at, at + entry_size)), type_encoding)
                types[type_filter] = pointer
            if next_offset == 0:
                break
            address = offset_base + next_offset
        chains[entry] = tuple(chain)
    intervals = sorted((record.address, record.end) for record in records.values())
    if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:])):
        raise MetadataError('Action records overlap one another')
    if types:
        reserved_types = Span(type_table - max(types) * entry_size, type_table)
        if any(start < reserved_types.end and end > reserved_types.start for start, end in intervals):
            raise MetadataError('Action record overlaps allocated type-table entries')
    return Lsda(metadata, lp_start, type_encoding, type_table, call_encoding, table, tuple(sites), chains, types)


@dataclass(frozen=True)
class CfiState:
    cfa_register: int | None = None
    cfa_offset: int | None = None
    saved: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class CfiStep:
    address: int
    pc: int
    operation: str
    state: CfiState


def parse_cfi(read: Read, program: Span, function: Span, *, initial=None,
              code_alignment=1, data_alignment=-4, max_steps=1024, max_register=31, max_stack_offset=1 << 20):
    """Return per-instruction state observations, not per-PC unwind intervals.

    Several observations can share one PC while a row is being constructed.
    Selecting a completed row, restoring registers and installing exception
    contexts are deliberately outside this parser's contract.
    """
    if (any(not isinstance(value, int) for value in (code_alignment, data_alignment, max_steps, max_register, max_stack_offset))
            or code_alignment < 1 or data_alignment == 0 or max_steps < 1 or not 0 <= max_register <= 31
            or max_stack_offset < 0 or function.start == function.end):
        raise MetadataError('Invalid CFI bounds/alignment')
    state = CfiState() if initial is None else initial
    if not isinstance(state, CfiState):
        raise MetadataError('Invalid initial CFI state')
    if not isinstance(state.saved, tuple):
        raise MetadataError('Invalid initial saved-register container')
    def checked_register(value):
        if not isinstance(value, int) or not 0 <= value <= max_register:
            raise UnsupportedMetadata('Register outside bounded CFI subset')
        return value
    register, offset, saved = state.cfa_register, state.cfa_offset, {}
    if (register is None) != (offset is None):
        raise MetadataError('Incomplete initial CFA state')
    if register is not None:
        checked_register(register)
        if not isinstance(offset, int) or not 0 <= offset <= max_stack_offset:
            raise MetadataError('Initial CFA offset exceeds bounds')
    for item in state.saved:
        if not isinstance(item, tuple) or len(item) != 2:
            raise MetadataError('Invalid initial saved-register record')
        saved_register, saved_offset = item
        checked_register(saved_register)
        if saved_register in saved or not isinstance(saved_offset, int) or abs(saved_offset) > max_stack_offset:
            raise MetadataError('Duplicate or out-of-bounds initial saved register')
        saved[saved_register] = saved_offset
    cursor, pc, steps = Cursor(read, program), function.start, []
    while cursor.position < program.end:
        if len(steps) >= max_steps:
            raise MetadataError('CFI instruction limit exceeded')
        at, opcode = cursor.position, cursor.number('B')
        primary, low = opcode & 192, opcode & 63
        if primary == 64:
            pc += low * code_alignment
            operation = 'advance_loc'
        elif primary == 128:
            saved[checked_register(low)] = cursor.leb() * data_alignment
            operation = 'offset'
        elif opcode in (2, 3, 4):
            pc += cursor.number({2: 'B', 3: 'H', 4: 'I'}[opcode]) * code_alignment
            operation = 'advance_loc'
        elif opcode == 12:
            register, offset = checked_register(cursor.leb()), cursor.leb()
            operation = 'def_cfa'
        elif opcode == 13:
            if offset is None:
                raise MetadataError('CFA register update precedes a CFA definition')
            register = checked_register(cursor.leb())
            operation = 'def_cfa_register'
        elif opcode == 14:
            if register is None:
                raise MetadataError('CFA offset update precedes a CFA definition')
            offset = cursor.leb()
            operation = 'def_cfa_offset'
        elif opcode == 0:
            operation = 'nop'
        else:
            raise UnsupportedMetadata('CFI opcode outside explicitly supported subset')
        function.require(pc, 0)
        if offset is not None and not 0 <= offset <= max_stack_offset or any(abs(value) > max_stack_offset for value in saved.values()):
            raise MetadataError('CFI stack offset limit exceeded')
        steps.append(CfiStep(at, pc, operation, CfiState(register, offset, tuple(sorted(saved.items())))))
    return tuple(steps), steps[-1].state if steps else state


@dataclass(frozen=True)
class PointerValue:
    value: int | None
    symbol: str | None = None
    addend: int = 0


@dataclass(frozen=True)
class CppClassTypeInfo:
    address: int
    name: str
    vtable_symbol: str


def read_class_type_info(read: Read, object_span: Span, name_span: Span,
                         resolve: Callable[[int], PointerValue], *, max_name_bytes=256):
    """Read the narrow original __class_type_info shape; never infer a CLR type."""
    if not isinstance(max_name_bytes, int) or not 1 <= max_name_bytes <= 4096:
        raise MetadataError('Invalid RTTI name limit')
    object_span.require(object_span.start, 16)
    vtable, name_pointer = resolve(object_span.start), resolve(object_span.start + 8)
    if vtable.symbol != '_ZTVN10__cxxabiv117__class_type_infoE' or vtable.addend != 16:
        raise UnsupportedMetadata('RTTI vtable is not the reviewed simple class type_info')
    if name_pointer.symbol is not None or name_pointer.value is None:
        raise UnsupportedMetadata('Unresolved RTTI name pointer')
    result = bytearray()
    for index in range(max_name_bytes):
        at = name_pointer.value + index
        name_span.require(at, 1)
        data = read(at, 1)
        if not isinstance(data, bytes) or len(data) != 1:
            raise MetadataError('Truncated RTTI name')
        byte = data[0]
        if byte == 0:
            if not result:
                raise MetadataError('Empty RTTI name')
            return CppClassTypeInfo(object_span.start, result.decode('ascii'), vtable.symbol)
        if not 32 <= byte < 127:
            raise MetadataError('Non-ASCII RTTI name')
        result.append(byte)
    raise MetadataError('Unterminated bounded RTTI name')
