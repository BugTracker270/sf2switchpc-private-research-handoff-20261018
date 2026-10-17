"""Execute unchanged legacy scalar boxing at supplied GC allocation/memcpy boundaries."""
from collections import Counter
import hashlib
import json
import random
import struct
from execute_native_ai_leaves import NativeScope, FUNCTIONS, ROOT, HEAP, STACK, STOP
from usb_boundary import destination
from unicorn import arm64_const as reg

WIDTHS = {'System.SByte':1, 'System.Byte':1, 'System.Int16':2, 'System.UInt16':2,
          'System.Int32':4, 'System.UInt32':4, 'System.Int64':8, 'System.UInt64':8,
          'System.Single':4, 'System.Double':8}


class ScalarBoxScope(NativeScope):
    def __init__(self):
        self.boundaries = Counter(); self.next_object = HEAP + 0x10000
        super().__init__()

    def block(self, vm, address, size, context):
        if address == 0xB5B490:
            if vm.reg_read(reg.UC_ARM64_REG_X0) != self.klass: raise AssertionError('Box allocation type differs')
            self.object = self.next_object; self.next_object += 0x40
            if self.next_object >= HEAP + 0x1F0000: raise ValueError('Bounded allocation arena exhausted')
            vm.mem_write(self.object, b'\0'*24 + b'\xCC'*16)
            self.put(self.object, 'Q', self.klass)
            vm.reg_write(reg.UC_ARM64_REG_X0, self.object)
            self.boundaries['supplied_zeroed_GC_allocation_without_scalar_cctor'] += 1
        elif address == 0x23730B8:
            target = vm.reg_read(reg.UC_ARM64_REG_X0)
            source = vm.reg_read(reg.UC_ARM64_REG_X1)
            length = vm.reg_read(reg.UC_ARM64_REG_X2)
            if (target, source, length) != (self.object + 16, self.input, self.width):
                raise AssertionError('Original boxing copy extent/address differs')
            vm.mem_write(target, bytes(vm.mem_read(source, length)))
            self.boundaries['supplied_standard_memcpy'] += 1
        else:
            return super().block(vm, address, size, context)
        vm.reg_write(reg.UC_ARM64_REG_PC, vm.reg_read(reg.UC_ARM64_REG_X30))


def main():
    metadata_path = ROOT/'reports/scalar-boxing-metadata-v30.json'
    metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
    layouts = {row['type']:row for row in metadata['primitives']}
    for name, width in WIDTHS.items():
        row = layouts[name]
        if not row['value_type'] or row['has_static_constructor'] or row['instance_size'] != width + 16:
            raise ValueError('Original primitive metadata no longer matches the bounded scalar scope: '+name)
    FUNCTIONS.clear()
    FUNCTIONS.update(box=(0xB5B070,0xB5B10C), nullable=(0xB05BB0,0xB05BE0),
                     size=(0xB04FF0,0xB05028), initialized_class=(0xB04F60,0xB04FD0))
    scope = ScalarBoxScope(); cases = checks = 0; per_type = {}; fixtures = []
    for index, (name, width) in enumerate(WIDTHS.items()):
        scope.klass = HEAP + 0x2000 + index * 0x200
        scope.width = width; scope.input = HEAP + 0x1000
        scope.put(scope.klass + 0x60, 'Q', 0)  # nongeneric concrete primitive class
        scope.put(scope.klass + 0x121, 'B', 0x43)  # value type, initialized class/layout
        scope.put(scope.klass + 0xE8, 'I', layouts[name]['instance_size'])
        rng = random.Random(0x53463200 + index)
        limit = 1 << (width * 8)
        patterns = list(range(256)) if width == 1 else [0,limit-1,1,limit//2,limit//2-1]
        patterns += [rng.randrange(limit) for _ in range(256-len(patterns))]
        previous = None
        for bits in patterns:
            payload = bits.to_bytes(width,'little')
            scope.vm.mem_write(scope.input-8,b'\xA5'*8 + payload + b'\x5A'*8)
            scope.vm.reg_write(reg.UC_ARM64_REG_SP, STACK + 0x80000)
            scope.vm.reg_write(reg.UC_ARM64_REG_X30, STOP)
            scope.vm.reg_write(reg.UC_ARM64_REG_X0, scope.klass)
            scope.vm.reg_write(reg.UC_ARM64_REG_X1, scope.input)
            scope.vm.emu_start(0xB5B070, STOP, count=1000)
            actual = [scope.vm.reg_read(reg.UC_ARM64_REG_PC), scope.vm.reg_read(reg.UC_ARM64_REG_X0),
                      bytes(scope.vm.mem_read(scope.object+16,width)),
                      struct.unpack('<Q',scope.vm.mem_read(scope.object,8))[0],
                      bytes(scope.vm.mem_read(scope.object+24,16)),
                      bytes(scope.vm.mem_read(scope.input-8,width+16)), scope.object != previous]
            expected = [STOP, scope.object, payload, scope.klass, b'\xCC'*16, b'\xA5'*8+payload+b'\x5A'*8, True]
            if actual != expected: raise AssertionError(f'Original boxing differs for {name} / {bits:X}')
            fixtures.append(dict(type=name, payload_hex=payload.hex()))
            previous = scope.object; cases += 1; checks += len(expected)
        per_type[name] = dict(width=width,cases=256,checks=1792)
    fixture_path = destination(ROOT, ROOT/'analysis/il2cpp/scalar-boxing-native-fixtures-v30.jsonl')
    fixture_path.write_text(''.join(json.dumps(row)+'\n' for row in fixtures),encoding='utf-8')
    report = dict(status='PASS_ORIGINAL_NON_NULLABLE_SCALAR_BOX_PAYLOADS_AT_GC_COPY_BOUNDARIES',
        cases=cases,checks=checks,types=per_type,text_modified=False,
        metadata_observation_sha256=hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
        fixtures=str(fixture_path.relative_to(ROOT)),fixtures_sha256=hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
        reviewed_functions={name:dict(rva=hex(a),bytes=b-a,sha256=hashlib.sha256(scope.vm.mem_read(a,b-a)).hexdigest()) for name,(a,b) in FUNCTIONS.items()},
        executed_blocks=dict(scope.visited),runtime_boundaries=dict(scope.boundaries),
        scope='Original boxing helper, nullable predicate, instance-size reader and already-initialized class path execute unchanged for ten concrete primitive classes with actual metadata sizes and no metadata .cctor. GC allocation and imported memcpy are explicit supplied contracts. Payload bits, exact requested type, fresh pointer, source bytes and destination bounds are checked. Boolean/Char (cctor), nullable/reference/custom types, GC/lifetime, uninitialized classes, actual CLR box instructions and full callers are outside this oracle.')
    destination(ROOT, ROOT/'reports/native-scalar-boxing-v30.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__': main()
