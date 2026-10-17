"""Private original native ranges for exact common-runtime source comparison."""
import hashlib
import json
from pathlib import Path
import sys
import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination
from native_unwind_inventory import Image


def main():
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    raw = source.read_bytes()
    source_hash = hashlib.sha256(raw).hexdigest()
    if source_hash != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original native image differs')
    image = Image(raw)
    targets = {0xB04F60: 'layout_init_candidate', 0xB06570: 'init_locked_candidate',
               0xB7DC90: 'lock_candidate', 0xB7DCA0: 'unlock_candidate', 0xB2E720: 'managed_cctor_candidate'}
    frames = {}
    for line in (ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl').read_text().splitlines():
        row = json.loads(line)
        if row['rva'] in targets:
            frames[row['rva']] = row
    if frames[0xB04F60]['end_rva'] != 0xB04FEC or frames[0xB06570]['end_rva'] != 0xB06820:
        raise ValueError('Exact original helper bounds differ')
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    decoder.detail = True
    records = []
    for start, name in targets.items():
        if start not in frames:
            records.append(dict(name=name, start=hex(start), exact_frame_missing=True))
            continue
        frame = frames[start]
        code = image.read(start, frame['end_rva'] - start)
        instructions = []
        for instruction in decoder.disasm(code, start):
            reads, writes = instruction.regs_access()
            instructions.append(dict(rva=hex(instruction.address), mnemonic=instruction.mnemonic,
                operands=instruction.op_str, bytes_hex=instruction.bytes.hex(),
                read_registers=[instruction.reg_name(register) for register in reads],
                written_registers=[instruction.reg_name(register) for register in writes]))
        if sum(len(bytes.fromhex(row['bytes_hex'])) for row in instructions) != len(code):
            raise ValueError('Original disassembly did not cover exact FDE bytes')
        records.append(dict(name=name, start=hex(start), end=hex(frame['end_rva']), bytes=len(code),
                            sha256=hashlib.sha256(code).hexdigest(), frame=frame, instructions=instructions))
    report = dict(status='PRIVATE_ORIGINAL_CLASS_LAYOUT_RUNTIME_RANGES', source_sha256=source_hash, methods=records,
        source_modified=False, native_execution_performed=False,
        prior_initialized_path_range=dict(start='0xb04f60', end='0xb04fd0', bytes=112,
            scope='Previously executed already-initialized path only, not the complete 140-byte exception-bearing FDE.'),
        probe_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = destination(ROOT, ROOT / 'analysis/reconstruction/class-layout-runtime-source-v37/native.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(status=report['status'], methods=[{key: row[key] for key in ('name', 'start', 'bytes', 'sha256') if key in row} for row in records])))


if __name__ == '__main__':
    main()
