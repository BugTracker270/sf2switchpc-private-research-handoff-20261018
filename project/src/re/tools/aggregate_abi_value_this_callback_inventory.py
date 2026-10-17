"""Private unchanged-native callback inventory; never executes guest functions."""
import hashlib
import json
import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def main():
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    raw = source.read_bytes()
    native_hash = hashlib.sha256(raw).hexdigest()
    if native_hash != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Native input changed')
    start, end = 0x7A8F20, 0x7A9128
    frames = [json.loads(line) for line in (ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl').read_text().splitlines()]
    frame, = [row for row in frames if row['rva'] == start]
    if frame['end_rva'] != end:
        raise ValueError('Exact original body extent differs')
    code = raw[0x100 + start:0x100 + end]
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    cs.detail = True
    rows = []
    for instruction in cs.disasm(code, start):
        reads, writes = instruction.regs_access()
        rows.append(dict(address=instruction.address, mnemonic=instruction.mnemonic,
                         operands=instruction.op_str, bytes_hex=instruction.bytes.hex(),
                         register_reads=[instruction.reg_name(r) for r in reads],
                         register_writes=[instruction.reg_name(r) for r in writes]))
    if len(rows) * 4 != len(code):
        raise ValueError('Incomplete native decoding')
    output = destination(ROOT, ROOT / 'analysis/reconstruction/value-this-regression-v36/native-callback-inventory.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(status='READ_ONLY_ORIGINAL_VALUE_THIS_CALLBACK_INVENTORY', native_sha256=native_hash,
                  body_sha256=hashlib.sha256(code).hexdigest(), exact_frame=frame,
                  source_modified=False, execution_performed=False,
                  probe_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), instructions=rows)
    output.write_text(json.dumps(report, indent=2) + '\n')
    for row in rows:
        print(hex(row['address']), row['mnemonic'], row['operands'], 'R', row['register_reads'], 'W', row['register_writes'])


if __name__ == '__main__':
    main()
