"""Private read-only native inventory for original stream virtual dispatch research."""
import hashlib
import json
from pathlib import Path
import sys
import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def main():
    source = ROOT / 'analysis/nso/main-uncompressed.nso'
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original native input differs')
    targets = {0x4A0D70: 'WebSocketFrameReader.Read', 0x843E80: 'MemoryStream.ReadByte',
               0x8491A0: 'Stream.ReadByte', 0x843450: 'MemoryStream.CheckIfClosedThrowDisposed'}
    frames = {}
    for line in (ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl').read_text().splitlines():
        row = json.loads(line)
        if row['rva'] in targets:
            if row['rva'] in frames:
                raise ValueError('Duplicate exact frame')
            frames[row['rva']] = row
    if frames.keys() != targets.keys():
        raise ValueError('Missing exact original frame')
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    methods = []
    for address, name in targets.items():
        frame = frames[address]
        body = raw[0x100 + address:0x100 + frame['end_rva']]
        rows = [dict(address=hex(i.address), mnemonic=i.mnemonic, operands=i.op_str,
                     bytes_hex=i.bytes.hex()) for i in cs.disasm(body, address)]
        if sum(len(bytes.fromhex(row['bytes_hex'])) for row in rows) != len(body):
            raise ValueError('Original frame did not decode completely')
        methods.append(dict(name=name, rva=hex(address), exact_frame=frame, bytes=len(body),
                            sha256=hashlib.sha256(body).hexdigest(), instructions=rows))
    report = dict(status='READ_ONLY_ORIGINAL_STREAM_VIRTUAL_DISPATCH_INVENTORY',
                  native_source_sha256=digest, source_modified=False, execution_performed=False,
                  probe_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), methods=methods)
    output = destination(ROOT, ROOT / 'analysis/reconstruction/virtual-stream-dispatch-v36/native-inventory.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    for method in methods:
        print(method['name'], method['bytes'], method['sha256'])
        for row in method['instructions']:
            print(row['address'], row['mnemonic'], row['operands'])


if __name__ == '__main__':
    main()
