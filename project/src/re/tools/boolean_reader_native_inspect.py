"""Read-only exact-frame provenance and instruction inventory for Boolean witness."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination


def main():
    path = ROOT / 'analysis/nso/main-uncompressed.nso'
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original NSO source differs')
    wanted = {0xF0D390: 'BinaryReaderNekki.ReadBoolean', 0x89D060: 'BitConverter.ToBoolean'}
    frames = {}
    with (ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl').open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['rva'] in wanted:
                if row['rva'] in frames:
                    raise ValueError('Ambiguous exact frame')
                frames[row['rva']] = row
    if frames.keys() != wanted.keys():
        raise ValueError('Missing exact frame')
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    methods = []
    for rva, name in wanted.items():
        frame = frames[rva]
        body = raw[0x100 + rva:0x100 + frame['end_rva']]
        rows = [dict(rva=hex(i.address), mnemonic=i.mnemonic, operands=i.op_str)
                for i in cs.disasm(body, rva)]
        methods.append(dict(name=name, rva=hex(rva), exact_frame=frame,
                            bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), instructions=rows))
    segments = [dict(name=name, file_offset=a, memory_offset=b, size=c)
                for name, offset in (('text', 0x10), ('rodata', 0x20), ('data', 0x30))
                for a, b, c in (struct.unpack_from('<III', raw, offset),)]
    report = dict(native_source_sha256=digest, methods=methods, segments=segments,
                  source_modified=False, execution_performed=False)
    output = destination(ROOT, ROOT / 'analysis/reconstruction/boolean-reader-reference/native-inventory.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    for method in methods:
        print(method['name'], method['bytes'], method['sha256'])
        for row in method['instructions']:
            print(row['rva'], row['mnemonic'], row['operands'])
    print(json.dumps(segments))


if __name__ == '__main__':
    main()
