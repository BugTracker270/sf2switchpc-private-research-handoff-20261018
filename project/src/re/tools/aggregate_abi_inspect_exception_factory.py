"""Inspect one unchanged runtime factory and extract only its official source pair."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path, PureWindowsPath

import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination
from native_unwind_inventory import Image


def main():
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    raw = (ROOT / 'analysis/nso/main-uncompressed.nso').read_bytes()
    native_hash = hashlib.sha256(raw).hexdigest()
    if native_hash != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original native image changed')
    image = Image(raw)
    frames = [json.loads(line) for line in (ROOT / 'analysis/nso/unwind-inventory-v1/frames.jsonl').read_text().splitlines()]
    frame, = [f for f in frames if f['rva'] == 0xB4D960]
    code = image.read(frame['rva'], frame['end_rva'] - frame['rva'])
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    cs.detail = True
    rows = []
    for instruction in cs.disasm(code, frame['rva']):
        reads, writes = instruction.regs_access()
        rows.append(dict(address=instruction.address, mnemonic=instruction.mnemonic, operands=instruction.op_str,
            bytes_hex=instruction.bytes.hex(), register_reads=[instruction.reg_name(r) for r in reads],
            register_writes=[instruction.reg_name(r) for r in writes]))
    if len(rows) * 4 != len(code):
        raise ValueError('Native helper did not decode completely')
    private_path = destination(ROOT, ROOT / 'analysis/reconstruction/exception-factory-v37/native.json')
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(json.dumps(dict(native_sha256=native_hash, exact_frame=frame,
        code_sha256=hashlib.sha256(code).hexdigest(), instructions=rows, source_modified=False), indent=2) + '\n')
    provenance_path = ROOT / 'reports/unity-2018.1.9f1-archive-provenance.json'
    provenance = json.loads(provenance_path.read_text(encoding='utf-8-sig'))
    archive = ROOT / provenance['archive_path']
    if provenance['status'] != 'PASS_OFFICIAL_ARCHIVE_MD5_WITH_RECORDED_API_SIZE_DELTA' or sha(archive) != provenance['local_sha256']:
        raise ValueError('Verified official archive differs')
    selection = ['Editor\\Data\\il2cpp\\libil2cpp\\vm\\Exception.cpp', 'Editor\\Data\\il2cpp\\libil2cpp\\vm\\Exception.h']
    listing = (ROOT / 'logs/unity-2018.1.9f1-archive-list.log').read_text(encoding='utf-8-sig')
    if not set(selection) <= {line[7:] for line in listing.splitlines() if line.startswith('Path = ')}:
        raise ValueError('Selected official exception source missing')
    output = destination(ROOT, ROOT / 'tools/unity-2018.1.9f1/exception-runtime-source')
    expected = [destination(ROOT, output.joinpath(*PureWindowsPath(s).parts)) for s in selection]
    if not all(p.is_file() for p in expected):
        if output.exists() and any(output.iterdir()):
            raise FileExistsError('Preserve partial extraction')
        output.mkdir(parents=True, exist_ok=True)
        selection_path = destination(ROOT, ROOT / 'tools/unity-2018.1.9f1/selected-exception-runtime-files.txt')
        selection_path.write_text('\n'.join(selection) + '\n', encoding='utf-8')
        result = subprocess.run(['C:/Program Files/7-Zip/7z.exe', 'x', str(archive), '-o' + str(output), '-scsUTF-8', '-aos', '@' + str(selection_path)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        destination(ROOT, ROOT / 'logs/unity-2018.1.9f1-exception-source-extraction.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        if result.returncode != 0:
            raise ValueError('Exact selected extraction failed; log retained')
    if {p for p in output.rglob('*') if p.is_file()} != set(expected):
        raise ValueError('Unexpected extracted files')
    report = dict(status='READ_ONLY_EXACT_RUNTIME_FACTORY_AND_OFFICIAL_SOURCE_PAIR', original_native_sha256=native_hash,
        helper_rva=hex(frame['rva']), helper_end=hex(frame['end_rva']), helper_bytes=len(code), helper_sha256=hashlib.sha256(code).hexdigest(),
        private_native_path=str(private_path.relative_to(ROOT)), private_native_sha256=sha(private_path),
        source_release=provenance['release'], source_revision=provenance['revision'], source_archive_sha256=provenance['local_sha256'],
        source_files=[dict(path=str(p.relative_to(ROOT)), bytes=p.stat().st_size, sha256=sha(p)) for p in expected],
        installer_executed=False, core_modified=False, guest_functions_executed=0, source_uploaded=False)
    def cstring(address):
        data = image.read(address, 256)
        return data.split(b'\0', 1)[0].decode('utf-8')
    constants = {hex(address): cstring(address) for address in (0x2CBF925, 0x2CC3783)}
    if constants != {'0x2cbf925': 'System', '0x2cc3783': 'OverflowException'}:
        raise ValueError('Original factory namespace/type constants differ')
    dependencies = []
    for address in (0xB547A0, 0xB4D660):
        found, = [f for f in frames if f['rva'] == address]
        original = image.read(address, found['end_rva'] - address)
        dependencies.append(dict(start=hex(address), end=hex(found['end_rva']), bytes=len(original), sha256=hashlib.sha256(original).hexdigest(),
            instructions=[dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str, bytes_hex=i.bytes.hex()) for i in cs.disasm(original, address)]))
    caller_frame, = [f for f in frames if f['rva'] == 0x4A0D70]
    caller = list(cs.disasm(image.read(0x4A0D70, caller_frame['end_rva'] - 0x4A0D70), 0x4A0D70))
    call_index, = [i for i, row in enumerate(caller) if row.mnemonic == 'bl' and row.op_str == '#0xb4d960']
    caller_rows = [dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str, bytes_hex=i.bytes.hex()) for i in caller[max(0, call_index-5):call_index+4]]
    dependencies_path = destination(ROOT, ROOT / 'analysis/reconstruction/exception-factory-v37/dependencies-and-caller.json')
    dependencies_path.write_text(json.dumps(dict(constants=constants, dependencies=dependencies, reader_call_window=caller_rows), indent=2) + '\n')
    report.update(constants=constants, private_dependencies_path=str(dependencies_path.relative_to(ROOT)), private_dependencies_sha256=sha(dependencies_path),
        reader_call_rva=hex(caller[call_index].address),
        dependencies=[{key: row[key] for key in ('start', 'end', 'bytes', 'sha256')} for row in dependencies])
    destination(ROOT, ROOT / 'reports/exception-factory-native-source-inventory-v37.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    for row in rows:
        print(hex(row['address']), row['mnemonic'], row['operands'])


if __name__ == '__main__':
    main()
