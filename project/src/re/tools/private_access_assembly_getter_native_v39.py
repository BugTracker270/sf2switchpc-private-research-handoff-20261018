"""Bounded original internal reference getter witness; no game runtime substitutes."""
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src/tools"))
sys.path.insert(0, str(ROOT / "tools/python-unicorn-2.1.4"))
from usb_boundary import destination
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X30, UC_ARM64_REG_PC


def main():
    raw = (ROOT / "analysis/nso/main-uncompressed.nso").read_bytes()
    native_hash = hashlib.sha256(raw).hexdigest()
    if native_hash != "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968":
        raise ValueError("Original native image differs")
    address = 0x1E6850
    body = raw[0x100 + address:0x108 + address]
    if body.hex() != "001040f9c0035fd6":
        raise ValueError("Original exact internal getter differs")
    frames = []
    with (ROOT / "analysis/nso/unwind-inventory-v1/frames.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row["rva"] == address:
                frames.append(row)
    if len(frames) != 1 or frames[0]["end_rva"] != address + len(body):
        raise ValueError("Exact native FDE extent differs")
    vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    vm.mem_map(address & ~0xFFF, 0x1000)
    vm.mem_write(address, body)
    vm.mem_protect(address & ~0xFFF, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    heap, stop = 0x10000000, 0x30000000
    vm.mem_map(heap, 0x1000)
    vm.mem_map(stop, 0x1000)
    writes = []
    vm.hook_add(UC_HOOK_MEM_WRITE, lambda vm, access, at, size, value, context: writes.append((at, size)))
    generator = random.Random(address)
    values = [0, 1, heap, (1 << 63), (1 << 64) - 1] + [generator.getrandbits(64) for _ in range(123)]
    checks = 0
    for value in values:
        storage = bytearray(generator.getrandbits(8) for _ in range(0x50))
        struct.pack_into("<Q", storage, 0x20, value)
        vm.mem_write(heap, bytes(storage))
        writes.clear()
        vm.reg_write(UC_ARM64_REG_X0, heap)
        vm.reg_write(UC_ARM64_REG_X1, generator.getrandbits(64))
        vm.reg_write(UC_ARM64_REG_X30, stop)
        vm.emu_start(address, stop, count=3)
        if vm.reg_read(UC_ARM64_REG_PC) != stop:
            raise AssertionError("Getter did not return")
        checks += 1
        if vm.reg_read(UC_ARM64_REG_X0) != value:
            raise AssertionError("Getter returned another payload")
        checks += 1
        if writes or bytes(vm.mem_read(heap, len(storage))) != storage:
            raise AssertionError("Getter changed receiver storage")
        checks += 1
    vm.reg_write(UC_ARM64_REG_X0, 0)
    vm.reg_write(UC_ARM64_REG_X30, stop)
    null_fault = False
    try:
        vm.emu_start(address, stop, count=3)
    except UcError:
        null_fault = vm.reg_read(UC_ARM64_REG_PC) == address
    if not null_fault or writes:
        raise AssertionError("Null receiver did not fault at original field load")
    report = {"status": "PASS_ORIGINAL_INTERNAL_REFERENCE_LEAF_GETTER",
        "native_source_sha256": native_hash, "native_code_sha256": hashlib.sha256(body).hexdigest(),
        "native_rva": "0x1E6850", "native_bytes": len(body), "exact_fde_size": frames[0]["end_rva"] - address,
        "field_offset": "0x20", "cases": len(values), "checks": checks,
        "null_receiver_original_load_fault": null_fault, "guest_function_replacements": 0,
        "native_code_unmodified": True, "managed_methods_invoked": 0,
        "source_tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": "Only original two-instruction internal JsonSerializerInternalBase.Serializer getter executes against valid supplied receiver bytes. Reference payloads are opaque bit patterns; X1 is varied and unused. Receiver bytes remain unchanged. Null receiver faults at original LDR. No GC, constructor, owner initialization, caller accessibility, emitted call, full method or whole-game parity is claimed."}
    output = destination(ROOT, ROOT / "reports/native-assembly-leaf-getter-v39.json")
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
