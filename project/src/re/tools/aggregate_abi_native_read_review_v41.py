"""Sanitized source-only review evidence for the original native read carrier."""
from pathlib import Path
import difflib
import hashlib
import json
import sys
import subprocess

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination
from native_unwind_inventory import Image


def path(relative):
    return destination(ROOT, ROOT / relative)


def sha(relative):
    return hashlib.sha256(path(relative).read_bytes()).hexdigest()


files = ["ISIL/MemoryOperand.cs", "InstructionSets/NewArmV8InstructionSet.cs"]
passes = ["SsaForm", "LocalVariables", "SsaSimplifier", "CopyCoalescer", "Simplifier"]
files += [f"Analysis/{name}.cs" for name in passes]
snapshot = "analysis/il2cpp/object-isinst-abi-v40-source-snapshot/refs/Cpp2IL/Cpp2IL.Core/"
patch = []
bindings = []
for relative in files:
    live = "refs/Cpp2IL/Cpp2IL.Core/" + relative
    old = snapshot + relative
    if path(old).exists():
        original = path(old).read_bytes()
        original_source = old
    else:
        # Frozen manifest captures modified candidate paths; previously unchanged
        # files are still the pinned upstream Git blob, not reconstructed game code.
        original = subprocess.run(["git", "-C", str(path("refs/Cpp2IL")), "show", "HEAD:Cpp2IL.Core/" + relative],
                                  check=True, capture_output=True).stdout
        original_source = "refs/Cpp2IL Git HEAD:Cpp2IL.Core/" + relative
    before = original.decode("utf-8-sig").replace("\r\n", "\n").splitlines(keepends=True)
    after = path(live).read_text(encoding="utf-8-sig").splitlines(keepends=True)
    patch.extend(difflib.unified_diff(before, after, fromfile="a/Cpp2IL.Core/" + relative,
                                      tofile="b/Cpp2IL.Core/" + relative))
    bindings.append(dict(path=live, sha256=sha(live), baseline_source=original_source,
                         baseline_sha256=hashlib.sha256(original).hexdigest()))
    if relative.startswith("Analysis/"):
        assert "memory.Base =" not in "".join(after)
        assert "memory.RebindBaseForProvenCopy(" in "".join(after)
patch_path = "patches/experimental-native-read-proof-v41.patch"
path(patch_path).parent.mkdir(parents=True, exist_ok=True)
path(patch_path).write_text("".join(patch), encoding="utf-8")

raw = path("analysis/nso/main-uncompressed.nso").read_bytes()
assert hashlib.sha256(raw).hexdigest() == "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968"
image = Image(raw)
examples = []
for address, expected_width in [(0x11A4D80, 8), (0x11A4D84, 8), (0x11A4D94, 4)]:
    native = image.read(address, 4)
    word = int.from_bytes(native, "little")
    assert word & 0xBFC00000 == 0xB9400000
    width = 8 if word & 0x40000000 else 4
    assert width == expected_width
    examples.append(dict(address=hex(address), access_width_bytes=width,
                         byte_sha256=hashlib.sha256(native).hexdigest(),
                         accepted_unsigned_pointer_shape=word & 0xFFC00000 == 0xF9400000))

report = dict(
    status="SOURCE_ONLY_NATIVE_READ_CARRIER_AND_CHECKED_REBIND_PENDING_BUILD_CONTRACT",
    baseline_run="nso-object-isinst-abi-v40",
    baseline_core_sha256="14232d46ca291ffb67944705e94ec5460bc8ee70c3df88ee3ef27e77b6e736d6",
    sources=bindings, patch_path=patch_path, patch_sha256=sha(patch_path),
    source_api=dict(carrier="MemoryOperand.NativeReadProof", field="MemoryOperand.NativeRead",
                    factory="NativeReadProof.TryCreate(owner, nativeAddress, source)",
                    validation="proof.ValidFor(owner, currentMemory)",
                    internal_rebind="memory.RebindBaseForProvenCopy(replacement)",
                    immutable_original_facts=["exact MethodAnalysisContext owner", "native virtual address", "native instruction word",
                                              "unsigned read width 8", "original native base/destination register names", "unsigned offset"],
                    derived_fact="immutable BoundBase: Register value identity through SSA; LocalVariable reference identity after local creation",
                    original_base_name_is_not_final_ssa_name=True),
    original_load_width_examples=examples,
    transformation_sites=[dict(path="refs/Cpp2IL/Cpp2IL.Core/Analysis/" + name + ".cs",
                               original_base_writes_replaced=1) for name in passes],
    validation_contract=[
        "Existing opt-in NSO24 pointer-size8 and cached exact reviewed image/helper gate; owner-selected exact FDE bounds.",
        "Native address alignment and current native word re-read; only unsigned-offset64-bit LDR X with non-SP base/non-ZR destination.",
        "Original seed requires an unversioned native Register matching raw base; NewArm separately matches decoded raw destination.",
        "Current memory must attach this carrier and match exact immutable BoundBase, addend, absent index/scale and absent scalar-FP tag.",
        "Only five existing proven renaming/copy sites derive a fresh immutable binding after validating the old attached carrier and old base.",
        "Direct untracked base mutation stays stale and cannot be blessed by subsequent rebinding; no-proof behavior remains the original base replacement.",
        "Copying or inlining the complete MemoryOperand preserves the carrier reference; it does not prove safe memory-effect motion.",
        "Fresh-array ownership/availability/escape/type/control semantics require the separate bounded origin proof; width evidence supplies none of those claims.",
    ],
    negative_contract_required=["wrong owner", "wrong address/alignment/FDE", "changed native word/image", "32-bit/byte/halfword/signed/FP/vector/pair/literal/indexed/writeback load",
                                "SP base or ZR destination", "changed addend/index/scale/FP tag", "stale direct Base mutation", "same-register different SSA version", "same-type different LocalVariable reference",
                                "stale proof rebound after a direct mutation", "attempt to seed from a pretyped LocalVariable", "whole-memory-copy retention", "all five checked-renaming paths"],
    core_built=False, contracts_run=False, full_recovery_run=False, recovered_game_or_native_functions_executed=0,
    original_cil_modified=False, managed_semantic_lowering=False, production_ready=False,
)
report_path = "reports/native-integer-read-carrier-design-v41.json"
path(report_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(dict(status=report["status"], files=len(bindings), patch=patch_path, patch_sha256=sha(patch_path))))
