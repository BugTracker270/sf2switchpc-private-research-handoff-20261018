"""Design-only original call-result receiver evidence; no Core/game execution."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination


def path(relative: str) -> Path:
    return destination(ROOT, ROOT / relative)


def digest(relative: str) -> str:
    result = hashlib.sha256()
    with path(relative).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def load(relative: str):
    return json.loads(path(relative).read_text(encoding="utf-8-sig"))


inventory = load("analysis/reconstruction/virtual-copy-root-v38/native-inventory.json")
native = next(method for method in inventory["methods"] if method["start"] == 0x15CA570)
assert native["bytes"] == 108 and native["end"] == 0x15CA5DC
assert native["sha256"] == "f821c50fecebb7edfeb7c42c5611624b1495d4c2266ff7895fcd7c8347d99909"
assert inventory["native_sha256"] == digest("analysis/nso/main-uncompressed.nso")
instructions = {row["address"]: row for row in native["instructions"]}
assert instructions[0x15CA590]["mnemonic"] == "blr"
assert instructions[0x15CA594]["mnemonic"] == "ldr" and instructions[0x15CA594]["operands"] == "x8, [x0]"
assert instructions[0x15CA598]["mnemonic"] == "ldp" and instructions[0x15CA598]["operands"] == "x9, x1, [x8, #0x178]"
assert instructions[0x15CA59C]["mnemonic"] == "blr"
graph_path = "analysis/il2cpp/virtual-companion-FirstAttribute-after-type-v38.txt"
graph = path(graph_path).read_text(encoding="utf-8")
assert re.search(r"^12 Call XmlNode\.get_Attributes, v15 @ X0_v4 \(System\.Xml\.XmlAttributeCollection\)", graph, re.M)
assert re.search(r"^13 Move .*\[v15 @ X0_v4 \(System\.Xml\.XmlAttributeCollection\)\]", graph, re.M)
assert re.search(r"^16 IndirectCall .*v15 @ X0_v4 \(System\.Xml\.XmlAttributeCollection\)", graph, re.M)
dump = path("analysis/il2cpp/effective-main/dump.cs").read_text(encoding="utf-8-sig")
named_map = dump.split("public class XmlNamedNodeMap : IEnumerable", 1)[1].split("// Namespace:", 1)[0]
assert "RVA: 0x2E6350" in named_map and "Slot: 5" in named_map and "public virtual int get_Count()" in named_map
inspection = load("reports/recovered-virtual-companion-nso-virtual-companion-copy-v38.json")
assert inspection["status"] == "PASS_ACTUAL_COPIED_COMPANION_CALLVIRT_AND_UNCHANGED_SCOPE_CORRELATION"
assert inspection["actual"]["FirstGetterVirtual"] == 2 and inspection["actual"]["First178"] == 1
production = load("reports/virtual-companion-production-v38.json")
assert production["status"] == "PASS_ORIGINAL_COMPANION_COPY_THROUGH_PRODUCTION_WITH_SCOPE_REJECTIONS"
helper = path("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64VirtualDispatch.cs").read_text(encoding="utf-8-sig")
assert "witness.SameParameter" in helper and "ParameterRoot" in helper

conditions = [
    "Keep the existing parameter-root path and all exact slot/class/function/companion, target ABI, validated ancestor-cone and pure-window guards unchanged.",
    "Add a separately tagged CallResult origin; never interpret an arbitrary typed local or legacy ParameterRoot default as a call-result proof.",
    "Trace receiver and class-load base independently through bounded unique available local Move copies to one identical LocalVariable object, not matching names/registers/types alone.",
    "Initial call-result origins must be in the same original dispatch block and be strictly defined before the class dereference; reject Phi, field/array/memory roots, arithmetic, conversions, undefined locals and cycles.",
    "The root must have exactly one original defining managed Call, remain its exact Destination and have the exact closed reference ReturnType of its captured managed target.",
    "The producer target must be a resolved metadata method, not a numeric runtime helper, delegate/invoke pseudo-target, open generic, constructor, void or byref/pointer/value-type result.",
    "Initial producer eligibility can be limited to an ordinary nonvirtual direct managed call or an already proven parameter-root native virtual call. Defer multi-producer chains rather than introduce recursive proof cycles.",
    "If producer is virtual, capture its existing immutable virtual proof and revalidate it. Do not accept a virtual producer whose dispatch proof has disappeared or whose target/receiver changed.",
    "The original producer instruction, original managed target, exact root/type and producer dispatch identity must all be retained in the carrier and rechecked at final emission.",
    "Retain all producer calls and their effects at original positions. No inlining, duplicate evaluation, common-subexpression merging, target substitution or fault movement is required.",
    "The pure effect window still starts at original class dereference and ends at native virtual dispatch. It must reject field writes, other calls, stores, unsupported instructions and reordered class/slot reads.",
    "Track each root/copy through the existing whole-graph address escape scan, including paths after the dispatch. A same-type second call result is not interchangeable.",
    "Protect call-result root locals from CopyCoalescer physical-register merges after SSA destruction, extending the existing parameter-root exclusion without protecting unrelated locals.",
    "Keep immutable carrier copy behavior; a graph clone that does not explicitly preserve/rebind the original producer/root identities must fail closed rather than use stale references.",
    "Bound total local/producer tracing and reject inconsistent topology or availability at every use. Do not memoize away per-use order/dominance checks.",
    "Consumer target remains parameterless, nonvoid integer/reference X0 result only, with existing no-interface/no-generic/no-value/no-pointer/byref restrictions; FP, void and explicit arguments remain deferred.",
]
negatives = [
    "same declared type from a different producer", "second same-target call replacing original producer", "producer target or return type mutated after proof", "producer destination changed after proof",
    "producer removed from graph", "producer changed to CallVoid", "producer is unresolved numeric helper", "producer is unproven virtual Call", "producer virtual proof stripped or stale receiver",
    "producer after class load or use", "producer in another block", "duplicate defining local", "local Phi or copy cycle", "open generic/interface/value/byref/pointer producer result", "constructor/invoke pseudo-producer",
    "receiver and class source reach different roots", "copy late or undefined before use", "root/copy address escape before or after call", "class-slot pure window gains field store or call", "wrong slot/companion/class",
    "stale carrier target/owner/opcode", "same-register coalescing merges a distinct producer", "clone retains stale producer/root without explicit mapping", "oversized local/producer trace", "multi-level call-result provenance in first narrow release",
]
report = {
    "status": "DESIGN_ONLY_TYPED_UNIQUE_CALL_RESULT_RECEIVER_ROOT",
    "recovery_implemented": False, "core_modified": False, "game_methods_executed": 0, "native_functions_executed": 0, "full_clean_decompile_ready": False,
    "original_case": {
        "caller": "XmlExtensions.FirstAttribute(System.Xml.XmlNode)", "native_start": "0x15CA570", "native_end": "0x15CA5DC", "native_bytes": 108, "native_sha256": native["sha256"],
        "producer_call": "0x15CA590", "class_load": "0x15CA594", "function_companion_load": "0x15CA598", "consumer_dispatch": "0x15CA59C",
        "return_receiver_register": "X0", "slot": 5, "function_offset": "0x178", "companion_offset": "0x180",
        "producer_target": "System.Xml.XmlNode.get_Attributes()->System.Xml.XmlAttributeCollection", "consumer_target": "System.Xml.XmlNamedNodeMap.get_Count()->System.Int32", "consumer_registered_rva": "0x2E6350",
        "actual_ir_producer": 12, "actual_ir_result_local": "v15/X0_v4", "actual_ir_class_load": 13, "actual_ir_consumer": 16,
        "producer_and_consumer_same_original_block": True, "consumer_currently_indirect": True, "two_existing_parameter_getters_preserved": True,
        "private_graph": graph_path, "private_graph_sha256": digest(graph_path),
    },
    "proposed_carrier": {
        "api": "TryProve and ValidForEmission signatures may remain unchanged; use a tagged receiver-origin payload in NativeVirtualDispatchProof.",
        "parameter_branch": "Retain existing exact ParameterRoot identity and validation.",
        "call_result_branch_fields": ["exact root LocalVariable", "exact closed reference TypeAnalysisContext", "exact defining Instruction", "exact managed MethodAnalysisContext target", "original producer virtual proof when present"],
        "final_emitter_check": "Re-trace current receiver copies to captured root; re-find unique available producer and captured target/destination/type; revalidate original producer dispatch before allowing existing callvirt emission.",
        "copy_coalescer": "Protect both origin root kinds from same-slot merges, preserving current parameter protections.",
        "initial_chain_limit": "One managed call-result layer; any virtual producer must retain the existing parameter-root proof. Longer chains are a separately bounded extension.",
    },
    "required_guards": conditions,
    "required_negative_fixtures": negatives,
    "proposed_acceptance": [
        "All existing69 selections/276 checks/99 authored CLR controls remain unchanged and pass.",
        "New positive direct-result and already-proven virtual-result witnesses pass; negative producer/receiver/carrier/cloning/null-timing cases fail closed.",
        "Original FirstAttribute Count16 becomes a valid slot5 proof at after-type and final emitter input; both original getter12/33 identities, null and Count<1 branches and direct indexer argument0 remain exact.",
        "Unchanged native getter/Count fixtures, if feasible at explicit initialized-field boundaries, must run original callees rather than replace guest functions. Native allocation/error paths remain separate until proved.",
        "Fresh actual CIL must show the original metadata Count callvirt, preserve both getter callvirt sites and null/count/tail behavior. No source/CIL rewrites may substitute for that gate.",
        "A separately reviewed unchanged whole-helper host XML invocation can test empty/nonempty/null-Attributes and repeated getter effects, but must label host System.Xml behavior separately from native parity.",
    ],
    "limitations": "Design and original native/metadata/actual-IR correlation only. Current v38 Count remains unresolved. No new carrier, origin proof, caller CIL or native Count execution has been implemented. Body null-fault timing and side effects must remain ordered; reference return type alone proves neither receiver identity nor virtual dispatch.",
    "bindings": {
        "core_sha256": production["core_sha256"], "helper_source_sha256": digest("refs/Cpp2IL/Cpp2IL.Core/Utils/LegacyArm64VirtualDispatch.cs"),
        "native_inventory_sha256": digest("analysis/reconstruction/virtual-copy-root-v38/native-inventory.json"), "original_native_sha256": inventory["native_sha256"],
        "metadata_dump_sha256": digest("analysis/il2cpp/effective-main/dump.cs"), "actual_v38_cil_report_sha256": digest("reports/recovered-virtual-companion-nso-virtual-companion-copy-v38.json"),
        "source_sha256": digest("src/re/tools/aggregate_abi_virtual_call_result_design.py"),
    },
}
path("reports/virtual-call-result-root-design-v39.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
path("reports/virtual-call-result-root-design-v39.md").write_text(
    "# Typed unique call-result receiver design\n\n"
    "Design only. The original FirstAttribute108-byte body passes the getter result in X0 directly into the slot5 Count dispatch. Current v38 IR has one typed getter Call12, its exact result local used by the class read13 and unresolved virtual Call16. Metadata declares XmlNamedNodeMap.get_Count as slot5 with Int32 return.\n\n"
    "A separately tagged call-result origin can preserve the existing parameter path. Bind the unique original producer instruction/target/destination/reference return type, independently trace the receiver and class source to that same immutable local, and retain original slot/companion, pure-window, availability and escape guards. Revalidate producer provenance at emission and protect its root during copy coalescing. Limit the initial extension to one producer layer; already-proven parameter-root virtual producers are the concrete FirstAttribute case.\n\n"
    f"The JSON lists{len(conditions)} required guards and{len(negatives)} negative fixture families. Current Count remains unresolved; no Core code or original inputs were edited and no new native/managed case was executed. Full native disassembly and IR remain in ignored analysis.\n", encoding="utf-8")
print(json.dumps({"status": report["status"], "guards": len(conditions), "negative_families": len(negatives), "current_consumer_unresolved": True}))
