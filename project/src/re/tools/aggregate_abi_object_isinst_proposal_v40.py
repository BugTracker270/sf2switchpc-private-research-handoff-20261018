"""Sanitized exact ABI proposal; no semantic lowering, Core edits or execution."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import sys
import capstone

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination
from native_unwind_inventory import Image


def path(relative):
    return destination(ROOT, ROOT / relative)


def sha(relative):
    return hashlib.sha256(path(relative).read_bytes()).hexdigest()


def load(relative):
    return json.loads(path(relative).read_text(encoding="utf-8-sig"))


source = load("reports/object-isinst-official-source-v40.json")
assert source["status"] == "PASS_PINNED_OFFICIAL_OBJECT_ISINST_SOURCE_READ_ONLY"
cpp = path(source["source_files"][0]["private_path"]).read_text(encoding="utf-8", errors="replace")
header = path(source["source_files"][1]["private_path"]).read_text(encoding="utf-8", errors="replace")
assert "Il2CppObject* Object::IsInst(Il2CppObject *obj, Il2CppClass *klass)" in cpp
assert "Il2CppObject * IsInst(Il2CppObject *obj, Il2CppClass *klass)" in header
body = cpp.split("Il2CppObject* Object::IsInst(", 1)[1].split("Il2CppObject* Object::New(", 1)[0]
for token in ("if (!obj)", "Class::IsAssignableFrom(klass, objClass) ? obj : NULL", "Class::IsInterface(klass)", "RCW::QueryInterface<false>", "unknown->Release()", "klass == il2cpp_defaults.object_class"):
    assert token in body
ir = load("reports/object-isinst-actual-ir-v38.json")
assert ir["discovered_object_is_inst"] == "0x0" and ir["native_B5B390_registered_aliases"] == []
assert ir["core_sha256"] == "197403735d374bdde681ad203cdb3eb18e8cd9eef01897908a8c4f9e786ad99a"
assert ir["methods"][0]["numeric_isinst_calls"] == 28 and set(ir["methods"][0]["helper_operand_counts"]) == {18}
graph = path(ir["methods"][0]["after_ir"]).read_text()
for token in ("61 Move v68", "62 Move v69", "63 Call B5B390, v70", "[v68 @ X8_v351 (Il2CppClass<System.String[]>)+40]", "64 CheckEqual"):
    assert token in graph
survey = load("reports/compiler-mechanism-survey-v38.json")
assert [a["unique_diagnostic_lines"] for a in survey["assemblies"]] == [20728, 32710]
raw = path("analysis/nso/main-uncompressed.nso").read_bytes()
assert hashlib.sha256(raw).hexdigest() == "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968"
image = Image(raw)
frames = [json.loads(line) for line in path("analysis/nso/unwind-inventory-v1/frames.jsonl").read_text().splitlines()]
frame_map = {f["rva"]: f for f in frames}
cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
private_rows = []
for address in (0xB5B390, 0xB05920, 0xB05B80, 0x9056A0, 0xB4DA50):
    frame = frame_map[address]
    code = image.read(address, frame["end_rva"] - address)
    rows = [dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str, bytes_hex=i.bytes.hex()) for i in cs.disasm(code, address)]
    assert len(rows) * 4 == len(code)
    private_rows.append(dict(start=address, end=frame["end_rva"], bytes=len(code), sha256=hashlib.sha256(code).hexdigest(), frame=frame, instructions=rows))
helper = private_rows[0]
assert helper["bytes"] == 244 and helper["end"] == 0xB5B484 and helper["sha256"] == "1b265abeee0dfb0991ffe2b237b6cf3f817a9a5071eb8787a2dc28b87d9cbec6"
anchor = private_rows[3]
assert not any(r["mnemonic"] == "bl" for r in anchor["instructions"])
native_candidates = load("analysis/reconstruction/compiler-family-v38/native-candidates.json")
profile = native_candidates[1]
rows = {r["address"]: r for r in profile["instructions"]}
assert rows[0x11A4D88]["mnemonic"] == "bl" and rows[0x11A4D88]["operands"] == "#0xb5b390"
assert rows[0x11A4D80]["operands"] == "x8, [x20]" and rows[0x11A4D84]["operands"] == "x1, [x8, #0x40]"
assert rows[0x11A4D8C]["mnemonic"] == "cbz" and rows[0x11A4D8C]["operands"] == "x0, #0x11a5c54"
assert rows[0x11A5C54]["mnemonic"] == "bl" and rows[0x11A5C54]["operands"] == "#0xb4da50"
assert rows[0x11A4D94]["operands"] == "w8, [x20, #0x18]" and rows[0x11A4DAC]["operands"] == "x21, [x20, #0x20]"
class_header = "tools/unity-2018.1.9f1/common-runtime-source/Editor/Data/il2cpp/libil2cpp/il2cpp-class-internals.h"
class_source = "tools/unity-2018.1.9f1/common-runtime-source/Editor/Data/il2cpp/libil2cpp/vm/Class.cpp"
assert "Il2CppClass* element_class" in path(class_header).read_text()
dump = path("analysis/il2cpp/effective-main/dump.cs").read_text(encoding="utf-8-sig")
assert not re.search(r"RVA: 0xB5B390\b", dump)
array_match = re.search(r"^(?:public|internal).*\bclass Array\s*:", dump, re.M)
array_metadata = []
if array_match:
    array_block = dump[array_match.start():].split("// Namespace:", 1)[0]
    for address, declaration in re.findall(r"// RVA: 0x([0-9A-F]+).*\n\t([^\n]+)", array_block):
        array_metadata.append((int(address, 16), declaration.strip()))
call_corpus = load("analysis/reconstruction/compiler-family-v38/array-helper-call-corpus.json")
caller_counts = {row["start"]: row["calls"] for row in call_corpus["enclosing_exact_frames"]}
array_callers = [dict(rva=hex(address), declaration=declaration, matching_bl_encodings=caller_counts[address]) for address, declaration in array_metadata if address in caller_counts]
private = path("analysis/reconstruction/compiler-family-v38/object-isinst-dependencies.json")
private.write_text(json.dumps(dict(dependencies=private_rows, original_profile_native_window=[r for r in profile["instructions"] if 0x11A4D70 <= r["address"] <= 0x11A4DAC or 0x11A5C54 <= r["address"] < 0x11A5C74], system_array_metadata_callers=array_callers), indent=2) + "\n")
casts = [a["exact_source_vicinity_counts"] for a in survey["assemblies"]]
proposal = dict(
    status="EVIDENCE_BACKED_EXACT_OBJECT_ISINST_ABI_ONLY_NEXT_CANDIDATE", recovery_implemented=False, core_modified=False, game_or_native_functions_executed=0, semantic_lowering_implemented=False, full_clean_decompile_ready=False,
    exact_native=dict(start="0xB5B390", end="0xB5B484", bytes=244, sha256=helper["sha256"], original_image_sha256=hashlib.sha256(raw).hexdigest(), registered_method_aliases=0, dump_registered_pointer_matches=0),
    official_contract=dict(release=source["release"], revision=source["revision"], archive_sha256=source["archive_sha256"], declaration="Il2CppObject* il2cpp::vm::Object::IsInst(Il2CppObject* obj, Il2CppClass* klass)", definition_lines=[203,228], declaration_line=23, source_files=source["source_files"]),
    existing_discovery=dict(field="BaseKeyFunctionAddresses.il2cpp_vm_object_is_inst", observed_result="0x0", frozen_core_sha256=ir["core_sha256"], anchor="System.Type.IsInstanceOfType", anchor_rva="0x9056A0", anchor_bytes=anchor["bytes"], anchor_sha256=anchor["sha256"], anchor_bl_count=0, explanation="Existing ARM64 finder chooses the final BL in this metadata body; original Switch Type.IsInstanceOfType body has no BL, so the hook yields0. Exact pinned fallback needs independent image/FDE/body validation; do not globally treat this discovery heuristic as identity proof."),
    native_abi=dict(argument0="X0: original Il2CppObject* value, possibly null", argument1="X1: Il2CppClass* target", return_value="X0: same original object pointer or null; not Boolean", incoming_x2_plus="No incoming X2-X7/V0-V7 argument dependency in this exact helper. X2 is assigned a local out-pointer on the COM path before use; assert paths set their own values.", null_contract="Null input returns null before reading either object class or target class.", effects=["Class::IsAssignableFrom for ordinary objects, including metadata Class::Init and generic/interface/array assignability rules", "COM/WinRT class classification and interface QueryInterface", "Release on successful queried interface", "object-class fallback for imported objects", "assertion failure paths in malformed COM state"]),
    proposed_abi_shield=dict(known_exact_target_only=True, preserve_numeric_diagnostic=True, preserve_existing_destination_identity=True, preserve_original_x0_x1_source_identities=True, trim_only_verified_raw_capture_suffix="From exact18operand target/result/X0-X7/V0-V7 layout to target/result/originalX0/originalX1", nominal_return_type="Canonical System.Object only when result type is unknown or already canonical; reject conflicting declared types", class_argument="Preserve exact X1 native class operand and unresolved loads. ABI recognition alone does not convert an unknown or runtime-dependent class into System.Type/static metadata.", carrier="Use existing immutable exact-ABI carrier/clone/emitter validation pattern; reject stale target/owner/opcode/result/source identities or noncanonical raw layout.", layout_guard="Original opt-in legacy NSO24 plus image/FDE/body hash. Check aliases before generic method lookup; no helper name guess or ABI inference from nearby methods.", semantics="None. Keep call effect and diagnostic; never replace return with default/null/Boolean or delete the call. Existing key-function field may expose validated identity but does not replace exact fallback proof."),
    original_caller=dict(owner="InControl.PlayStation4MacBTProfile..ctor", rva="0x11A4CC0", original_numeric_calls=28, current_operand_count=18, first_call_rva="0x11A4D88", first_call_ir_index=63, class_read_ir_index=61, target_element_class_ir_index=62, object_input="Original OS X string inX0 /v66", class_input="Original runtime array objectv65→klassv68→[klass+0x40]v69 inX1; this local remains untyped", exact_result="v70/X0_v347 remains live in original CheckEqual64 and failure branch65", exception_order="Original type-test failure leads toB4DA50 at11A5C54 before the array length read11A4D94 and original element store11A4DAC.", element_class_layout="Original pointer-size8 Class prefix: image/gc_desc/name/namespaze plus two16-byte Il2CppType values place element_class at0x40, independently matching native loads.", private_ir=ir["methods"][0]["after_ir"], private_ir_sha256=ir["methods"][0]["after_sha256"]),
    observed_coverage=dict(canonical_diagnostics=[20728,32710], total_diagnostics=53438, array_to_nint_diagnostic_occurrences=sum(r["array_to_nint_total"] for r in casts), array_to_nint_B5B390_within4lines=sum(r["array_to_nint_with_B5B390_within4lines"] for r in casts), distinct_exported_owner_groups=[a["array_helper_distinct_owner_groups"] for a in survey["assemblies"]], matching_original_BL_encodings=len(call_corpus["direct_calls"]), enclosing_original_FDEs=len(caller_counts), interpretation="These are exact log/source associations and matching BL instruction encodings inside text/FDE ranges. They are not independent bugs, proof of full reachability, guaranteed eliminated diagnostics or a completion percentage."),
    semantic_phase_deferred=dict(static_metadata_target="A separate original metadata-origin proof might support exact CIL isinst for a known closed target, with result/null/effect/type validation.", runtime_array_target="The target is actual runtime array element_class, not the array expression's static ElementType. A future semantic representation must preserve this dynamic target or explicitly prove exact freshly allocated array identity without covariance/escape.", array_store_fusion="Do not fuse into stelem.ref merely because it also checks covariance: preserve original type-check versus bounds/null exception order and exact source/index/store/return uses.", system_array_metadata_functions=len(array_metadata), system_array_metadata_caller_count=len(array_callers), system_array_metadata_callers=array_callers),
    concrete_counterexamples=[
        "An object[] reference holding a string[] cannot use isinst System.Object for a boxed Int32 store: runtime target String rejects it.",
        "Wrong element type plus out-of-range index can distinguish original pre-bounds type check from a blindly fused stelem.ref check order.",
        "IsInst result is the original object or null; replacing it with Boolean breaks casts/stores/identity consumers outside null-test-only array guards.",
        "Null object input must not eagerly dereference an invalid/unknown target class, since original helper exits before those reads.",
        "Imported COM/WinRT objects can invoke QueryInterface/Release and assertion paths; no purity assumption or host substitution follows from this ABI proof.",
        "Class metadata from a Phi, generic context, unrelated class field, mismatched array, indexed/mutated source, cross-use or address escape cannot establish a static managed target.",
        "Object arithmetic errors also arise independently from missing field/load/FP-flag semantics; correcting this helper does not type all object-valued integer masks.",
    ],
    other_independent_gap=dict(owner="Vector3f.get_Length", rva="0x15C5AE0", evidence="Original FSQRT S1,S0 then FCMP S1,S1/B.VS; current decoder sends FCMP through integer EmitCompareFlags and emits Single XOR/AND overflow formulas. FSQRT itself is NotImplemented, so stale S1 contributes the previous product. This is not a bitcast or array ABI problem.", private_ir=ir["methods"][1]["after_ir"], private_ir_sha256=ir["methods"][1]["after_sha256"], required_future_scope="Typed floating compare/unordered flag model and real sqrt/FPrelated ABI recovery, with NaN/inf/signed-zero fixtures; no blanket casts."),
    bindings=dict(survey_report_sha256=sha("reports/compiler-mechanism-survey-v38.json"), actual_ir_report_sha256=sha("reports/object-isinst-actual-ir-v38.json"), official_source_report_sha256=sha("reports/object-isinst-official-source-v40.json"), private_native_dependencies=str(private.relative_to(ROOT)), private_native_sha256=hashlib.sha256(private.read_bytes()).hexdigest(), official_class_header_sha256=sha(class_header), official_class_source_sha256=sha(class_source), source_sha256=sha("src/re/tools/aggregate_abi_object_isinst_proposal_v40.py")))
path("reports/object-isinst-native-source-proposal-v40.json").write_text(json.dumps(proposal, indent=2) + "\n", encoding="utf-8")
path("reports/object-isinst-native-source-proposal-v40.md").write_text(
    "# Exact Object::IsInst ABI candidate\n\n"
    "Pinned official Unity2018.1.9f1 source and original244-byte FDE0xB5B390..0xB5B484 agree on Object*(Object*,Class*): X0 original object/null, X1 target class, X0 same object/null return. The legacy finder currently returns0 because its Type.IsInstanceOfType anchor has no BL. There are no registered method aliases at this target.\n\n"
    "The first safe phase is ABI-only: retain the numeric diagnostic/effect and original X0 destination plus original X0/X1 arguments; discard only the verified raw capture suffix and seed a conflict-checked canonical Object result. No isinst/array-store semantics are restored by this step. COM/WinRT queries, Release, metadata initialization and assertion paths remain unresolved effects.\n\n"
    "The selected original constructor contains28 eighteen-operand calls. Its first X1 is a unique native/SSA runtime array klass.element_class load at+0x40. Fresh logs contain3,355 array-to-nint diagnostics within four lines of this helper (3,508 total); the text-word inventory has13,188 matching BL encodings in4,783 original FDEs. These are associations, not expected diagnostic reductions or proof of semantic recovery.\n\n"
    "A later semantic phase must preserve runtime covariance, object/null identity and original type-failure-before-bounds order. Static element isinst and blind stelem.ref fusion have concrete counterexamples. Separate Single XOR failures originate in FCMP being lowered as integer overflow flags plus missing FSQRT, demonstrating that one generic cast/type patch cannot repair all families.\n", encoding="utf-8")
print(json.dumps({"status": proposal["status"], "helper_bytes": helper["bytes"], "finder": "0x0", "current_ctor_numeric_calls": 28, "associated_array_casts": 3355, "system_array_callers": len(array_callers)}))
