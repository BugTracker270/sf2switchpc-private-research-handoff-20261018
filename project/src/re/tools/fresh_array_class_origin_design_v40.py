"""Read-only, hash-bound design inventory; no native/CIL semantic recovery."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    inputs = [
        "reports/object-isinst-abi-production-v40.json",
        "reports/object-isinst-abi-contract-v40.json",
        "reports/native-object-isinst-abi-v40.json",
        "reports/object-isinst-official-source-v40.json",
        "analysis/reconstruction/object-isinst-v40/profile-emitter-input.txt",
        "analysis/reconstruction/compiler-family-v38/official-runtime/Object.cpp",
        "tools/unity-2018.1.9f1/common-runtime-source/Editor/Data/il2cpp/libil2cpp/vm/Class.cpp",
        "analysis/reference/byte-array-layout-fusion-v40/runtime-source/Array.cpp",
        "refs/Cpp2IL/Cpp2IL.Core/Model/Contexts/MethodAnalysisContext.cs",
        "refs/Cpp2IL/Cpp2IL.Core/Analysis/ArrayRecovery.cs",
        "refs/Cpp2IL/Cpp2IL.Core/ISIL/OpCode.cs",
    ]
    data, source_text_encodings = {}, {}
    for p in inputs:
        raw = (ROOT / p).read_bytes()
        try:
            data[p] = raw.decode("utf-8-sig")
            source_text_encodings[p] = "utf-8-sig"
        except UnicodeDecodeError:
            # The verified legacy Windows runtime source contains Windows punctuation
            # in comments. Hashes remain over its exact bytes; never discard bytes.
            if not p.endswith(("Class.cpp", "Array.cpp", "Object.cpp")):
                raise
            data[p] = raw.decode("cp1252")
            source_text_encodings[p] = "cp1252"
    production, contract, native, official = [json.loads(data[p]) for p in inputs[:4]]
    core = "14232d46ca291ffb67944705e94ec5460bc8ee70c3df88ee3ef27e77b6e736d6"
    assert production["status"] == "PASS_ORIGINAL_ISINST_ABI_ONLY_PRODUCTION_DATAFLOW_AND_DIAGNOSTICS" and production["checks"] == 41
    assert production["core_sha256"] == contract["core_sha256"] == core
    assert contract["status"] == "PASS_EXACT_OBJECT_ISINST_ABI_ONLY_CONTRACT" and contract["checks"] == 57
    graph_path = inputs[4]
    stage = next(s for s in production["stages"] if s["stage"] == "emitter-input")
    assert stage["private_graph_sha256"] == sha(ROOT / graph_path)
    object_source = data[inputs[5]]
    assert sha(ROOT / inputs[5]) == official["source_files"][0]["sha256"]
    class_source, array_source = data[inputs[6]], data[inputs[7]]
    assignability = class_source.split("bool Class::IsAssignableFrom(", 1)[1].split("bool Class::IsGeneric(", 1)[0]
    assert assignability.index("if (klass == oklass)") < assignability.index("Class::Init(klass);") < assignability.index("Class::Init(oklass);")
    assert "if (!objClass->is_import_or_windows_runtime)" in object_source
    assert "Class::Init(klass);" in array_source and "klass->element_class->initialized" in array_source
    pipeline = data[inputs[8]]
    assert pipeline.index("SsaForm.Remove(this);") < pipeline.index("ArrayRecovery.Run(this);")

    # These are text identities in an already hash-bound original-method stage dump.
    # They are deliberately not a substitute for live operand object/dominance proof.
    graph = data[graph_path]
    roots = {}
    headers = {}
    candidates = []
    for line in graph.splitlines():
        allocation = re.fullmatch(r"(\d+) NewArr (v\d+) @ .*?, typeof\(([^)]+)\), (\d+)", line)
        if allocation:
            index, local, array_type, length = allocation.groups()
            assert local not in roots
            roots[local] = {"allocation_index": int(index), "array_type": array_type, "constant_length": int(length)}
        header = re.fullmatch(r"(\d+) Move (v\d+) @ .*?\(Il2CppClass<([^>]+)>\), \[(v\d+) @ .*\]", line)
        if header:
            index, local, array_type, root_local = header.groups()
            headers[local] = {"header_index": int(index), "array_type": array_type, "array_local": root_local}
        call = re.fullmatch(r"(\d+) Call B5B390, .*?\[(v\d+) @ .*\+40\]", line)
        if call:
            index, header_local = call.groups()
            header = headers[header_local]
            root_local = header["array_local"]
            root = roots[root_local]
            assert header["array_type"] == root["array_type"]
            candidates.append({"call_index": int(index), "array_local": root_local, **root,
                "header_index": header["header_index"], "literal_object": ', "' in line})
    assert len(roots) == 4 and len(candidates) == 28
    by_type = Counter(c["array_type"] for c in candidates)
    assert by_type == {"System.String[]": 2, "InControl.InputControlMapping[]": 26}
    assert all(c["allocation_index"] < c["header_index"] < c["call_index"] for c in candidates)

    private = destination(ROOT, ROOT / "analysis/reconstruction/object-isinst-v40/fresh-array-root-design-inventory.json")
    private.write_text(json.dumps({"roots": roots, "candidate_textual_chains": candidates,
        "live_operand_identity_proof": False, "dominance_or_escape_proof": False}, indent=2) + "\n", encoding="utf-8")
    report = {
        "status": "DESIGN_ONLY_FRESH_ARRAY_CLASS_ORIGIN_WITH_SEMANTIC_BLOCKERS",
        "core_sha256": core,
        "original_method": "InControl.PlayStation4MacBTProfile::.ctor",
        "original_method_rva": "0x11A4CC0",
        "static_textual_newarr_roots": 4,
        "static_textual_class_projection_candidates": 28,
        "candidate_array_types": dict(by_type),
        "literal_string_object_candidates": 2,
        "accepted_semantic_sites": 0,
        "evidence": [{"path": p, "sha256": sha(ROOT / p)} for p in inputs],
        "read_only_text_view_encodings": source_text_encodings,
        "private_inventory": {"path": str(private.relative_to(ROOT)).replace("\\", "/"), "sha256": sha(private)},
        "class_origin_contract": [
            "Start from a surviving reviewed B5B390 ABI call and exact original X1 element-class source, not the inferred managed array variable type.",
            "Require actual operand identities: class=load(header(array)+0x40), header=load(array+0), eight-byte ordinary loads with no index/extra offset; both header and array copies have one unique definition and are available before each use.",
            "Follow a bounded acyclic copy-only chain to one typed NewArr whose canonical SzArray element is a closed, non-generic ordinary reference class. Reject parameter, field, call-return, Phi, arithmetic/address, cast, interface, value-type, byref/pointer and unresolved roots.",
            "Recompute dominance on the current CFG; one unique allocation must dominate each header/projection/call use, including within-block order. Never reuse pre-SSA-removal dominator state or infer dominance from text order.",
            "Reject rewritten/multiply-defined locals, overlapping addressed storage, unknown native writes, escaping array/header/class aliases, unsupported exceptional flow and unproved cycles. Preserve allocation, class-init, object computation and original call position.",
            "Keep a proof separate from the ABI carrier and bind allocation/type/array/header/class/call objects plus evidence image; invalidate stale proofs at emission. Do not suppress a class load shared by another unresolved user.",
        ],
        "semantic_contract_separate_from_class_origin": [
            "Fresh NewArr proves an exact runtime element type only after the above object-level proof; it does not prove native IsInst behavior or object runtime-class origin.",
            "Official Object::IsInst has an imported/Windows-Runtime branch. Reject object sources whose ordinary non-import runtime class is unknown; a fresh target array cannot rule that branch out.",
            "Official Class::IsAssignableFrom returns immediately for identical classes; other ordinary-class paths initialize both target and object class. Prove metadata readiness and failure ordering independently, without running a managed .cctor or mapping metadata initialization to one.",
            "Initial stronger candidates are the two String[] sites with literal String objects. Their class identity/no-interop evidence still needs original metadata/native and real CLR tests. The 26 mapping sites also need precise Newobj object-class and intervening-effect/escape proof.",
            "If authorized after proof, use a dedicated result-bearing IsInst-like IR operation and emit load-original-object, isinst exact T, store-original-result. Keep the original result-null branch, ArrayTypeMismatch failure edge, later bounds checks and original element store in their existing order. Do not fuse stelem.ref, replace with a constant/original argument, or delete failure branches.",
        ],
        "pipeline_design": {
            "current_newarr_stage": "ArrayRecovery.Run after SsaForm.Remove and CopyCoalescer; current NewArr is not inherently a single-assignment provenance proof.",
            "smallest_readonly_next_probe": "Recompute a unique-definition map and dominance on this final CFG, bind original local/operand identities, enumerate every array/header/class use and reject unsupported escape/entry paths. Keep all semantic acceptance false.",
            "future_ssa_option": "Recognize the existing typed allocator while still in SSA and retain an immutable allocation-origin proof through late NewArr recovery; this would require separately reviewed Core changes.",
            "isil_support": "Current OpCode has no IsInst operation. A future implementation must define destination/source/type ownership, use/liveness/type propagation, clone and stale emitter validation, plus managed result-null semantics. ABI-only Object result typing is insufficient.",
        },
        "required_fail_closed_fixtures": [
            "Positive one exact NewArr, no copies and boundary copy depth; retain exact original object/result identity and original block/exception order.",
            "Reject same declared object[] from a covariant String[] parameter/field/managed call, two NewArr roots merged by Phi, duplicate/late definitions, cycles, branch-only allocation, wrong header/0x40 width/index/offset, mutable-address storage and alias escape.",
            "Reject generic/interface/value/import/WinRT types, unresolved runtime object classes, unknown native effects, and altered proof owner/call/type/array/header/result at emission.",
            "Compare original native return pointer/null and original failure/bounds ordering against the exact emitted CIL expression for null/matching/nonmatching objects. Existing ordinary native ABI oracle supplies assignability and cannot certify this semantic test.",
            "Real CLR counter and throwing .cctor types must show NewArr plus isinst does not initialize the element or tested class early; independently test zero/positive lengths, original-object reference identity and no constructor invocation.",
        ],
        "unresolved": [
            "This inventory parses immutable stage text. It has not proved actual operand identities, unique definitions, current CFG dominance, full use/escape graph, ordinary runtime object classes or exception coverage.",
            "The existing native wrapper oracle deliberately supplies Class::IsAssignableFrom; it does not recover its initialization/assignability/COM/error effects.",
            "Current numeric helper CIL emits a diagnostic without evaluating original arguments or producing the original return semantics. An ABI or static-candidate count is not an executable decompile.",
        ],
        "core_edited": False, "core_built": False, "original_game_methods_invoked": 0,
        "native_functions_executed": 0, "helper_suppressed": False, "semantic_lowering_implemented": False,
        "production_ready": False, "full_clean_decompile_ready": False, "portable_game_ready": False,
        "tool_sha256": sha(Path(__file__)),
    }
    out = destination(ROOT, ROOT / "reports/fresh-array-class-origin-design-v40.json")
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md = """# Fresh array class-origin design

Design only. The hash-bound original constructor stage contains four typed NewArr roots feeding 28 runtime element-class projections: two String[] sites and 26 InputControlMapping[] sites. These are textual candidates; none is accepted for semantic translation.

The first next step is a read-only operand-identity, unique-definition, dominance and complete-use/escape probe on the current CFG. ArrayRecovery runs after SSA removal, so a typed local or earlier textual definition is insufficient. Parameter/field/covariant arrays, Phi roots and unresolved storage must reject.

Class provenance is separate from IsInst semantics. Official source shows a COM/WinRT branch and metadata initialization on non-identical ordinary class pairs. The two literal String cases provide a narrower starting candidate; exact original class identity, unchanged native behavior, initialization timing and CLR .cctor-negative tests remain required. The current native ABI oracle supplies assignability and does not prove it.

A future result-bearing isinst operation must preserve the original null/failure branch, then bounds checks and original store. No helper removal, constant/argument substitution, stelem.ref fusion or Core implementation is authorized or performed by this design. Numeric helper argument/return semantics and the full clean portable decompile remain unresolved.
"""
    destination(ROOT, ROOT / "reports/fresh-array-class-origin-design-v40.md").write_text(md, encoding="utf-8")
    print(json.dumps({"status": report["status"], "static_candidates": 28, "accepted_semantic_sites": 0, "sha256": sha(out)}))


if __name__ == "__main__":
    main()
