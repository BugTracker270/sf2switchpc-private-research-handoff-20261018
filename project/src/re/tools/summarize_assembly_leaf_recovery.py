"""Bind frozen v39 evidence without re-reading full compiler input source trees."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination

RUN = "nso-assembly-leaf-getter-v39"
BASE = "nso-virtual-companion-copy-v38"
CORE = "52e9fa40275b71be5ea48e1bab1816e59dc4412ddfc0c627c29345f3086a4929"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--added-diagnostics-audit")
    args = parser.parse_args()
    evidence, gates = {}, []

    def gate(name, passed, pending=False):
        gates.append({"name": name, "status": "PASS" if passed else "PENDING" if pending else "FAIL"})

    def read(name, relative, status=None):
        path = ROOT / relative
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        evidence[name] = {"path": relative, "sha256": sha(path), "status": data.get("status")}
        if status:
            gate(name + "_status", data.get("status") == status)
        return data

    invocation = read("invocation", f"logs/cpp2il-{RUN}-result.json")
    gate("completed_reviewed_core_invocation", invocation["exit_code"] == 0 and invocation["tool_assembly_sha256"]["Cpp2IL.Core.dll"] == CORE)
    output = ROOT / "analysis/il2cpp" / ("cpp2il-recovery-" + RUN)
    assembly_hashes = {p.name: sha(p) for p in sorted(output.glob("*.dll"))}
    gate("all44_output_assemblies", len(assembly_hashes) == 44)
    snapshot = read("frozen_sources", "reports/assembly-leaf-getter-v39-source-snapshot.json", "PASS_IMMUTABLE_COMPLETE_CANDIDATE_SOURCE_CAPTURE")
    gate("all40_frozen_sources_match_invocation", snapshot["source_count"] == 40 and len(snapshot["sources"]) == 40
        and snapshot["core_sha256"] == CORE and snapshot["recovery_invocation_sha256"] == evidence["invocation"]["sha256"]
        and all(sha(ROOT / s["snapshot_path"]) == s["sha256"] for s in snapshot["sources"])
        and sha(ROOT / snapshot["manifest_path"]) == snapshot["manifest_sha256"])
    binaries = read("frozen_tool_binaries", "reports/assembly-leaf-getter-v39-tool-binary-snapshot.json", "PASS_FROZEN_V39_THREE_TOOL_ASSEMBLIES_AND_COMPLETE_PATCH")
    gate("three_frozen_tool_binaries_and_reverse_check", len(binaries["files"]) == 3 and binaries["frozen_reverse_check_exit_code"] == 0
        and all(sha(ROOT / row["path"]) == row["sha256"] == invocation["tool_assembly_sha256"][Path(row["path"]).name] for row in binaries["files"]))
    lock = read("candidate", "reports/cpp2il-hfa-experimental-lock-assembly-leaf-getter-v39.json", "EXPERIMENTAL_SAVED_NOT_PROMOTED")
    source_map = {s["path"].replace("\\", "/").removeprefix("refs/Cpp2IL/"): s["sha256"] for s in snapshot["sources"]}
    gate("complete40_file_candidate_binds_frozen_source", lock["changed_or_new_tool_paths"] == 40 and lock["source_inventory_coverage_verified"]
        and {s["path"].replace("\\", "/"): s["sha256"] for s in lock["files"]} == source_map
        and sha(ROOT / lock["patch"]) == lock["sha256"] == snapshot["candidate_patch_sha256"]
        and sha(ROOT / evidence["candidate"]["path"]) == snapshot["candidate_lock_sha256"])
    native = read("native_getter", "reports/native-assembly-leaf-getter-v39.json", "PASS_ORIGINAL_INTERNAL_REFERENCE_LEAF_GETTER")
    gate("native_128cases384checks_and_null_boundary", native["cases"] == 128 and native["checks"] == 384
        and native["null_receiver_original_load_fault"] and native["guest_function_replacements"] == 0 and native["native_code_unmodified"])
    baseline = read("baseline", "reports/assembly-leaf-accessor-contract-v39-baseline.json", "PASS_BASELINE_PUBLIC_ONLY_LEAF_ROUTE_REJECTS_INTERNAL_GETTER")
    gate("original_public_only_baseline9", baseline["checks"] == 9 and baseline["core_sha256"] == "197403735d374bdde681ad203cdb3eb18e8cd9eef01897908a8c4f9e786ad99a")
    contract = read("contract", "reports/assembly-leaf-accessor-contract-v39.json", "PASS_ASSEMBLY_LEAF_GETTER_NATIVE_ACCESSIBILITY_AND_EMISSION_CONTRACT")
    gate("independent78_contract_checks", contract["checks"] == 78 and contract["fatal"] is None and contract["core_sha256"] == CORE
        and len(contract["eligible_getter_inventory"]) == 27 and all(r["valid"] for r in contract["eligible_getter_inventory"]))
    production = read("production", "reports/assembly-leaf-accessor-production-v39.json", "PASS_ACTUAL_ORIGINAL_CONSTRUCTOR_RECEIVER_AND_ASSEMBLY_GETTER_EMISSION")
    gate("original_two_constructor_pipeline15", production["checks"] == 15 and production["fatal"] is None and production["core_sha256"] == CORE
        and len(production["methods"]) == 2 and all(m["receiver_type_preserved"] and m["existing_effect_and_control_rows_preserved"]
            and m["exact_nonvirtual_getter_calls_after"] == 1 and m["backing_field_reads_after"] == 0 for m in production["methods"]))
    fresh = read("fresh_output", f"reports/recovered-assembly-leaves-{RUN}.json", "PASS_FRESH_ORIGINAL_ASSEMBLY_GETTERS_AND_CONSTRUCTOR_CALL_CORRELATION")
    gate("fresh27_getters_two_constructors118", fresh["checks"] == 118 and fresh["fatal"] is None and fresh["selected_getters"] == 27 and fresh["actual_constructors"] == 2
        and fresh["contract_report_sha256"] == evidence["contract"]["sha256"] and fresh["production_report_sha256"] == evidence["production"]["sha256"]
        and fresh["invocation_report_sha256"] == evidence["invocation"]["sha256"] and not fresh["core_dependency_loaded"]
        and fresh["actual_main_sha256"] == assembly_hashes["Assembly-CSharp.dll"] and fresh["actual_firstpass_sha256"] == assembly_hashes["Assembly-CSharp-firstpass.dll"]
        and fresh["recovered_game_methods_invoked"] == 0 and fresh["tokens_remapped"] == 0 and not fresh["metadata_flags_changed"]
        and all(g["exact_original_field_flow"] and g["original_flags_preserved"] for g in fresh["getters"]))
    regression = read("regressions", f"reports/recovery-regression-{RUN}.json", "PASS_SCOPED_RECOVERY_REGRESSIONS")
    gate("all18_existing_bounded_regressions", len(regression["probes"]) == 18 and all(p["exit_code"] == 0 for p in regression["probes"]))
    syntax = read("syntax", f"analysis/il2cpp/cil-audit-{RUN}/summary.json")
    gate("all44_cil_syntax", len(syntax["assemblies"]) == 44 and all(not a.get("malformed_il") for a in syntax["assemblies"]))
    stack = read("stack", f"reports/cil-stack-audit-{RUN}.json", "PASS_STACK_DEPTH_AND_HEADERS_ONLY")
    gate("all44_stack_depth_headers_only", stack["assembly_count"] == 44 and stack["understated_max_stack"] == 0 and stack["stack_flow_failures"] == 0)
    delta = read("compiler_comparison", "reports/compiler-diagnostic-delta-v39.json", "PASS_CANONICAL_COMPLETE_SOURCE_COMPILER_COMPARISON")
    gate("compiler_comparison_exact_runs", delta["before_run"] == BASE and delta["after_run"] == RUN)
    source_audit_reuse, verified_reports = {}, set()
    for assembly, row in delta["assemblies"].items():
        for run, proof in row["source_integrity"].items():
            gate("canonical_source_profile_" + assembly + "_" + run, proof["matching_reference_source_manifest_unchanged"] and proof["restore_exit_code"] == 0 and proof["build_exit_code"] == 1)
            for role in ["summary", "export"]:
                item = proof[role]
                if item["path"] not in verified_reports:
                    gate("canonical_manifest_hash_" + item["path"], sha(ROOT / item["path"]) == item["sha256"])
                    verified_reports.add(item["path"])
            source_audit_reuse.setdefault(run, {})[assembly] = {"manifest_entries": proof["source_manifest_files"],
                "diagnostic_source_byte_hashes_previously_verified": proof["diagnostic_source_files_hash_verified"],
                "matching_reference_source_manifest_unchanged": proof["matching_reference_source_manifest_unchanged"]}
    focused = read("focused_source", "reports/assembly-leaf-accessor-source-v39.json", "PASS_SCOPED_NATIVE_ASSEMBLY_GETTER_SOURCE_CORRELATION")
    gate("99_source_reads_and_two_remaining_private_stores", focused["canonical_comparison_sha256"] == evidence["compiler_comparison"]["sha256"]
        and focused["private_backing_references_before"] == 101 and focused["private_backing_references_after"] == 2
        and focused["additional_existing_internal_property_references"] == 99 and focused["private_constructor_store_diagnostics_preserved"] == 2)
    audit = None
    if args.added_diagnostics_audit:
        audit = read("added_diagnostics_audit", args.added_diagnostics_audit)
    expected_added = {("Unity.IO.Compression.CopyEncoder", "WriteLenNLen"): 4,
        ("BestHTTP.HTTPManager", "FindOrCreateFreeConnection"): 1,
        ("Newtonsoft.Json.Serialization.JsonSerializerInternalReader", "PopulateDictionary"): 1}
    gate("six_added_diagnostics_independently_audited", audit is not None
        and audit.get("status") == "PASS_SIX_ADDED_DIAGNOSTICS_EXPOSE_EXISTING_UNCHANGED_OPERATIONS"
        and audit.get("checks") == 275 and audit.get("fatal") is None and audit.get("added_occurrences") == 6
        and {(m["owner"], m["method"]): m["added_occurrences"] for m in audit["methods"]} == expected_added
        and all(m["all_other_original_rows_and_shape_equal"] and m["all_other_raw_non_token_bytes_equal"] for m in audit["methods"])
        and audit["canonical_delta_sha256"] == evidence["compiler_comparison"]["sha256"]
        and audit["fresh_gate_report_sha256"] == evidence["fresh_output"]["sha256"]
        and sha(ROOT / "src/re/RecoveredAssemblyLeafDiagnosticProbe/Program.cs") == audit["source_sha256"]
        and sha(ROOT / audit["private_cil"]) == audit["private_cil_sha256"]
        and not audit["core_dependency_loaded"] and audit["recovered_game_methods_invoked"] == 0
        and not audit["cil_modified"] and not audit["compiler_errors_repaired"], pending=audit is None)
    failed = [g["name"] for g in gates if g["status"] == "FAIL"]
    pending = [g["name"] for g in gates if g["status"] == "PENDING"]
    status = "ASSEMBLY_LEAF_RECOVERY_EVIDENCE_FAILED" if failed else "SCOPED_ASSEMBLY_GETTER_RECOVERY_ADDED_DIAGNOSTICS_AUDIT_PENDING" if pending else "SCOPED_ASSEMBLY_GETTER_RECOVERY_VALIDATED_WHOLE_SOURCE_INCOMPLETE"
    report = {"status": status, "recovery_run": RUN, "baseline_run": BASE, "updated": datetime.now(timezone.utc).isoformat(),
        "recovery_core_sha256": CORE, "evidence": evidence, "gates": gates, "failed_gates": failed, "pending_gates": pending,
        "assembly_hashes": assembly_hashes, "source_audit_reuse": {"canonical_report_sha256": evidence["compiler_comparison"]["sha256"],
            "completed_canonical_manifest_and_diagnostic_source_audit_reused": True, "new_full_source_tree_byte_hash_reads": False, "profiles": source_audit_reuse},
        "compiler": {name: {"before": row["before_unique"], "after": row["after_unique"], "delta": row["delta"],
            "before_cs0122": row["before_error_codes"].get("CS0122", 0), "after_cs0122": row["after_error_codes"].get("CS0122", 0),
            "added_semantic_diagnostic_occurrences": row["semantic_added_occurrences"], "added_diagnostics": row["top_added_messages"]} for name, row in delta["assemblies"].items()},
        "candidate_patch": {"path": lock["patch"], "sha256": lock["sha256"], "files": 40, "promoted": False},
        "bounded_scopes": {"native_getter_cases": 128, "native_getter_checks": 384, "null_receiver_boundary": True,
            "baseline_contract_checks": 9, "assembly_contract_checks": 78, "original_constructor_pipeline_checks": 15,
            "fresh_output_checks": 118, "fresh_getters": 27, "fresh_constructors": 2, "bounded_regression_jobs": 18,
            "focused_source_private_reads_recovered_as_existing_internal_property": 99, "private_constructor_stores_remaining": 2},
        "original_visibility_changed": False, "source_text_edited": False, "full_clean_decompile_ready": False,
        "whole_game_source_ready": False, "portable_game_ready": False,
        "summary_tool_sha256": sha(Path(__file__)),
        "limits": "Exact nonpublic accessor recovery preserves field flags and requires the same actual output assembly. Native reads, synthetic native/accessibility/emitter contracts, actual constructor IR/CIL correlation and whole source compilation remain separate scopes. Both complete matching source builds still fail. Six newly diagnosed arithmetic/cast occurrences were independently traced to unchanged prior recovered operations; those invalid operations remain unresolved. No original game code executes in the getter/constructor inspection probes, and no full game parity or clean portable decompile is claimed."}
    json_path = destination(ROOT, ROOT / "reports/assembly-leaf-getter-source-recovery-v39.json")
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    counts = Counter(g["status"] for g in gates)
    text = ("# Scoped internal getter recovery\n\n" + status + "\n\n"
        "Original private fields retain their visibility. The same-assembly getter route passes78 contract checks,15 original constructor-pipeline checks and118 independent fresh-output checks covering27 getters/two callers. Separate original-native evidence covers128 cases/384 checks plus a null-receiver boundary. All18 bounded regressions pass.\n\n"
        "Matching source compiler: firstpass20,728 →20,534 (−194); main32,710 →32,710. Both complete builds still exit1. Firstpass CS0122 falls2713 →2528;99 Serializer reads use the existing internal property, while two private constructor stores remain errors.\n\n"
        "Six added semantic diagnostics are retained: byte[]+int four times, HTTPProxy→HTTPConnectionStates once and System.Type→nint once. Independent added-diagnostic audit: " + ("pending" if pending else "275 checks trace all six to unchanged prior invalid operations; those operations remain unresolved") + ".\n\n"
        f"Evidence gates: {counts['PASS']} pass/{counts['PENDING']} pending/{counts['FAIL']} fail. Completed canonical compiler/source-manifest audit is reused explicitly; full source trees are not rehashed by this summary. Frozen40-source/tool-binary snapshots bind the historical Core independently of later tool edits. Full clean decompilation and portable source remain incomplete.\n")
    destination(ROOT, ROOT / "reports/assembly-leaf-getter-source-recovery-v39.md").write_text(text, encoding="utf-8")
    print(json.dumps({"status": status, "gate_counts": dict(counts), "failed_gates": failed, "pending_gates": pending,
        "json_sha256": sha(json_path)}))
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
