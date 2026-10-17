"""Correlate unedited full source/compiler outputs for the scoped internal getter."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination

BEFORE = "nso-virtual-companion-copy-v38"
AFTER = "nso-assembly-leaf-getter-v39"
MEMBER = "JsonSerializerInternalBase.Serializer__BackingField"


def source_code(text):
    # A lexical count only: exclude ordinary/verbatim strings, chars and comments
    # so exception diagnostic text cannot masquerade as an accessible property.
    return re.sub(r'@"(?:[^"]|"")*"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/',
        " ", text, flags=re.DOTALL)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def survey(run):
    path = ROOT / f"reports/recovered-source-profile-legacy-reference-check-{run}.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    assemblies, selected_files, shapes, source_hashes = [], set(), Counter(), {}
    for item in manifest["assemblies"]:
        log = ROOT / item["compiler_log"]
        source_hashes.update({ROOT / f["path"]: f["sha256"] for f in item["source_files"]})
        seen, codes, members = set(), Counter(), Counter()
        for line in log.open(encoding="utf-8-sig", errors="strict"):
            match = re.search(r"error (CS\d+): (.*?)(?: \[.*)?$", line)
            if not match:
                continue
            key = line.split(" [F:")[0].strip()
            if key in seen:
                continue
            seen.add(key)
            codes[match[1]] += 1
            if match[1] != "CS0122":
                continue
            name = re.search(r"'([^']+)'", match[2])
            if not name:
                raise ValueError("Missing inaccessible member")
            members[name[1]] += 1
            if name[1] == MEMBER:
                loc = re.match(r"(.+\.cs)\((\d+),(\d+)\):", line)
                if not loc or item["assembly"] != "Assembly-CSharp-firstpass":
                    raise ValueError("Focused source location differs")
                source = Path(loc[1])
                if sha(source) != source_hashes.get(source):
                    raise ValueError("Focused diagnostic source differs from actual compiler input hash")
                relative = source.relative_to(ROOT / f"analysis/il2cpp/source-profile-project-build-{run}/Assembly-CSharp-firstpass")
                selected_files.add(relative)
                text = source.read_text(encoding="utf-8-sig").splitlines()[int(loc[2]) - 1]
                tail = text[int(loc[3]) - 1:]
                if not tail.startswith("Serializer__BackingField"):
                    raise ValueError("Focused compiler column differs")
                tail = tail[len("Serializer__BackingField"):].lstrip()
                shapes["simple_store" if re.match(r"=(?!=|>)", tail) else "read_or_address_other"] += 1
        if len(seen) != item["unique_compiler_diagnostic_lines"] or item["build_exit_code"] != 1:
            raise ValueError("Complete compiler results differ from frozen manifest")
        assemblies.append({"assembly": item["assembly"], "unique_diagnostic_lines": len(seen),
            "private_access_diagnostics": codes["CS0122"], "focused_member_diagnostics": members[MEMBER],
            "compiler_log_sha256": sha(log), "build_exit_code": item["build_exit_code"]})
    return {"run": run, "manifest_sha256": sha(path), "assemblies": assemblies,
        "focused_compiler_expression_shapes": dict(shapes)}, selected_files, source_hashes


def main():
    canonical_path = ROOT / "reports/compiler-diagnostic-delta-v39.json"
    canonical = json.loads(canonical_path.read_text(encoding="utf-8-sig"))
    if (canonical["status"] != "PASS_CANONICAL_COMPLETE_SOURCE_COMPILER_COMPARISON"
            or canonical["before_run"] != BEFORE or canonical["after_run"] != AFTER):
        raise ValueError("Canonical complete source/compiler comparison is not ready")
    before, files, before_hashes = survey(BEFORE)
    after, _, after_hashes = survey(AFTER)
    if before["focused_compiler_expression_shapes"] != {"read_or_address_other": 99, "simple_store": 2}:
        raise ValueError("Original focused private-access compiler baseline differs")
    if after["focused_compiler_expression_shapes"] != {"simple_store": 2}:
        raise ValueError("Recovered internal getter source did not retain only original constructor stores")
    rows = []
    for relative in sorted(files):
        record = {"relative_source": str(relative)}
        for label, run in [("before", BEFORE), ("after", AFTER)]:
            path = ROOT / f"analysis/il2cpp/source-profile-project-build-{run}/Assembly-CSharp-firstpass" / relative
            text = path.read_text(encoding="utf-8-sig")
            code = source_code(text)
            expected_hashes = before_hashes if label == "before" else after_hashes
            if sha(path) != expected_hashes.get(path):
                raise ValueError("Focused source bytes differ from hash recorded by actual matching compiler")
            record[label] = {"sha256": sha(path),
                "explicit_private_backing_references": len(re.findall(r"\.Serializer__BackingField\b", code)),
                "existing_internal_property_identifier_occurrences": len(re.findall(r"\bSerializer\b", code))}
        rows.append(record)
    direct_before = sum(r["before"]["explicit_private_backing_references"] for r in rows)
    direct_after = sum(r["after"]["explicit_private_backing_references"] for r in rows)
    properties_before = sum(r["before"]["existing_internal_property_identifier_occurrences"] for r in rows)
    properties_after = sum(r["after"]["existing_internal_property_identifier_occurrences"] for r in rows)
    if (direct_before, direct_after, properties_after - properties_before) != (101, 2, 99):
        raise ValueError("Unedited same-file source private-field/property correlation differs")
    invocation = json.loads((ROOT / f"logs/cpp2il-{AFTER}-result.json").read_text(encoding="utf-8-sig"))
    contract = json.loads((ROOT / "reports/assembly-leaf-accessor-contract-v39.json").read_text(encoding="utf-8-sig"))
    if invocation["tool_assembly_sha256"]["Cpp2IL.Core.dll"] != contract["core_sha256"]:
        raise ValueError("Focused source run does not bind reviewed Core")
    report = {"status": "PASS_SCOPED_NATIVE_ASSEMBLY_GETTER_SOURCE_CORRELATION", "before": before, "after": after,
        "canonical_comparison_sha256": sha(canonical_path), "recovery_core_sha256": contract["core_sha256"],
        "focused_unedited_exported_source_files": len(rows), "source_files": rows,
        "private_backing_references_before": direct_before, "private_backing_references_after": direct_after,
        "additional_existing_internal_property_references": properties_after - properties_before,
        "private_constructor_store_diagnostics_preserved": 2,
        "private_visibility_preserved": True, "source_text_edited": False, "new_game_metadata_added": False,
        "whole_game_source_ready": False,
        "scope": "Named Serializer private-access compiler errors and exact unedited matching source files correlate 99 backing-field read diagnostics to 99 additional existing internal property identifier occurrences (qualified or inherited unqualified spellings). String/character literals and comments are excluded from lexical counts; this is not a general C# semantic parser. Two private constructor/base-inlining stores remain diagnostics. Canonical whole compiler results stay separate and include cascades. Getter/native/actual-CIL runtime boundaries are separate reports; no entire caller/game parity, manual source rewrite or full clean source is claimed."}
    output = destination(ROOT, ROOT / "reports/assembly-leaf-accessor-source-v39.json")
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "source_files": len(rows), "read_expressions": 99, "remaining_stores": 2}))


if __name__ == "__main__":
    main()
