"""Sanitize the original private-access census and separate recovery mechanisms."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    census_path = ROOT / "reports/private-access-census-v37.json"
    census = json.loads(census_path.read_text(encoding="utf-8-sig"))
    by_assembly = {a["assembly"]: a for a in census["assemblies"]}
    first = by_assembly["Assembly-CSharp-firstpass"]
    main_assembly = by_assembly["Assembly-CSharp"]
    if (first["private_access_diagnostics"] != 2713 or main_assembly["private_access_diagnostics"] != 4225
            or first["top_member_source_expression_shapes"]["JsonSerializerInternalBase.Serializer__BackingField"]
            != {"read_or_address_other": 99, "simple_store": 2}):
        raise ValueError("Frozen v37 census differs")
    raw_path = ROOT / "analysis/nso/main-uncompressed.nso"
    if sha(raw_path) != "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968":
        raise ValueError("Original native image differs")
    raw = raw_path.read_bytes()
    expected = {
        0x1E6850: "001040f9c0035fd6", 0x1E6840: "011000f9c0035fd6",
        0x1238500: "001840bdc0035fd6", 0x12384F0: "000840bdc0035fd6",
        0x1238540: "001c40bdc0035fd6", 0x1238530: "000c40bdc0035fd6",
    }
    witnesses = []
    for at, hex_code in expected.items():
        code = raw[0x100 + at:0x108 + at]
        if code.hex() != hex_code:
            raise ValueError(f"Original native leaf differs: {at:X}")
        witnesses.append({"rva": f"0x{at:X}", "bytes": 8, "sha256": hashlib.sha256(code).hexdigest()})
    db = sqlite3.connect(ROOT / "analysis/nso/corpus.sqlite")
    detailed = []
    for address in [0xCEDE90, 0xF0E180]:
        row = db.execute("select rva,name,corpus,offset,length from functions where rva=?", (address,)).fetchone()
        if not row:
            raise ValueError("Missing original corpus method")
        with (ROOT / row[2]).open("rb") as stream:
            stream.seek(row[3])
            record = json.loads(stream.read(row[4]))
        detailed.append(record)
    private_path = destination(ROOT, ROOT / "analysis/reconstruction/private-access-v37/native-layout-witnesses.json")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(json.dumps(detailed, indent=2) + "\n", encoding="utf-8")
    report = {
        "status": "READ_ONLY_PRIVATE_ACCESS_MECHANISMS_SEPARATED_SCOPED_ASSEMBLY_GETTER_CONTRACT_IN_PROGRESS",
        "census_run": census["recovery_run"], "census_sha256": sha(census_path),
        "diagnostics": {"firstpass_cs0122": 2713, "main_cs0122": 4225,
            "rect_private_float_fields_firstpass": 219, "rect_private_float_fields_main": 508,
            "serializer_backing_field_read_or_address_shapes": 99, "serializer_backing_field_simple_stores": 2,
            "dialogs_singleton": 170, "protected_modelnode_current": 113},
        "original_native_sha256": sha(raw_path), "native_leaves": witnesses,
        "private_native_detail_sha256": sha(private_path),
        "visibility_provenance": [
            "LibCpp2IL/Metadata/Il2CppTypeDefinition.cs FieldAttributes reads native Il2CppType.Attrs.",
            "Il2CppFieldReflectionData.Attributes feeds FieldAnalysisContext.DefaultAttributes; original private/Family/Assembly flags remain evidence.",
            "AsmResolverAssemblyPopulator.CopyFieldsInType copies context Attributes into FieldDefinition; types/methods have separate original flags.",
            "The compiler errors arise after native inlining or unresolved receiver/body recovery produces direct nonpublic accesses in other managed callers. They do not justify public visibility overrides."],
        "mechanisms": [
            {"kind": "same_assembly_exact_instance_getter", "candidate": "JsonSerializerInternalBase.Serializer",
             "original_field": "private reference at 0x20", "original_getter": "Assembly nonvirtual instance",
             "normal_source_form": "Existing accessible internal property getter", "excluded": "Two private-setter/base-constructor stores",
             "next_step": "Unique exact native getter selection plus uncached actual attached output assembly/type/method/field identity checks per caller; no original flags change. Bind every selected existing recovered getter to one exact field load/return with local copies only, then real emitter tests and fresh production/source correlation."},
            {"kind": "value_type_receiver_and_entry_identity", "candidate": "UnityEngine.Rect",
             "original_layout": "Four private Single fields at unboxed offsets 0/4/8/12; registered boxed get_width/get_height read +24/+28; separate unregistered unboxed leaves read +8/+12.",
             "observed_caller": "ChangingSprite.SetAnimation supplies stack Rect storage, calls unregistered scalar leaves, and consumes S0; current source retains unresolved calls and erroneous m_XMin read shapes.",
             "next_step": "Prove receiver-adjusted native leaf identity, call ABI and stack storage before any value-type accessor reconstruction. Private-property substitution alone would conceal a deeper body/receiver error.", "implemented": False},
            {"kind": "effectful_singleton_inlining", "candidate": "DialogsManager.Instance",
             "original_native_bytes": 128, "effects": ["method metadata assurance", "null branch", "allocation", "constructor", "static field store"],
             "next_step": "Whole-region ordered effect/allocation/branch proof; single field loads must not be mapped to this effectful getter.", "implemented": False},
            {"kind": "protected_instance_getter_initialization", "candidate": "ModelNode.CurrentPosition",
             "prior_audit": "reports/private-access-protected-analysis-v29.json",
             "reason_deferred": "Original Family field, owner BeforeFieldInit and .cctor; native leaf alone does not prove managed initialization timing.", "implemented": False},
            {"kind": "inlined_constructor_private_stores", "examples": ["Token.start/end", "Serializer private setter/base constructor"],
             "next_step": "Recover original constructor/call region with exact parameters, ordered guards/effects, initialized storage and allocation identity; do not call a private setter from an unrelated type.", "implemented": False}],
        "prior_validated_private_access": {"run": "nso-native-leaves-v29", "source_report": "reports/private-access-source-nso-native-leaves-v29.json",
            "input_handle_stores_recovered_as_existing_public_setter": 673, "original_private_flags_preserved": True,
            "effectful_fallback_getter_rejected": True},
        "source_edited": False, "visibility_widened": False, "game_methods_executed_by_assessment": 0,
        "whole_game_source_ready": False,
        "limits": "Counts include compiler cascades and source expression classifications, not unique defects or runtime coverage. This report separates recovery mechanisms; the new Core experiment and its gates are separate artifacts, not a claim that existing compiler failures are fixed."}
    out = destination(ROOT, ROOT / "reports/private-access-recovery-design-v39.json")
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "sha256": sha(out)}))


if __name__ == "__main__":
    main()
