"""Preserve the independently built pre-implementation v38 accessor baseline."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination


def main():
    report_path = ROOT / "reports/assembly-leaf-accessor-contract-v39-baseline.json"
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    source = ROOT / "src/re/AssemblyLeafAccessorContractProbe/Program.cs"
    core = ROOT / "src/re/AssemblyLeafAccessorContractProbe/bin/Release/net10.0/Cpp2IL.Core.dll"
    if (report["status"] != "PASS_BASELINE_PUBLIC_ONLY_LEAF_ROUTE_REJECTS_INTERNAL_GETTER" or report["checks"] != 9
            or report["core_sha256"] != "197403735d374bdde681ad203cdb3eb18e8cd9eef01897908a8c4f9e786ad99a"
            or hashlib.sha256(source.read_bytes()).hexdigest() != report["probe_source_sha256"]
            or hashlib.sha256(core.read_bytes()).hexdigest() != report["core_sha256"]):
        raise ValueError("Original baseline source/Core/report binding differs")
    paths = [report_path, source, source.with_name("AssemblyLeafAccessorContractProbe.csproj"), core,
        core.with_name("AssemblyLeafAccessorContractProbe.dll"), ROOT / "logs/assembly-leaf-accessor-contract-v39-baseline.log"]
    folder = ROOT / "analysis/reconstruction/assembly-leaf-v39/baseline-core197403"
    rows = []
    for path in paths:
        blob = path.read_bytes()
        target = destination(ROOT, folder / path.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != blob:
            raise ValueError("Refusing to replace changed frozen baseline bytes")
        if not target.exists():
            target.write_bytes(blob)
        rows.append({"path": str(path.relative_to(ROOT)), "snapshot": str(target.relative_to(ROOT)),
            "sha256": hashlib.sha256(blob).hexdigest()})
    manifest = {"status": "PASS_FROZEN_ORIGINAL_PUBLIC_ONLY_ACCESSOR_BASELINE", "files": rows,
        "core_sha256": report["core_sha256"], "baseline_checks": report["checks"]}
    target = destination(ROOT, folder / "manifest.json")
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": manifest["status"], "files": len(rows), "manifest_sha256": hashlib.sha256(target.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
