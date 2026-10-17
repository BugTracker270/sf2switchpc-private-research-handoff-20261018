"""Read pinned official runtime source directly from its already local archive."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination


def path(relative):
    return destination(ROOT, ROOT / relative)


def sha(p):
    value = hashlib.sha256()
    with p.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


provenance = json.loads(path("reports/unity-2018.1.9f1-archive-provenance.json").read_text(encoding="utf-8-sig"))
archive = path(provenance["archive_path"])
assert provenance["status"] == "PASS_OFFICIAL_ARCHIVE_MD5_WITH_RECORDED_API_SIZE_DELTA"
assert provenance["local_sha256"] == "ce666b2de60716cb5564b53317b56f0b82eddbea7afb3462ef51d5e121833c96"
assert sha(archive) == provenance["local_sha256"]
folder = path("analysis/reconstruction/compiler-family-v38/official-runtime")
folder.mkdir(parents=True, exist_ok=True)
source_rows = []
for name in ("Object.cpp", "Object.h"):
    member = "Editor\\Data\\il2cpp\\libil2cpp\\vm\\" + name
    target = folder / name
    result = subprocess.run(["C:/Program Files/7-Zip/7z.exe", "e", "-so", str(archive), member], capture_output=True, timeout=120)
    if result.returncode != 0 or not result.stdout or b"IsInst" not in result.stdout:
        raise ValueError("Official selected source unavailable: " + result.stderr.decode("utf-8", errors="replace"))
    if target.exists() and target.read_bytes() != result.stdout:
        raise ValueError("Preserve differing prior source")
    target.write_bytes(result.stdout)
    source_rows.append(dict(archive_member=member, private_path=str(target.relative_to(ROOT)), sha256=sha(target), bytes=len(result.stdout)))
report = dict(status="PASS_PINNED_OFFICIAL_OBJECT_ISINST_SOURCE_READ_ONLY", release=provenance["release"], revision=provenance["revision"], archive_sha256=provenance["local_sha256"], source_files=source_rows, source_sha256=sha(path("src/re/tools/aggregate_abi_object_isinst_source.py")), installer_executed=False, source_uploaded=False, core_modified=False, game_or_native_methods_executed=0, scope="Selected official vm/Object.cpp and vm/Object.h read through7-Zip stdout from the already local verified Unity2018.1.9f1 archive. Installer never executed. Full selected source retained under ignored analysis; native mapping and ABI certification remain separate.")
path("reports/object-isinst-official-source-v40.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"status": report["status"], "source_files": len(source_rows)}))
