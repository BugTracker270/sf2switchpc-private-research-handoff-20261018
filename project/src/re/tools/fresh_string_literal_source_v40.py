"""Extract only original common String/literal implementation for a local design audit."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    provenance_path = ROOT / "reports/unity-2018.1.9f1-archive-provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8-sig"))
    assert provenance["status"] == "PASS_OFFICIAL_ARCHIVE_MD5_WITH_RECORDED_API_SIZE_DELTA"
    archive = ROOT / provenance["archive_path"]
    assert sha(archive) == provenance["local_sha256"] == "ce666b2de60716cb5564b53317b56f0b82eddbea7afb3462ef51d5e121833c96"
    files = []
    for name in ("MetadataCache.cpp", "String.cpp", "String.h"):
        member = "Editor\\Data\\il2cpp\\libil2cpp\\vm\\" + name
        target = destination(ROOT, ROOT / "analysis/reference/string-exact-class-v40/runtime-source" / name)
        result = subprocess.run(["C:/Program Files/7-Zip/7z.exe", "e", "-so", str(archive), member], capture_output=True, timeout=60)
        if result.returncode or not result.stdout:
            raise RuntimeError("Selected official common runtime source absent: " + member)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != result.stdout:
            raise RuntimeError("Preserve differing prior source: " + name)
        target.write_bytes(result.stdout)
        files.append({"archive_member": member, "path": str(target.relative_to(ROOT)).replace("\\", "/"),
            "bytes": len(result.stdout), "sha256": sha(target)})
    image_path = ROOT / "analysis/nso/main-uncompressed.nso"
    metadata_path = ROOT / "unpacked/effective/romfs/Data/Managed/Metadata/global-metadata.dat"
    assert sha(image_path) == "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968"
    assert sha(metadata_path) == "f37df12eb1e4b3bb6972ab650a20659010096fd1932dc4f4f930150f279bde85"
    image = image_path.read_bytes()
    segments = [struct.unpack_from("<III", image, offset) for offset in (16, 32, 48)]

    def original_pointer(rva):
        ranges = [(offset + rva - start) for offset, start, size in segments if start <= rva and rva + 8 <= start + size]
        assert len(ranges) == 1
        return struct.unpack_from("<Q", image, ranges[0])[0]

    assert original_pointer(0x39F3CC8) == 0x3B7A110
    assert original_pointer(0x397A410) == 0x3B2DC88
    metadata = metadata_path.read_bytes()
    assert struct.unpack_from("<II", metadata) == (0xFAB11BAF, 24)
    literals, literals_size, text, text_size = struct.unpack_from("<4I", metadata, 8)
    assert literals_size % 8 == 0 and literals + literals_size <= len(metadata) and text + text_size <= len(metadata)
    matches = []
    for index in range(literals_size // 8):
        length, relative = struct.unpack_from("<II", metadata, literals + index * 8)
        assert relative + length <= text_size
        if metadata[text + relative:text + relative + length] == b"OS X":
            matches.append(index)
    assert matches == [4849]
    literal_map_path = ROOT / "analysis/il2cpp/effective-main/stringliteral.json"
    literal_map = json.loads(literal_map_path.read_text(encoding="utf-8-sig"))
    matches = [row for row in literal_map if int(row["address"], 16) == 0x3B7A110]
    assert matches == [{"value": "OS X", "address": "0x3B7A110"}]
    report = {"status": "PASS_SELECTED_OFFICIAL_STRING_SOURCE_AND_ORIGINAL_LITERAL_STATIC_CORRELATION",
        "release": provenance["release"], "revision": provenance["revision"], "archive_sha256": provenance["local_sha256"],
        "archive_provenance_sha256": sha(provenance_path), "source_files": files,
        "original_image_sha256": sha(image_path), "original_metadata_sha256": sha(metadata_path),
        "literal_map_sha256": sha(literal_map_path), "literal_index": 4849,
        "literal_got_rva": "0x39F3CC8", "literal_slot_rva": "0x3B7A110",
        "string_array_got_rva": "0x397A410", "string_array_slot_rva": "0x3B2DC88",
        "canonical_runtime_class_identity_proved": False, "literal_runtime_object_read": False,
        "native_functions_executed": 0, "game_methods_invoked": 0, "installer_executed": False,
        "core_modified": False, "semantic_lowering_implemented": False, "full_clean_decompile_ready": False,
        "scope": "Static original raw GOT words, bounded original metadata literal-index read and independent prior literal-map correlation. Common runtime source is extracted locally for further design inspection. Runtime literal object/header identity and exact canonical String[] element type still require an original-context operand/metadata proof; these addresses or the literal text alone do not authorize semantic lowering.",
        "tool_sha256": sha(Path(__file__))}
    out = destination(ROOT, ROOT / "reports/fresh-string-literal-source-v40.json")
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "source_files": len(files), "sha256": sha(out)}))


if __name__ == "__main__":
    main()
