"""Read-only complete compiler/native mechanism survey; no recovery or rewriting."""
from __future__ import annotations
from bisect import bisect_right
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import capstone

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination
from compiler_diagnostic_delta import ERROR
from native_unwind_inventory import Image

RUN = "nso-virtual-companion-copy-v38"


def path(relative):
    return destination(ROOT, ROOT / relative)


def sha(relative):
    return hashlib.sha256(path(relative).read_bytes()).hexdigest()


summary_path = f"reports/recovered-source-profile-legacy-reference-check-{RUN}.json"
summary = json.loads(path(summary_path).read_text(encoding="utf-8-sig"))
private = path("analysis/reconstruction/compiler-family-v38")
private.mkdir(parents=True, exist_ok=True)
public_assemblies = []
all_rows = {}
method_rows = defaultdict(list)
native_helper = 0xB5B390

for assembly in summary["assemblies"]:
    rows, seen = [], set()
    for raw in path(assembly["compiler_log"]).read_text(encoding="utf-8-sig", errors="replace").splitlines():
        canonical = re.sub(r"^\d+>", "", raw.lstrip()).strip()
        if ": error " not in canonical or canonical in seen:
            continue
        match = ERROR.match(canonical)
        if not match:
            continue
        seen.add(canonical)
        source = Path(match[1].strip()).resolve()
        rows.append(dict(path=str(source.relative_to(ROOT)), line=int(match[2]), column=int(match[3]), code=match[4], message=match[5].strip()))
    assert len(rows) == assembly["unique_compiler_diagnostic_lines"]
    assert dict(Counter(r["code"] for r in rows)) == assembly["error_codes"]
    expected = {str(Path(f["path"]).resolve().relative_to(ROOT)) if Path(f["path"]).is_absolute() else str(Path(f["path"])): f["sha256"] for f in assembly["source_files"]}
    sources = {}
    starts = {}
    for source in {r["path"] for r in rows}:
        raw = path(source).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected[source], source
        lines = raw.decode("utf-8-sig").splitlines()
        sources[source] = lines
        declarations = [(1, "<file>")]
        for line, text in enumerate(lines, 1):
            if re.match(r"^\t(?:public|private|protected|internal)\s", text) and not text.endswith(";") and not re.search(r"\b(?:class|struct|enum|interface)\b", text):
                if text.endswith(")") or re.match(r"^\t(?:public|private|protected|internal)\s[\w<>,.?\[\] ]+\s\w+$", text):
                    declarations.append((line, text.strip()))
        starts[source] = declarations
    casts, operators, vicinity = Counter(), Counter(), Counter()
    owners = Counter()
    for row in rows:
        declarations = starts[row["path"]]
        position = bisect_right([s[0] for s in declarations], row["line"]) - 1
        row["owner_declaration_line"], row["owner_declaration"] = declarations[position]
        owner = (row["path"], row["owner_declaration_line"], row["owner_declaration"])
        method_rows[(assembly["assembly"], *owner)].append(row)
        lines = sources[row["path"]]
        near = "\n".join(lines[max(0, row["line"] - 4):row["line"] + 4])
        if row["code"] == "CS0030":
            match = re.fullmatch(r"Cannot convert type '(.+)' to '(.+)'", row["message"])
            if match:
                casts[match.groups()] += 1
                if match[2] == "nint" and match[1].endswith("[]"):
                    vicinity["array_to_nint_total"] += 1
                    if "Method not found @B5B390" in near:
                        vicinity["array_to_nint_with_B5B390_within4lines"] += 1
                        owners[owner] += 1
                if match[1] == "System.Type" and match[2] == "nint":
                    vicinity["type_to_nint_total"] += 1
                    if "Unmanaged memory load" in near:
                        vicinity["type_to_nint_near_unmanaged_load"] += 1
                    if "Indirect call" in near:
                        vicinity["type_to_nint_near_indirect_call"] += 1
        if row["code"] == "CS0019":
            match = re.fullmatch(r"Operator '(.+)' cannot be applied to operands of type '(.+)' and '(.+)'", row["message"])
            if match:
                operators[match.groups()] += 1
                if match.groups() == ("&", "object", "int"):
                    vicinity["object_and_int_total"] += 1
                    vicinity["object_and_int_near_unmanaged_load" if "Unmanaged memory load" in near else "object_and_int_without_near_unmanaged_load"] += 1
    all_rows[assembly["assembly"]] = rows
    public_assemblies.append(dict(assembly=assembly["assembly"], unique_diagnostic_lines=len(rows), codes=dict(Counter(r["code"] for r in rows)), compiler_log=assembly["compiler_log"], compiler_log_sha256=sha(assembly["compiler_log"]),
        cast_pairs=[dict(source_type=a, target_type=b, count=n) for (a, b), n in casts.most_common(30)], operator_pairs=[dict(operator=op, left_type=a, right_type=b, count=n) for (op, a, b), n in operators.most_common(20)],
        exact_source_vicinity_counts=dict(vicinity), array_helper_cast_owner_groups=[dict(path=p, declaration_line=line, diagnostic_occurrences=n) for (p, line, declaration), n in owners.most_common(15)], array_helper_distinct_owner_groups=len(owners)))

(private / "canonical-diagnostics.json").write_text(json.dumps(all_rows, indent=2) + "\n", encoding="utf-8")
groups = []
for (assembly, source, line, declaration), rows in method_rows.items():
    if any(r["code"] in ("CS0030", "CS0019") for r in rows):
        groups.append(dict(assembly=assembly, path=source, declaration_line=line, declaration=declaration, diagnostics=len(rows), selected_families=dict(Counter(r["code"] for r in rows))))
(private / "owner-diagnostic-groups.json").write_text(json.dumps(sorted(groups, key=lambda r: -r["diagnostics"]), indent=2) + "\n", encoding="utf-8")

raw = path("analysis/nso/main-uncompressed.nso").read_bytes()
assert hashlib.sha256(raw).hexdigest() == "bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968"
image = Image(raw)
frames = [json.loads(line) for line in path("analysis/nso/unwind-inventory-v1/frames.jsonl").read_text().splitlines()]
frame_map = {f["rva"]: f for f in frames}
cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
native = []
for address in (0xB5B390, 0x11A4CC0, 0x15C5AE0):
    frame = frame_map[address]
    code = image.read(address, frame["end_rva"] - address)
    instructions = [dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str, bytes_hex=i.bytes.hex()) for i in cs.disasm(code, address)]
    assert len(instructions) * 4 == len(code)
    native.append(dict(start=address, end=frame["end_rva"], bytes=len(code), sha256=hashlib.sha256(code).hexdigest(), frame=frame, instructions=instructions))
(private / "native-candidates.json").write_text(json.dumps(native, indent=2) + "\n", encoding="utf-8")
native_calls = []
for offset, start, size in image.segments[:1]:
    for at in range(0, size - 3, 4):
        word = struct.unpack_from("<I", raw, offset + at)[0]
        if word & 0xFC000000 != 0x94000000:
            continue
        displacement = word & 0x03FFFFFF
        if displacement & 0x02000000:
            displacement -= 0x04000000
        address = start + at
        if address + displacement * 4 == native_helper:
            native_calls.append(address)
ordered = sorted(frames, key=lambda f: f["rva"])
frame_starts = [f["rva"] for f in ordered]
caller_frames = Counter()
for call in native_calls:
    i = bisect_right(frame_starts, call) - 1
    if i >= 0 and call < ordered[i]["end_rva"]:
        caller_frames[ordered[i]["rva"]] += 1
(private / "array-helper-call-corpus.json").write_text(json.dumps(dict(helper=native_helper, direct_calls=native_calls, enclosing_exact_frames=[dict(start=address, calls=count) for address, count in caller_frames.most_common()]), indent=2) + "\n", encoding="utf-8")
report = dict(status="READ_ONLY_FRESH_CANONICAL_COMPILER_AND_NATIVE_MECHANISM_SURVEY", recovery_run=RUN, assemblies=public_assemblies, source_manifest_sha256=sha(summary_path), private_evidence=str(private.relative_to(ROOT)),
    array_helper_native=dict(rva=hex(native_helper), bytes=native[0]["bytes"], sha256=native[0]["sha256"], direct_call_sites=len(native_calls), enclosing_exact_frames=len(caller_frames)),
    original_native_sha256=hashlib.sha256(raw).hexdigest(), core_modified=False, exported_source_modified=False, native_executed=False, original_methods_invoked=0, full_clean_decompile_ready=False,
    scope="Complete matching-reference canonical log counts and checked source hashes. Owner declarations use conservative nearest exported declaration grouping and are observational, not formal C# semantic ownership. Four-line source vicinity is association, not a proof of root cause or recoverable error count. Original exact-FDE native candidates and all direct array-helper callers are retained privately for mechanism review.", source_sha256=sha("src/re/tools/aggregate_abi_compiler_mechanisms_v38.py"))
path("reports/compiler-mechanism-survey-v38.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(dict(status=report["status"], assemblies=[dict(assembly=a["assembly"], diagnostics=a["unique_diagnostic_lines"], vicinity=a["exact_source_vicinity_counts"]) for a in public_assemblies], native=report["array_helper_native"])))
