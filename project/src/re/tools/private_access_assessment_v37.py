"""Read-only v37 compiler census; preserve source contexts privately on the USB."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src/tools"))
from usb_boundary import destination

RUN = "nso-runtime-helper-abi-v37"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest_path = ROOT / f"reports/recovered-source-profile-legacy-reference-check-{RUN}.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    assemblies = []
    private = []
    cached = {}
    for item in manifest["assemblies"]:
        path = ROOT / item["compiler_log"]
        seen = set()
        codes = Counter()
        members = Counter()
        expressions = defaultdict(Counter)
        examples = defaultdict(list)
        for line in path.open(encoding="utf-8-sig", errors="strict"):
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
            member = re.search(r"'([^']+)'", match[2])
            loc = re.match(r"(.+\.cs)\((\d+),(\d+)\):", line)
            if not member or not loc:
                raise ValueError("Unrecognized private-access diagnostic")
            name = member[1]
            members[name] += 1
            source = Path(loc[1])
            source.relative_to(ROOT)
            if source not in cached:
                cached[source] = source.read_text(encoding="utf-8-sig").splitlines()
            at = int(loc[2])
            source_line = cached[source][at - 1]
            identifier = name.rsplit(".", 1)[-1]
            tail = source_line[int(loc[3]) - 1:]
            kind = "unsupported_or_ambiguous"
            if tail.startswith(identifier) and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", identifier):
                after = tail[len(identifier):].lstrip()
                if re.match(r"=(?!=|>)", after):
                    kind = "simple_store"
                elif re.match(r"(?:\+\+|--|[+*/%&|^-]=)", after):
                    kind = "read_modify_write"
                else:
                    kind = "read_or_address_other"
            expressions[name][kind] += 1
            if len(examples[name]) < 3:
                examples[name].append({"source": str(source.relative_to(ROOT)), "line": at,
                    "context": cached[source][max(0, at - 4):at + 3]})
        if len(seen) != item["unique_compiler_diagnostic_lines"]:
            raise ValueError("Diagnostic count does not match frozen source report")
        assemblies.append({"assembly": item["assembly"], "unique_diagnostic_lines": len(seen),
            "error_codes": dict(codes.most_common()), "private_access_diagnostics": codes["CS0122"],
            "top_inaccessible_members": dict(members.most_common(60)),
            "top_member_source_expression_shapes": {name: dict(expressions[name]) for name, _ in members.most_common(60)},
            "compiler_log_sha256": sha(path), "source_text_edited": False})
        private.append({"assembly": item["assembly"], "examples": dict(examples)})
    private_path = destination(ROOT, ROOT / "analysis/reconstruction/private-access-v37/census-source-contexts.json")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(json.dumps(private, indent=2) + "\n", encoding="utf-8")
    report = {"status": "READ_ONLY_PRIVATE_ACCESS_COMPILER_CENSUS", "recovery_run": RUN,
        "source_manifest": str(manifest_path.relative_to(ROOT)), "source_manifest_sha256": sha(manifest_path),
        "assemblies": assemblies, "private_contexts_sha256": sha(private_path),
        "source_edited": False, "core_edited": False, "game_methods_executed": 0,
        "whole_game_source_ready": False,
        "scope": "Unique compiler diagnostic lines, including cascades; these are not unique recovery defects. Source contexts remain private and are not type or native proof."}
    output = destination(ROOT, ROOT / "reports/private-access-census-v37.json")
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({a["assembly"]: {"private": a["private_access_diagnostics"],
        "top": dict(list(a["top_inaccessible_members"].items())[:20])} for a in assemblies}))


if __name__ == "__main__":
    main()
