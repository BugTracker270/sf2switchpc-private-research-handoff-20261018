"""Package an isolated correction to the independent tool's generic NSO mapper."""
import difflib
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from usb_boundary import destination

ROOT = Path(__file__).resolve().parents[3]
NAME = 'src/main.rs'


def main():
    lock = json.loads((ROOT / 'reports/il2cpp-dumper-rs-source-lock.json').read_text())
    entry = next(row for row in lock['files'] if row['path'] == NAME)
    source = destination(ROOT, ROOT / 'refs/il2cpp-dumper-rs' / NAME)
    before = source.read_bytes()
    if hashlib.sha256(before).hexdigest() != entry['sha256']:
        raise ValueError('Expected the unchanged pinned upstream source')
    original = before.decode('utf-8')
    old = '    il2cpp.va_segments = vec![VaSegment { vaddr: 0, memsz: stream_len, offset: 0 }];'
    # This same identity expression occurs in other format adapters. Change
    # only the already isolated NSO initialization function.
    start, end = original.index('fn init_nso('), original.index('fn init_wasm(')
    region = original[start:end]
    if region.count(old) != 1:
        raise ValueError('Unexpected NSO adapter shape')
    new = '''    // NSO addresses are RVAs, not file offsets. Preserve the verified
    // segment mappings for later metadata and method-body reads too.
    let image = nso.stream.data();
    il2cpp.va_segments = [0x10usize, 0x20, 0x30].into_iter().map(|base| {
        let read = |offset: usize| u32::from_le_bytes(
            image[offset..offset + 4].try_into().expect("validated NSO header")) as u64;
        VaSegment { vaddr: read(base + 4), memsz: read(base + 8), offset: read(base) }
    }).collect();'''
    region = region.replace('    let stream_len = nso.stream.data().len() as u64;\n', '')
    after = original[:start] + region.replace(old, new) + original[end:]
    saved = destination(ROOT, ROOT / 'analysis/reference/rust-upstream-main-145a7510.rs')
    if saved.exists():
        raise ValueError('Preserve earlier upstream snapshot')
    saved.write_bytes(before)
    patch = f'diff --git a/{NAME} b/{NAME}\n' + ''.join(difflib.unified_diff(
        original.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile='a/' + NAME, tofile='b/' + NAME))
    output = destination(ROOT, ROOT / 'src/re/tool-patches/rust-il2cpp-nso-mapping-experimental.patch')
    output.write_text(patch, encoding='utf-8', newline='\n')
    source.write_text(after, encoding='utf-8', newline='\n')
    report = dict(status='EXPERIMENTAL_NOT_VALIDATED', upstream=lock['upstream'], commit=lock['commit'],
                  patch=str(output.relative_to(ROOT)), sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                  files=[dict(path=NAME, before_sha256=entry['sha256'], sha256=hashlib.sha256(source.read_bytes()).hexdigest())],
                  scope='Generic NSO RVA-to-file mapping only. Test uses independently hashed uncompressed NSO. '
                        'Compressed-loader repacking and all recovered CIL semantics remain separate issues. '
                        'Upstream source/license provenance stays in the original source lock.')
    destination(ROOT, ROOT / 'reports/rust-nso-mapping-patch-lock.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
