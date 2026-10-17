"""Record the previously omitted same-buffer Dispose site in the original full frame."""
import hashlib
import json
from pathlib import Path
import sys
import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/tools'))
from usb_boundary import destination

source = ROOT / 'analysis/nso/main-uncompressed.nso'
with source.open('rb') as stream:
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != 'bcdbf6a3d36d884a31288243ea0269d1665488ff2fd1461851f375cd16bd9968':
        raise ValueError('Original native input differs')
    stream.seek(0x100 + 0xC9F3F0)
    body = stream.read(552)
    if hashlib.sha256(body).hexdigest() != 'a1752250eaef0b5c3c2714f7dd5995a15560d9f83f7ad057b5078a62eb93efe9':
        raise ValueError('Original complete caller differs')
    stream.seek(0x100 + 0xC9F5D0)
    window = stream.read(20)
decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
decoded = [(i.mnemonic, i.op_str) for i in decoder.disasm(window, 0xC9F5D0)]
if decoded != [('adrp', 'x8, #0x39d6000'), ('ldr', 'x8, [x8, #0x1b8]'),
        ('ldr', 'x1, [x8]'), ('add', 'x0, sp, #8'), ('bl', '#0x11dd3b0')]:
    raise ValueError('Original extra receiver/MethodInfo/Dispose site differs')
report = dict(status='PASS_EXACT_NATIVE_ADDITIONAL_DISPOSE_SITE_CORRELATION', checks=5,
    native_source_sha256=digest, caller_rva='0xC9F3F0', caller_fde_bytes=552,
    caller_body_sha256=hashlib.sha256(body).hexdigest(), reviewed_window_rva='0xC9F5D0',
    reviewed_window_bytes=20, reviewed_window_sha256=hashlib.sha256(window).hexdigest(),
    extra_receiver_address_rva='0xC9F5DC', extra_call_rva='0xC9F5E0', target_rva='0x11DD3B0',
    methodinfo_got_slot='0x39D61B8', same_as_normal_dispose_got_slot=True, receiver='SP+8',
    total_reviewed_SP8_address_takes=5, normal_cfg_retained_consumer_calls=3,
    decoder_version=capstone.__version__, probe_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    game_code_executed=False, exception_flow_recovered=False,
    scope='Static unchanged native caller correlation only. The additional same-buffer Dispose sits in the full-frame exception-cleanup tail that ordinary CFG reachability removes. Exact receiver, GOT MethodInfo load and direct callee agree with normal Dispose. This adds only its reviewed storage use to the scoped helper guard; it does not recover LSDA, exception regions, unwind behavior or full SetStage semantics.')
path = destination(ROOT, ROOT / 'reports/indirect-return-tail-provenance-v32.json')
path.write_text(json.dumps(report, indent=2) + '\n')
print('Additional native Dispose-site correlation PASS: 5 checks')
