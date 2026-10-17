"""Correct target-specific IL2CPP runtime layouts without altering Dumper output.

Metadata v24.0 alone does not select this Unity 2018.1 runtime layout. Native
code uses static_fields=0xB8, vtable=0x128 and array data=0x20 on ARM64.
"""
from pathlib import Path
import hashlib
import json
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def main():
    source=ROOT/'analysis/il2cpp/effective-main/il2cpp_ghidra.h'
    original=source.read_bytes();text=original.decode('utf-8')
    replacements={
        '    Il2CppType* byval_arg;':'    Il2CppType byval_arg;',
        '    Il2CppType* this_arg;':'    Il2CppType this_arg;',
        '    void* interopData;\n    void* fields;':'    void* interopData;\n    Il2CppClass* klass;\n    void* fields;',
        'typedef int32_t il2cpp_array_size_t;':'typedef uintptr_t il2cpp_array_size_t;',
    }
    # Normalize only the derived header's line endings.
    text=text.replace('\r\n','\n')
    for before,after in replacements.items():
        if text.count(before)!=1:raise ValueError('Unexpected source layout: '+before)
        text=text.replace(before,after)
    target=destination(ROOT,ROOT/'analysis/il2cpp/effective-main/il2cpp_ghidra_runtime_v2.h')
    if target.exists():raise ValueError('Preserve prior corrected header')
    target.write_text(text,encoding='utf-8',newline='\n')
    report=dict(source=str(source.relative_to(ROOT)),source_sha256=hashlib.sha256(original).hexdigest(),
        output=str(target.relative_to(ROOT)),output_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
        corrected_layout_gates=dict(static_fields='0xB8',vtable='0x128',array_items='0x20'),
        evidence='BinaryReader virtual calls 0x1041D10/0x1041EF0; class static loads in 0x1041D10; array indexing in 0x103E660. Class field names outside these gates require individual validation.')
    destination(ROOT,ROOT/'analysis/il2cpp/runtime-header-v2.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
