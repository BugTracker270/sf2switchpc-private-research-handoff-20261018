"""Read ELF64 dynamic symbol regions from already decompressed NSOs, locally."""
import collections
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def symbols(path):
    data=path.read_bytes()
    if data[:4]!=b'NSO0':raise ValueError('NSO magic')
    if struct.unpack_from('<I',data,12)[0]&7:raise ValueError('Compressed NSO: decompress first')
    ro_file,ro_rva,ro_size=struct.unpack_from('<III',data,0x20)
    str_rel,str_size=struct.unpack_from('<II',data,0x90)
    sym_rel,sym_size=struct.unpack_from('<II',data,0x98)
    if str_rel+str_size>ro_size or sym_rel+sym_size>ro_size or sym_size%24:raise ValueError('Dynamic regions outside rodata')
    strings=data[ro_file+str_rel:ro_file+str_rel+str_size];result=[]
    for offset in range(ro_file+sym_rel,ro_file+sym_rel+sym_size,24):
        name,info,other,section,value,size=struct.unpack_from('<IBBHQQ',data,offset)
        if name>=len(strings):raise ValueError('Symbol string outside table')
        end=strings.find(b'\0',name)
        if end<0:raise ValueError('Unterminated symbol')
        text=strings[name:end].decode('utf-8')
        if not text:continue
        result.append(dict(name=text,binding=info>>4,type=info&15,visibility=other&3,section=section,value=value,size=size,role='IMPORT' if section==0 else 'EXPORT'))
    return result,hashlib.sha256(data).hexdigest()

def main():
    modules={};hashes={}
    for name in ['main','sdk','subsdk0']:
        path=ROOT/'analysis/nso'/(name+'-uncompressed.nso')
        modules[name],hashes[name]=symbols(path)
    exporters=collections.defaultdict(set)
    for module,rows in modules.items():
        for row in rows:
            if row['role']=='EXPORT':exporters[row['name']].add(module)
    rows=[]
    for module,items in modules.items():
        for item in items:rows.append(dict(module=module,**item,providers=','.join(sorted(exporters[item['name']]-{module})) if item['role']=='IMPORT' else ''))
    with destination(ROOT,ROOT/'analysis/nso/dynamic-symbols.csv').open('w',encoding='utf-8',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    report=dict(modules={name:dict(symbols=len(items),roles=dict(collections.Counter(r['role'] for r in items)),sha256_uncompressed=hashes[name]) for name,items in modules.items()},
        import_resolution={name:dict(collections.Counter('RESOLVED_SUPPLIED_MODULE' if exporters[r['name']]-{name} else 'EXTERNAL_OR_RUNTIME' for r in items if r['role']=='IMPORT')) for name,items in modules.items()},
        limitations=['Symbol-name matches identify candidate providers; binding/relocation/runtime resolution has not been emulated.',
          'Nintendo SDK and multimedia modules are supplied binary evidence. No commercial SDK was downloaded.'])
    destination(ROOT,ROOT/'analysis/nso/dynamic-symbols-summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
