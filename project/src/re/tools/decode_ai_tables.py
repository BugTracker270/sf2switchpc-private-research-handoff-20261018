"""Bounded Switch AI archive parser, traced from the supplied native readers.

Original table bytes remain private. The catalog records offsets and integrity;
the same parser can materialize a selected block for functional research.
"""
import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination,require_space
ROOT=Path(__file__).resolve().parents[3]

class Cursor:
    def __init__(self,data):self.data=memoryview(data);self.pos=0
    @property
    def remaining(self):return len(self.data)-self.pos
    def take(self,n):
        if n<0 or n>self.remaining:raise ValueError(f'Truncated field at {self.pos:#x}, length {n}')
        start=self.pos;self.pos+=n;return self.data[start:self.pos]
    def number(self,kind):return struct.unpack('<'+kind,self.take(struct.calcsize('<'+kind)))[0]
    def array(self,kind,n):
        if n<0 or n>self.remaining//struct.calcsize('<'+kind):raise ValueError('Array count exceeds block bounds')
        return [v[0] for v in struct.iter_unpack('<'+kind,self.take(n*struct.calcsize('<'+kind)))]
    def zero_string(self):
        start=self.pos
        while self.remaining and self.pos-start<=4096:
            if self.number('B')==0:return bytes(self.data[start:self.pos-1]).decode('utf-8',errors='strict')
        raise ValueError('Unterminated or oversized identifier')
    def names(self,count_kind):
        count=self.number(count_kind)
        if count<0:raise ValueError('Negative name count')
        lengths=self.array('B',count);names=[]
        for length in lengths:
            # BinaryReader.ReadChars counts UTF-16 characters. Shipping names are
            # ASCII; reject unsupported encodings rather than silently misalign.
            raw=bytes(self.take(length))
            if any(b>=128 for b in raw):raise ValueError('Non-ASCII name requires UTF-16 character-count reader')
            names.append(raw.decode('ascii'))
        return names
    def finish(self):
        if self.remaining:raise ValueError(f'Unconsumed bytes: {self.remaining} at {self.pos:#x}')

def index_at(items,index):
    if not 0<=index<len(items):raise ValueError(f'Index {index} exceeds {len(items)} entries')
    return items[index]

def take_pool(items,start,count):
    if start<0 or count<0 or start+count>len(items):raise ValueError('Flattened pool slice exceeds count')
    return items[start:start+count]

def parse_holder(data,materialize=False):
    c=Cursor(data);animations=c.names('H');weapons=c.names('h')
    keys=['animations','groups','tables','frames','intervals','distances','interframes']
    counts=dict(zip(keys,[c.number('I') for _ in keys]))
    if any(v>max(1,len(data)) for v in counts.values()):raise ValueError('Unreasonable declared pool count')
    selected=[index_at(animations,i) for i in c.array('H',counts['animations'])]
    scale=c.number('h');distances=c.array('h',counts['distances'])
    if scale:distances=[v*scale for v in distances]
    # All source values fit exactly in float32; conversion is still explicit.
    distances=[struct.unpack('<f',struct.pack('<f',v))[0] for v in distances]
    interframes=c.array('i',counts['interframes'])
    interval_animations=[index_at(animations,i) for i in c.array('H',counts['intervals'])]
    used=collections.Counter();labels=collections.Counter();out=[]
    interval_shapes=collections.Counter();unordered=0;empty_tables=0
    for animation in selected:
        ng=c.number('H');used['groups']+=ng;groups=[]
        for _ in range(ng):
            weapon=index_at(weapons,c.number('H'));nt=c.number('H');used['tables']+=nt;tables=[]
            for _ in range(nt):
                label=c.zero_string();labels[label]+=1;nf=c.number('H');used['frames']+=nf
                first_frame=c.number('h') if nf else 0;frames=[]
                if not nf:empty_tables+=1
                for _ in range(nf):
                    ni=c.number('H');ai=take_pool(interval_animations,used['intervals'],ni);used['intervals']+=ni
                    ds=[];fs=[]
                    for _ in range(ni):
                        n=c.number('H');ds.append(take_pool(distances,used['distances'],n));used['distances']+=n
                    for _ in range(ni):
                        n=c.number('H');fs.append(take_pool(interframes,used['interframes'],n));used['interframes']+=n
                    for name,d,f in zip(ai,ds,fs):
                        interval_shapes[(len(d),len(f))]+=1
                        if any(a>b for a,b in zip(d,d[1:])):unordered+=1
                    if materialize:frames.append([dict(animation=a,distances=d,interframes=f) for a,d,f in zip(ai,ds,fs)])
                if materialize:tables.append(dict(label=label,first_frame=first_frame,frames=frames))
            if materialize:groups.append(dict(weapon=weapon,tables=tables))
        if materialize:out.append(dict(animation=animation,groups=groups))
    c.finish()
    for key in keys[1:]:
        if used[key]!=counts[key]:raise ValueError(f'Pool {key}: consumed {used[key]} != declared {counts[key]}')
    result=dict(animation_dictionary=len(animations),weapon_dictionary=len(weapons),counts=counts,distance_scale=scale,
        labels=dict(labels),empty_tables=empty_tables,unordered_distance_lists=unordered,
        interval_shapes={f'{a}:{b}':n for (a,b),n in interval_shapes.items()})
    if materialize:result.update(animation_names=animations,weapon_names=weapons,entries=out)
    return result

def parse_shift(data,materialize=False):
    c=Cursor(data);count=c.number('I')
    if count>len(data)//5:raise ValueError('Shift count exceeds bounds')
    animations=[];nodes=collections.Counter();total=0
    for _ in range(count):
        name=c.zero_string();length=c.number('I');s=Cursor(c.take(length));nc=s.number('I')
        if nc>length//2:raise ValueError('Node count exceeds shift block')
        names=[s.zero_string() for _ in range(nc)];nfbytes=s.remaining
        if not nc or nfbytes%(4*nc):raise ValueError('Shift dimensions do not divide payload')
        nframes=nfbytes//(4*nc);floats=s.array('f',nfbytes//4);s.finish()
        if not all(math.isfinite(v) for v in floats):raise ValueError('Nonfinite shift values')
        total+=len(floats);nodes.update(names)
        row=dict(animation=name,nodes=names,frames=nframes)
        if materialize:row['values']=floats
        animations.append(row)
    c.finish();return dict(animations=animations,float_count=total,node_names=dict(nodes))

def parse_archive(data,name_count,materialize=False):
    if name_count not in (1,2):raise ValueError('Archive must have one or two weapon identifiers')
    c=Cursor(data);blocks=[]
    while c.remaining:
        start=c.pos;kind=c.number('I')
        if kind>10:raise ValueError(f'Unknown tactic table type {kind}')
        names=[c.zero_string() for _ in range(name_count)]
        length=c.number('I');offset=c.pos;payload=c.take(length)
        row=dict(offset=start,table_type=kind,weapons=names,payload_offset=offset,payload_bytes=length,
            sha256=hashlib.sha256(payload).hexdigest())
        if length:
            row['decoded']=parse_shift(payload,materialize) if kind==7 else parse_holder(payload,materialize)
        else:row['decoded']=None
        blocks.append(row)
    c.finish();return blocks

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--catalog',action='store_true')
    p.add_argument('--source');p.add_argument('--names',type=int,choices=[1,2]);p.add_argument('--output')
    a=p.parse_args()
    if a.catalog:
        require_space(ROOT,256*1024**2);output=destination(ROOT,ROOT/'analysis/assets/ai-tables-v1')
        output.mkdir(exist_ok=True);manifest=destination(ROOT,output/'manifest.jsonl')
        if manifest.exists():raise ValueError('Preserve previous table catalog')
        totals=collections.Counter();failures=[];rows=[]
        with manifest.open('w',encoding='utf-8') as writer:
            for i,line in enumerate((ROOT/'analysis/assets/tactics-decoded-v2/manifest.jsonl').open(encoding='utf-8'),1):
                source=json.loads(line)
                if not source.get('output'):continue
                path=ROOT/source['output'];row=dict(source=source['output'])
                try:
                    raw=path.read_bytes()
                    if hashlib.sha256(raw).hexdigest()!=source['decoded_sha256']:raise ValueError('Decoded source hash changed')
                    blocks=parse_archive(raw,len(source['weapon_identifiers']))
                    row.update(status='PASS_NATIVE_SCHEMA_BOUNDS_AND_POOL_COUNTS',blocks=blocks)
                    totals['archives']+=1
                    for b in blocks:
                        totals['blocks']+=1;totals['table_type_'+str(b['table_type'])]+=1
                        d=b['decoded']
                        if d and b['table_type']!=7:
                            for key,value in d['counts'].items():totals[key]+=value
                            totals['unordered_distance_lists']+=d['unordered_distance_lists']
                        elif d:totals['shift_animations']+=len(d['animations']);totals['shift_floats']+=d['float_count']
                except Exception as error:
                    row.update(status='FAIL_SCHEMA',error=str(error));failures.append(row)
                writer.write(json.dumps(row)+'\n');rows.append(row)
                if i%100==0:writer.flush();print(i,'source entries; failures',len(failures),flush=True)
        report=dict(status='PASS' if not failures else 'FAIL',totals=dict(totals),failures=failures,
            scope='Native reader schema and complete pool/boundary validation. Runtime AI decision equivalence not established.',
            evidence_rvas=['0x103C900','0x103D2B0','0x1041D10','0x1041EF0','0x1042000','0x103EC60','0x103EE80'])
        destination(ROOT,output/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report,indent=2))
        return 0 if not failures else 1
    if not(a.source and a.names and a.output):p.error('Supply --catalog or --source/--names/--output')
    source=Path(a.source).resolve()
    if not source.is_relative_to(ROOT):raise ValueError('Source must remain on USB workspace')
    result=parse_archive(source.read_bytes(),a.names,materialize=True)
    target=destination(ROOT,Path(a.output).resolve())
    if target.exists():raise ValueError('Preserve previous materialized output')
    target.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print('Decoded',len(result),'blocks to',target)
    return 0
if __name__=='__main__':raise SystemExit(main())
