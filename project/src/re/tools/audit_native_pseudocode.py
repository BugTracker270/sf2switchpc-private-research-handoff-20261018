"""Audit a closed index snapshot for partial-decompiler markers and out-of-range listing entries."""
import collections
import datetime
import json
from pathlib import Path
import re
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]
BASE=0x7100000000

def observations(row,bounds=None):
    text=row.get('pseudocode','')
    markers={name:len(re.findall(pattern,text,re.IGNORECASE)) for name,pattern in {
        'bad_instruction_or_data':r'\bhalt_baddata\s*\(|Bad instruction',
        'unimplemented_pcode':r'\bhalt_unimplemented\s*\(|unimplemented pcode',
        'warning_comments':r'WARNING:',
        'unrecovered_jump_table':r'Could not recover jumptable|unrecovered jumptable',
        'unresolved_flow':r'Could not recover jump|Could not recover indirect',
    }.items()}
    addresses=[int(match.group(1),16)-BASE for line in row.get('assembly','').splitlines()
               if (match:=re.match(r'^([0-9a-fA-F]+)\t',line))]
    outside=[rva for rva in addresses if bounds and not bounds[0]<=rva<bounds[1]]
    return dict(markers={key:value for key,value in markers.items() if value},listing_instructions=len(addresses),
        listing_outside_frame=len(outside),outside_examples=[hex(value) for value in outside[:8]])

def main():
    frames={row['rva']:(row['rva'],row['end_rva']) for row in map(json.loads,(ROOT/'analysis/nso/unwind-inventory-v1/frames.jsonl').open(encoding='utf-8'))}
    with sqlite3.connect((ROOT/'analysis/nso/corpus.sqlite').as_uri()+'?mode=ro',uri=True) as db:
        records=db.execute('SELECT rva,corpus,offset,length,status FROM functions ORDER BY corpus,offset').fetchall()
    # Close the read transaction before scanning files; the bulk writer can continue.
    db.close()
    counts=collections.Counter();marker_functions=collections.Counter();details=destination(ROOT,ROOT/'analysis/nso/pseudocode-quality-snapshot.jsonl')
    stream=None;current=None
    try:
        with details.open('w',encoding='utf-8') as output:
            for rva,corpus,offset,length,status in records:
                if corpus!=current:
                    if stream:stream.close()
                    stream=(ROOT/corpus).open('rb');current=corpus
                stream.seek(offset);raw=stream.read(length)
                if len(raw)!=length or not raw.endswith(b'\n'):raise ValueError('Indexed record is incomplete or changed')
                row=json.loads(raw)
                if row['rva']!=rva or row['status']!=status:raise ValueError('Index/record mismatch')
                observation=observations(row,frames.get(rva));counts['records']+=1
                if rva in frames:counts['records_with_frame']+=1
                if observation['markers']:
                    counts['records_with_partial_output_markers']+=1
                    marker_functions.update(observation['markers'].keys())
                if observation['listing_outside_frame']:counts['records_with_listing_outside_frame']+=1
                if observation['markers'] or observation['listing_outside_frame']:
                    output.write(json.dumps(dict(rva=rva,corpus=corpus,**observation))+'\n')
    finally:
        if stream:stream.close()
    report=dict(status='RECOVERY_QUALITY_LIMITATIONS_CONFIRMED' if counts['records_with_partial_output_markers'] or counts['records_with_listing_outside_frame'] else 'PASS_MARKER_AND_LISTING_BOUNDS_AUDIT_ONLY',
        utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),counts=dict(counts),functions_by_marker=dict(marker_functions),
        details=str(details.relative_to(ROOT)),snapshot_records=len(records),
        scope='Read-only snapshot of indexed original Ghidra output. Warning/partial-output markers are observations, not necessarily independent defects. Listing addresses outside a validated frame require boundary/flow review; omitted instructions and data are not certified by this check. Pseudocode export success does not mean clean decompilation. Bulk export can advance beyond this snapshot.')
    destination(ROOT,ROOT/'reports/native-pseudocode-quality.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
