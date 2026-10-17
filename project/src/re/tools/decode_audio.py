"""Decode local exported FSBs and validate PCM sample counts; no playback/upload."""
import collections
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import wave
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination,require_space
ROOT=Path(__file__).resolve().parents[3]

def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def decode(path,source,output,tool):
    row=dict(source=str(path.relative_to(ROOT)),source_sha256=sha(path))
    try:
        info=subprocess.run([str(tool),'-m','-I',str(path)],capture_output=True,timeout=60)
        if info.returncode:raise ValueError('Metadata decoder exit '+str(info.returncode)+': '+info.stderr.decode('utf-8',errors='replace'))
        metadata=json.loads(info.stdout);row['metadata']=metadata
        if metadata['streamInfo']['total']!=1:raise ValueError('Multiple subsongs require an explicit split; do not silently drop streams')
        target=destination(ROOT,output/path.relative_to(source).with_suffix('.wav'));target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists():raise ValueError('Output exists; preserve prior decode')
        command=[str(tool),'-i','-o',str(target),str(path)]
        result=subprocess.run(command,capture_output=True,timeout=120)
        row.update(command=command,exit_code=result.returncode,stdout=result.stdout.decode('utf-8',errors='replace'),stderr=result.stderr.decode('utf-8',errors='replace'))
        if result.returncode:raise ValueError('Audio decode failed')
        with wave.open(str(target),'rb') as pcm:
            frames,channels,rate,width=pcm.getnframes(),pcm.getnchannels(),pcm.getframerate(),pcm.getsampwidth()
            if (frames,channels,rate)!=(metadata['numberOfSamples'],metadata['channels'],metadata['sampleRate']):raise ValueError('PCM count/rate/channel mismatch')
            read_frames=0;nonzero=False
            while True:
                block=pcm.readframes(65536)
                if not block:break
                if len(block)%(channels*width):raise ValueError('Partial PCM sample frame')
                read_frames+=len(block)//(channels*width);nonzero|=any(block)
            if read_frames!=frames:raise ValueError('Truncated PCM data')
        row.update(output=str(target.relative_to(ROOT)),output_sha256=sha(target),output_bytes=target.stat().st_size,
            frames=frames,channels=channels,sample_rate=rate,sample_width=width,nonzero_pcm=nonzero,status='PASS_PCM_SAMPLE_MATCH')
    except Exception as error:row.update(status='ERROR',error=str(error))
    return row

def main():
    require_space(ROOT,2*1024**3)
    lock=json.loads((ROOT/'reports/vgmstream-lock.json').read_text(encoding='utf-8-sig'))
    tool=ROOT/'tools'/('vgmstream-'+lock['version'])/'vgmstream-cli.exe'
    source=ROOT/'analysis/assets/unity-export/ExportedProject/Assets'
    output=destination(ROOT,ROOT/'analysis/assets/audio-decoded');output.mkdir(exist_ok=True)
    manifest=destination(ROOT,output/'manifest.jsonl')
    if manifest.exists():raise ValueError('Audio decode manifest exists; preserve evidence')
    banks=sorted(source.rglob('*.fsb'));rows=[]
    with ThreadPoolExecutor(max_workers=2) as pool,manifest.open('w',encoding='utf-8') as writer:
        jobs=[pool.submit(decode,p,source,output,tool) for p in banks]
        for i,future in enumerate(as_completed(jobs),1):
            row=future.result();rows.append(row);writer.write(json.dumps(row,ensure_ascii=False)+'\n');writer.flush()
            if i%25==0:print(i,'/',len(banks),'audio banks processed',flush=True)
    report=dict(total=len(rows),status_counts=dict(collections.Counter(r['status'] for r in rows)),
        codecs=dict(collections.Counter(r.get('metadata',{}).get('encoding','UNKNOWN') for r in rows)),
        output_bytes=sum(r.get('output_bytes',0) for r in rows),
        original_loop_metadata_preserved=True,decode_policy='One full stream, original channels/rate, PCM16; loops ignored for finite output, original loop points retained in manifest.',
        limitation='Decoder/sample integrity verified; no listening comparison or in-game mixing/loop-trigger parity test.',tool_lock='reports/vgmstream-lock.json')
    destination(ROOT,output/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2),flush=True)
    if any(r['status']=='ERROR' for r in rows):raise RuntimeError('Audio decode errors retained in manifest')
if __name__=='__main__':main()
