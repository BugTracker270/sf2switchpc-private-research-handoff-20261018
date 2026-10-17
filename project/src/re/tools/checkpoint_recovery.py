"""Record recovery checkpoint integrity and AI pair coverage without uploading inputs."""
import collections
import datetime
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination
ROOT=Path(__file__).resolve().parents[3]

def write(path,value):destination(ROOT,ROOT/path).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def main():
    expected={
      'input/base/Shadow Fight 2 [0100AB000ABFE000][v0][Base].nsp':'98d2d44f224321a174ce672826c5ece77d4f98350da336a21ffefc247e36cba5',
      'input/update/Shadow Fight 2 [0100AB000ABFE800][v131072][Up v1.1.0].nsp':'21831c39c058b815d838a7543678685ef89e1e95778753e71091ae3b8415b8f8'}
    if '--skip-input-rehash' not in sys.argv:
        results=[]
        for relative,digest in expected.items():
            path=ROOT/relative;actual=sha(path)
            results.append(dict(path=relative,sha256=actual,status='PASS_UNCHANGED' if actual==digest else 'FAIL_CHANGED'))
            print(relative,results[-1]['status'],flush=True)
        write('reports/input-integrity-recheck.json',dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),inputs=results,original_archives_modified=False))
        if any(r['status']!='PASS_UNCHANGED' for r in results):raise ValueError('Input hash changed')
    rows=[json.loads(l) for l in (ROOT/'analysis/assets/tactics-decoded-v2/manifest.jsonl').open(encoding='utf-8')]
    pairs=[tuple(r['weapon_identifiers']) for r in rows if r.get('version_candidate')==1]
    left={a for a,b in pairs};right={b for a,b in pairs};observed=set(pairs);missing={(a,b) for a in left for b in right}-observed
    ai=dict(weapon_pair_tables=len(pairs),unique_pairs=len(observed),left_identifiers=len(left),right_identifiers=len(right),
        unobserved_cartesian_combinations=len(missing),required_cartesian_product_known=False,
        duplicate_pairs=[pair for pair,count in collections.Counter(pairs).items() if count>1],
        single_identifier_tables=sum(r.get('version_candidate')==2 for r in rows),
        status='OBSERVED_PAIR_SET_REQUIRED_COMBINATIONS_UNVERIFIED',
        limitation='Observed header strings only. No dense Cartesian requirement is established; absent combinations are not automatically missing assets. Empty identifiers, aliases and ordering require native-reader validation.')
    write('analysis/assets/tactics-decoded-v2/pair-coverage.json',ai)
    print('AI observed header pairs:',len(observed),'; distinct identifiers per position:',len(left),len(right),'; required combination set unknown',flush=True)
    extraction=json.loads((ROOT/'reports/extract-manifest.json').read_text(encoding='utf-8-sig'))
    lines=['hactool 1.4.0 extraction checkpoint; actual detailed logs remain under logs/.',
        'No key values are included here. Exit code alone is not accepted without semantic/output checks.']
    for row in extraction['operations']:
        lines.append(f"{row['status']} exit={row['exit_code']} output={row['output']} source_nca={row['source_nca']} base_nca={row.get('base_nca')} signature_failures={row['signature_failure_count']} errors={row['errors']}")
    destination(ROOT,ROOT/'reports/extract.log').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    destination(ROOT,ROOT/'reports/ai-data-recovery.md').write_text(f'''# AI tactic recovery

All 1,579 entries in the original tactics_compressed directory are accounted for: 1,578 bounded LZMA-alone decodes and one uncompressed XML reference. Size, EOF, trailing data and SHA-256 are recorded; the original compressed payloads remain intact.

Observed header kind 1 contains two zero-terminated identifier strings: {len(pairs)} distinct pairs, with {len(left)} and {len(right)} distinct strings per position. Some identifiers are empty. No requirement for a complete Cartesian grid has been established; aliases, canonical ordering and supported pair selection require native-reader validation. Unobserved combinations are not reported as missing game files. Header kind 2 contains one identifier: {ai['single_identifier_tables']} tables. These are observed format distinctions; candidate version labels and the remaining numeric schema still need native validation.

Version 1 of this research decoder incorrectly expected two names for both formats; 36 valid single-name records were consequently flagged as header errors, and one XML entry was misclassified. The authoritative version-2 manifest resolves these without altering any source assets. Its unresolved list is empty.

Recovered decoded bytes are in analysis/assets/tactics-decoded-v2. No decision weights, distance/height axes, animation indices or tactic selection behavior have been invented. AttackTableHolder and TacticalTableHolder native readers and the supplied ComputerSettings data remain the sources for subsequent semantic work.
''',encoding='utf-8')
    print('Checkpoint input integrity, extraction log and AI coverage saved.',flush=True)
if __name__=='__main__':main()
