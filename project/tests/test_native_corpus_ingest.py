import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import unittest

spec=importlib.util.spec_from_file_location('native_corpus_index',Path(__file__).resolve().parents[1]/'src/re/tools/native_corpus_index.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class Corpus:
    def __init__(self,data):self.data=data
    def open(self,mode):return io.BytesIO(self.data)
    def relative_to(self,root):return Path('fixture/functions.jsonl')

def payload(rva,status='PSEUDOCODE_EXPORTED',target=0x7100002000):
    return dict(rva=rva,name='entry_'+hex(rva),status=status,assembly=f'{0x7100000000+rva:x}\t00000094\tbl 0x{target:x}',body_bytes=4)

class CorpusOverlayTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:')
        self.db.executescript('CREATE TABLE functions(rva INTEGER PRIMARY KEY,name,signature,corpus,offset,length,status,body_bytes,prototype_applied);CREATE TABLE aliases(rva,name,signature);CREATE TABLE calls(caller_rva,callee_rva,kind,instruction);')
        self.db.execute('INSERT INTO aliases VALUES(?,?,?)',(0x1000,'managed_alias','void f()'));self.db.commit()
    def tearDown(self):self.db.close()
    def ingest(self,*rows):
        data=b''.join((json.dumps(row)+'\n').encode() for row in rows)
        with self.db:return module.ingest(self.db,Corpus(data))
    def test_failed_overlay_retains_existing_good_body_and_edges(self):
        self.ingest(payload(0x1000));self.ingest(payload(0x1000,'ERROR',0x7100003000))
        self.assertEqual(self.db.execute('SELECT status FROM functions').fetchone()[0],'PSEUDOCODE_EXPORTED')
        self.assertEqual(self.db.execute('SELECT callee_rva FROM calls').fetchall(),[(0x2000,)])
    def test_success_repairs_error_and_preserves_metadata_alias(self):
        self.ingest(payload(0x1000,'ERROR'));self.ingest(payload(0x1000))
        self.assertEqual(self.db.execute('SELECT status FROM functions').fetchone()[0],'PSEUDOCODE_EXPORTED')
        self.assertEqual(self.db.execute('SELECT name FROM aliases').fetchall(),[('managed_alias',)])
    def test_duplicate_success_replaces_instead_of_accumulating_edges(self):
        self.ingest(payload(0x1000));self.ingest(payload(0x1000,target=0x7100004000))
        self.assertEqual(self.db.execute('SELECT callee_rva FROM calls').fetchall(),[(0x4000,)])
    def test_partial_live_record_is_not_indexed(self):
        complete=(json.dumps(payload(0x1000))+'\n').encode()
        with self.db:module.ingest(self.db,Corpus(complete+json.dumps(payload(0x2000)).encode()))
        self.assertEqual(self.db.execute('SELECT rva FROM functions').fetchall(),[(0x1000,)])
    def test_malformed_batch_rolls_back_transaction(self):
        self.ingest(payload(0x1000));data=(json.dumps(payload(0x2000))+'\n{bad}\n').encode()
        with self.assertRaises(json.JSONDecodeError):
            with self.db:module.ingest(self.db,Corpus(data))
        self.assertEqual(self.db.execute('SELECT rva FROM functions').fetchall(),[(0x1000,)])

if __name__=='__main__':unittest.main()
