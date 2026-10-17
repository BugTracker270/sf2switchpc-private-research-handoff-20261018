"""Catalog the local-only AssetRipper API; no external target allowed."""
import collections
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import sqlite3
import sys
import urllib.parse
import urllib.request
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from usb_boundary import destination

ROOT=Path(__file__).resolve().parents[3]
BASE='http://127.0.0.1:5888'

class Page(HTMLParser):
    def __init__(self):
        super().__init__();self.links=[];self.rows=[];self.row=None;self.cell=None;self.link=None;self.title='';self.in_title=False
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='title':self.in_title=True
        if tag=='tr':self.row={'cells':[],'links':[]}
        if tag=='td':self.cell=''
        if tag=='a':self.link={'href':attrs.get('href',''),'text':''}
    def handle_data(self,data):
        if self.in_title:self.title+=data
        if self.cell is not None:self.cell+=data
        if self.link is not None:self.link['text']+=data
    def handle_endtag(self,tag):
        if tag=='title':self.in_title=False
        if tag=='td' and self.row is not None:self.row['cells'].append((self.cell or '').strip());self.cell=None
        if tag=='a' and self.link is not None:
            self.links.append(self.link)
            if self.row is not None:self.row['links'].append(self.link)
            self.link=None
        if tag=='tr' and self.row is not None:self.rows.append(self.row);self.row=None

def get(path):
    if not path.startswith('/') or path.startswith('//'):raise ValueError('Local API paths only')
    with urllib.request.urlopen(BASE+path,timeout=180) as response:return response.read()

def main():
    rootpage=Page();rootpage.feed(get('/Bundles/View?Path='+urllib.parse.quote('{"P":[]}')).decode())
    links={link['href']:link['text'] for link in rootpage.links if link['href'].startswith('/Collections/View?')}
    database=destination(ROOT,ROOT/'analysis'/'assets'/'assets.sqlite')
    if database.exists():raise ValueError('Asset database exists; preserve prior annotations')
    connection=sqlite3.connect(database)
    connection.executescript('''CREATE TABLE collections(id INTEGER PRIMARY KEY,name TEXT,api_path TEXT,asset_count INTEGER);
    CREATE TABLE assets(collection_id INTEGER,path_id INTEGER,class TEXT,name TEXT,api_descriptor TEXT,source_file TEXT,
      inspection TEXT,PRIMARY KEY(collection_id,path_id));
    CREATE INDEX asset_name_idx ON assets(name); CREATE INDEX asset_class_idx ON assets(class);''')
    counts=collections.Counter();collection_counts=[]
    for href,name in links.items():
        descriptor=json.loads(urllib.parse.parse_qs(urllib.parse.urlsplit(href).query)['Path'][0])
        collection_id=descriptor['I']
        page=Page();page.feed(get(href).decode())
        rows=[]
        for row in page.rows:
            if len(row['cells'])!=3 or not row['cells'][0].lstrip('-').isdigit():continue
            path_id=int(row['cells'][0]);asset_class,asset_name=row['cells'][1:]
            asset_link=next((link for link in row['links'] if link['href'].startswith('/Assets/View?')),None)
            if not asset_link:continue
            asset_descriptor=urllib.parse.parse_qs(urllib.parse.urlsplit(asset_link['href']).query)['Path'][0]
            rows.append((collection_id,path_id,asset_class,asset_name,asset_descriptor,name,'CATALOGUED_NOT_VALIDATED'))
            counts[asset_class]+=1
        connection.execute('INSERT INTO collections VALUES(?,?,?,?)',(collection_id,name,href,len(rows)))
        connection.executemany('INSERT INTO assets VALUES(?,?,?,?,?,?,?)',rows)
        collection_counts.append(dict(id=collection_id,name=name,assets=len(rows)))
        print(name,len(rows),flush=True)
    connection.commit();connection.close()
    summary=dict(collections=collection_counts,asset_count=sum(counts.values()),by_type=dict(counts),
        source='AssetRipper 2.0.0 local API; includes generated collections',
        warnings=['AssetRipper reported Unknown scripting backend when loading the Switch Data directory. IL2CPP is independently proven.',
                  'Catalog is not export/import validation; generated assets may increase counts.'])
    destination(ROOT,ROOT/'analysis'/'assets'/'catalog-summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print('TOTAL',summary['asset_count'],'assets',len(links),'collections',flush=True)

if __name__=='__main__':main()
