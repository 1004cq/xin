import os, sys, tempfile, hashlib, re, json, io, zipfile
from pathlib import Path
from fastapi.testclient import TestClient
T=tempfile.TemporaryDirectory()
salt='ab'*16
os.environ.update(XIN_DATA=T.name,XIN_DEV='1',XIN_SESSION_SECRET='test-only-secret-not-for-production-123456',XIN_ADMIN_HASH=salt+':'+hashlib.scrypt(b'test-password',salt=bytes.fromhex(salt),n=16384,r=8,p=1,dklen=32).hex())
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from app import app,digest

def csrf(r):return re.search(r'name="csrf" value="([^"]+)"',r.text).group(1)
def test_flow(monkeypatch):
    a=TestClient(app); b=TestClient(app); outsider=TestClient(app)
    assert outsider.get('/admin').status_code==403
    assert a.post('/login',data={'password':'test-password'}).status_code==403
    r=a.post('/login',data={'csrf':csrf(a.get('/login')),'password':'test-password'}); assert r.status_code==200
    r=a.post('/new',data={'csrf':csrf(a.get('/new')),'lender':'测试甲','borrower':'测试乙','due':'2028-12-31','penalty':'100','ledger':'2026-01-01,借款,100.10,测试\n2026-01-02,借款,200.20\n2026-02-01,还款,50.05'})
    assert r.status_code==200,r.text
    token=re.search(r'/s/([\w-]+)',r.text).group(1); pin=re.search(r'value="(\d{8})"',r.text).group(1); id=re.search(r'/c/([a-f0-9]+)',r.text).group(1)
    assert outsider.get('/c/'+id+'/export').status_code==403
    s=b.get('/s/'+token); assert '250.25' in s.text
    sha=re.search(r'name="sha" value="([a-f0-9]+)"',s.text).group(1)
    data={'csrf':csrf(s),'pin':pin,'name':'测试乙','consent':'yes','sha':sha}
    assert b.post('/s/'+token,data=dict(data,sha='bad')).status_code==400
    assert '核验码错误' in b.post('/s/'+token,data=dict(data,pin='00000000')).text
    assert '确认记录已保存' in b.post('/s/'+token,data=data).text
    assert b.post('/s/'+token,data=data).status_code==409
    assert outsider.get('/copy/'+id).status_code==403
    z=zipfile.ZipFile(io.BytesIO(b.get('/copy/'+id).content)); receipt=json.loads(z.read('confirmation.json')); assert receipt['contract_sha256']==digest(z.read('contract.txt'))==sha
    assert receipt['ledger_sha256']==digest(z.read('ledger.json'))
    assert 'confirmation.json.ots' not in z.namelist()
    r=a.post('/c/'+id+'/attach',data={'csrf':csrf(a.get('/c/'+id))},files={'file':('test.txt',b'example')}); assert r.status_code==200
    z=zipfile.ZipFile(io.BytesIO(a.get('/c/'+id+'/export').content)); assert any(k.startswith('attachments/') for k in z.namelist()); manifest=json.loads(z.read('manifest.json')); assert all(digest(z.read(k))==v for k,v in manifest['files'].items())
    def unavailable(*a,**kw): raise FileNotFoundError('test OTS unavailable')
    monkeypatch.setattr('app.subprocess.run',unavailable)
    assert a.post('/c/'+id+'/ots',data={'csrf':csrf(a.get('/c/'+id))}).status_code==503
