import os,sys,tempfile,hashlib,re,json,io,zipfile,base64,struct
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from fastapi.testclient import TestClient
T=tempfile.TemporaryDirectory()
salt='ab'*16
ORIGIN='http://localhost:8000'
os.environ.update(XIN_BASE_URL=ORIGIN,XIN_DATA=T.name,XIN_DEV='1',XIN_SESSION_SECRET='test-only-secret-not-for-production-123456',XIN_ADMIN_HASH=salt+':'+hashlib.scrypt(b'test-password',salt=bytes.fromhex(salt),n=16384,r=8,p=1,dklen=32).hex())
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from app import app,digest
def csrf(r):return re.search(r'name="csrf" value="([^"]+)"',r.text).group(1)
def b64(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def client_data(kind,ch,origin=ORIGIN):
    return json.dumps({'type':kind,'challenge':ch,'origin':origin,'crossOrigin':False},separators=(',',':')).encode()
def registration(key,cid,ch):
    n=key.public_key().public_numbers()
    cose=cbor2.dumps({1:2,3:-7,-1:1,-2:n.x.to_bytes(32,'big'),-3:n.y.to_bytes(32,'big')})
    auth=hashlib.sha256(b'localhost').digest()+b'\x45'+struct.pack('>I',0)+bytes(16)+struct.pack('>H',len(cid))+cid+cose
    return {'id':b64(cid),'rawId':b64(cid),'type':'public-key','response':{'clientDataJSON':b64(client_data('webauthn.create',ch)),'attestationObject':b64(cbor2.dumps({'fmt':'none','attStmt':{},'authData':auth}))},'clientExtensionResults':{}}
def assertion(key,cid,ch,uv=True,origin=ORIGIN):
    cd=client_data('webauthn.get',ch,origin)
    auth=hashlib.sha256(b'localhost').digest()+bytes([5 if uv else 1])+struct.pack('>I',1)
    sig=key.sign(auth+hashlib.sha256(cd).digest(),ec.ECDSA(hashes.SHA256()))
    return {'id':b64(cid),'rawId':b64(cid),'type':'public-key','response':{'clientDataJSON':b64(cd),'authenticatorData':b64(auth),'signature':b64(sig)},'clientExtensionResults':{}}

def test_flow(monkeypatch):
    a,b,outsider=TestClient(app),TestClient(app),TestClient(app)
    assert outsider.get('/admin').status_code==403
    assert a.post('/login',data={'password':'test-password'}).status_code==403
    assert a.post('/login',data={'csrf':csrf(a.get('/login')),'password':'test-password'}).status_code==200
    r=a.post('/new',data={'csrf':csrf(a.get('/new')),'lender':'测试甲','borrower':'测试乙','due':'2028-12-31','penalty':'100','ledger':'2026-01-01,借款,100.10,测试\n2026-01-02,借款,200.20\n2026-02-01,还款,50.05'})
    assert r.status_code==200,r.text
    token=re.search(r'/s/([\w-]+)',r.text).group(1); pin=re.search(r'value="(\d{8})"',r.text).group(1); id=re.search(r'/c/([a-f0-9]+)',r.text).group(1)
    path='/s/'+token
    assert outsider.get('/c/'+id+'/export').status_code==403
    assert outsider.get(path+'/pdf').status_code==403
    assert '250.25' not in b.get(path).text
    assert '核验码错误' in b.post(path+'/unlock',data={'csrf':csrf(b.get(path)),'pin':'wrong'}).text
    s=b.post(path+'/unlock',data={'csrf':csrf(b.get(path)),'pin':pin});assert '250.25' in s.text
    pdf=b.get(path+'/pdf');assert pdf.content.startswith(b'%PDF')
    sha=re.search(r'name="sha" value="([a-f0-9]+)"',s.text).group(1)
    pdfsha=re.search(r'name="pdfsha" value="([a-f0-9]+)"',s.text).group(1)
    assert pdfsha==digest(pdf.content)
    form={'csrf':csrf(s),'name':'测试乙','consent':'yes','sha':sha,'pdfsha':pdfsha}
    assert b.post(path,data=form).status_code==409
    assert b.post(path+'/passkey/start',json=form,headers={'Origin':'https://evil.example'}).status_code==403
    headers={'Origin':ORIGIN}
    assert b.post(path+'/passkey/start',json=dict(form,pdfsha='bad'),headers=headers).status_code==400
    key=ec.generate_private_key(ec.SECP256R1());cid=b'xin-test-credential'
    def begin():
        x=b.post(path+'/passkey/start',json=form,headers=headers);assert x.status_code==200,x.text
        reg=registration(key,cid,x.json()['challenge'])
        x=b.post(path+'/passkey/register',json={'csrf':form['csrf'],'credential':reg},headers=headers);assert x.status_code==200,x.text
        return x.json()['challenge']
    ch=begin()
    bad=assertion(key,cid,ch,uv=False)
    assert b.post(path+'/passkey/finish',json={'csrf':form['csrf'],'credential':bad},headers=headers).status_code==400
    assert b.post(path+'/passkey/finish',json={'csrf':form['csrf'],'credential':assertion(key,cid,ch)},headers=headers).status_code==409
    ch=begin()
    good=assertion(key,cid,ch)
    data={'csrf':form['csrf'],'credential':good}
    assert b.post(path+'/passkey/finish',json=data,headers=headers).status_code==200
    assert b.post(path+'/passkey/finish',json=data,headers=headers).status_code==403
    assert outsider.get('/copy/'+id).status_code==403
    z=zipfile.ZipFile(io.BytesIO(b.get('/copy/'+id).content));receipt=json.loads(z.read('confirmation.json'))
    assert receipt['contract_sha256']==digest(z.read('contract.txt'))==sha
    assert receipt['contract_pdf_sha256']==digest(z.read('contract.pdf'))==pdfsha
    assert receipt['ledger_sha256']==digest(z.read('ledger.json'))
    assert receipt['webauthn']['assertion']==good
    assert 'confirmation.json.ots' not in z.namelist()
    r=a.post('/c/'+id+'/attach',data={'csrf':csrf(a.get('/c/'+id))},files={'file':('test.txt',b'example')});assert r.status_code==200
    z=zipfile.ZipFile(io.BytesIO(a.get('/c/'+id+'/export').content));m=json.loads(z.read('manifest.json'));assert all(digest(z.read(k))==v for k,v in m['files'].items())
    def unavailable(*a,**kw):raise FileNotFoundError('test OTS unavailable')
    monkeypatch.setattr('app.subprocess.run',unavailable)
    assert a.post('/c/'+id+'/ots',data={'csrf':csrf(a.get('/c/'+id))}).status_code==503
    assert a.post('/c/'+id+'/bitcoin-verify',data={'csrf':csrf(a.get('/c/'+id))}).status_code==409
