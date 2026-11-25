import os,sys,tempfile,hashlib,re,json,io,zipfile,base64,struct
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from fastapi.testclient import TestClient
T=tempfile.TemporaryDirectory()
salt='ab'*16
ORIGIN='http://localhost:8000'
os.environ.update(XIN_BASE_URL=ORIGIN,XIN_DATA=T.name,XIN_DEV='1',XIN_DATA_KEY='12'*32,XIN_ADMIN_ENROLL_TOKEN='test-only-bootstrap-token-123456789',XIN_SESSION_SECRET='test-only-secret-not-for-production-123456',XIN_ADMIN_HASH=salt+':'+hashlib.scrypt(b'test-password',salt=bytes.fromhex(salt),n=16384,r=8,p=1,dklen=32).hex())
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
def assertion(key,cid,ch,uv=True,origin=ORIGIN,count=1):
    cd=client_data('webauthn.get',ch,origin)
    auth=hashlib.sha256(b'localhost').digest()+bytes([5 if uv else 1])+struct.pack('>I',count)
    sig=key.sign(auth+hashlib.sha256(cd).digest(),ec.ECDSA(hashes.SHA256()))
    return {'id':b64(cid),'rawId':b64(cid),'type':'public-key','response':{'clientDataJSON':b64(cd),'authenticatorData':b64(auth),'signature':b64(sig)},'clientExtensionResults':{}}

def test_flow(monkeypatch,tmp_path):
    a,b,l,outsider=TestClient(app),TestClient(app),TestClient(app),TestClient(app)
    headers={'Origin':ORIGIN}
    assert outsider.get('/admin').status_code==403
    assert a.post('/login',data={'password':'test-password'}).status_code==403
    def password():
        r=a.post('/login',data={'csrf':csrf(a.get('/login')),'password':'test-password'})
        assert r.status_code==200,r.text
        assert a.get('/admin').status_code==403
        return csrf(r)
    admin_key=ec.generate_private_key(ec.SECP256R1());admin_id=b'admin-credential'
    c=password()
    assert a.post('/auth/passkey/start',json={'csrf':c,'bootstrap':'incorrect'},headers=headers).status_code==403
    reg=a.post('/auth/passkey/start',json={'csrf':c,'bootstrap':os.environ['XIN_ADMIN_ENROLL_TOKEN']},headers=headers)
    assert reg.status_code==200,reg.text
    assert reg.json()['stage']=='register'
    data={'csrf':c,'credential':registration(admin_key,admin_id,reg.json()['options']['challenge'])}
    assert a.post('/auth/passkey/finish',json=data,headers=headers).json()['next']=='/login'
    assert a.get('/admin').status_code==403
    c=password()
    reg=a.post('/auth/passkey/start',json={'csrf':c},headers=headers)
    assert reg.json()['stage']=='assert'
    data={'csrf':c,'credential':assertion(admin_key,admin_id,reg.json()['options']['challenge'])}
    assert a.post('/auth/passkey/finish',json=data,headers=headers).json()['next']=='/admin'
    assert a.get('/admin').status_code==200
    r=a.post('/new',data={'csrf':csrf(a.get('/new')),'lender':'测试甲','borrower':'测试乙','due':'2028-12-31','penalty':'100','ledger':'2026-01-01,借款,100.10,测试\n2026-01-02,借款,200.20\n2026-02-01,还款,50.05'})
    assert r.status_code==200,r.text
    tokens=re.findall(r'/s/([\w-]+)',r.text);pins=re.findall(r'value="(\d{8})"',r.text);id=re.search(r'/c/([a-f0-9]+)',r.text).group(1)
    assert len(tokens)==len(pins)==2 and tokens[0]!=tokens[1]
    assert outsider.get('/c/'+id+'/export').status_code==403
    assert outsider.get('/s/'+tokens[0]+'/pdf').status_code==403
    def sign_party(client,token,pin,name,check=False):
        path='/s/'+token
        assert '250.25' not in client.get(path).text
        if check:assert '核验码错误' in client.post(path+'/unlock',data={'csrf':csrf(client.get(path)),'pin':'wrong'}).text
        s=client.post(path+'/unlock',data={'csrf':csrf(client.get(path)),'pin':pin});assert '250.25' in s.text
        pdf=client.get(path+'/pdf');assert pdf.content.startswith(b'%PDF')
        sha=re.search(r'name="sha" value="([a-f0-9]+)"',s.text).group(1)
        pdfsha=re.search(r'name="pdfsha" value="([a-f0-9]+)"',s.text).group(1)
        assert pdfsha==digest(pdf.content)
        form={'csrf':csrf(s),'name':name,'consent':'yes','sha':sha,'pdfsha':pdfsha}
        assert client.post(path,data=form).status_code==409
        assert client.post(path+'/passkey/start',json=form,headers={'Origin':'https://evil.example'}).status_code==403
        assert client.post(path+'/passkey/start',json=dict(form,pdfsha='bad'),headers=headers).status_code==400
        k=ec.generate_private_key(ec.SECP256R1());cid=os.urandom(32)
        def begin():
            x=client.post(path+'/passkey/start',json=form,headers=headers);assert x.status_code==200,x.text
            x=client.post(path+'/passkey/register',json={'csrf':form['csrf'],'credential':registration(k,cid,x.json()['challenge'])},headers=headers);assert x.status_code==200,x.text
            return x.json()['challenge']
        ch=begin()
        if check:
            bad=assertion(k,cid,ch,uv=False)
            assert client.post(path+'/passkey/finish',json={'csrf':form['csrf'],'credential':bad},headers=headers).status_code==400
            assert client.post(path+'/passkey/finish',json={'csrf':form['csrf'],'credential':assertion(k,cid,ch)},headers=headers).status_code==409
            ch=begin()
        data={'csrf':form['csrf'],'credential':assertion(k,cid,ch)}
        assert client.post(path+'/passkey/finish',json=data,headers=headers).status_code==200
        assert client.post(path+'/passkey/finish',json=data,headers=headers).status_code==403
    sign_party(b,tokens[0],pins[0],'测试乙',True)
    assert outsider.get('/copy/'+id).status_code==403
    z=zipfile.ZipFile(io.BytesIO(b.get('/copy/'+id).content))
    assert 'party-borrower.json' in z.namelist() and 'confirmation.json' not in z.namelist()
    assert a.post('/c/'+id+'/ots',data={'csrf':csrf(a.get('/c/'+id))}).status_code==409
    sign_party(l,tokens[1],pins[1],'测试甲')
    raw=b.get('/copy/'+id).content
    z=zipfile.ZipFile(io.BytesIO(raw));receipt=json.loads(z.read('confirmation.json'))
    assert receipt['schema']=='xin-confirmation-v3' and set(receipt['parties'])=={'lender','borrower'}
    assert receipt['contract_sha256']==digest(z.read('contract.txt'))
    assert receipt['contract_pdf_sha256']==digest(z.read('contract.pdf'))
    assert receipt['ledger_sha256']==digest(z.read('ledger.json'))
    import importlib.util
    spec=importlib.util.spec_from_file_location('offline_verify',Path(__file__).resolve().parents[1]/'verify.py')
    verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
    f=tmp_path/'receipt.zip';f.write_bytes(raw)
    assert '双方' in verifier.verify_archive(f)
    r=a.post('/c/'+id+'/attach',data={'csrf':csrf(a.get('/c/'+id))},files={'file':('test.txt',b'example')});assert r.status_code==200
    z=zipfile.ZipFile(io.BytesIO(a.get('/c/'+id+'/export').content));m=json.loads(z.read('manifest.json'));assert all(digest(z.read(k))==v for k,v in m['files'].items())
    from app import STORE
    from proof_queue import run_one
    with STORE.db() as c:
        jobs=c.execute('SELECT * FROM proof_jobs WHERE contract_id=?',(id,)).fetchall()
        assert {j['kind'] for j in jobs}=={'contract','attachment'}
        aid=next(j['subject'] for j in jobs if j['kind']=='attachment')
    assert outsider.get('/verify').status_code==200
    assert outsider.get('/verify').headers.get('set-cookie') is None
    monkeypatch.delenv('XIN_PUBLIC_NODE_VERIFY',raising=False)
    assert outsider.post('/verify/node',json={}).status_code==404
    assert outsider.get('/c/'+id+'/certificate').status_code==403
    assert a.get('/c/'+id+'/certificate').status_code==409
    assert a.post('/c/'+id+'/ots',data={'csrf':csrf(a.get('/c/'+id))}).status_code==200
    assert a.post('/c/'+id+'/bitcoin-verify',data={'csrf':csrf(a.get('/c/'+id))}).status_code==200
    assert run_one(STORE,update=lambda *_:b'test-proof',verify=lambda *_: (_ for _ in ()).throw(ValueError('not verified')))
    assert a.get('/c/'+id+'/certificate').status_code==409
    assert a.get('/c/'+id+'/attachments/'+aid+'/certificate').status_code==409
    assert a.post('/admin/revoke-sessions',data={'csrf':csrf(a.get('/admin'))}).status_code==200
    assert a.get('/admin').status_code==403 and b.get('/copy/'+id).status_code==403 and l.get('/copy/'+id).status_code==403
