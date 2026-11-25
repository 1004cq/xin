import os, sqlite3, secrets, hashlib, hmac, json, io, zipfile, tempfile, subprocess, threading, re
from pathlib import Path
from datetime import datetime, timezone, date
from decimal import Decimal, InvalidOperation
from contextlib import contextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from urllib.parse import urlsplit
from datetime import timedelta
from pdf_contract import render_pdf
import proof_queue
from proof_certificate import render_certificate
import time, base64
from fastapi.staticfiles import StaticFiles
from security_core import Store, key, init as init_security, audit as append_audit, verify_audit, SessionMiddleware, Sessions
from starlette.concurrency import run_in_threadpool
from jinja2 import Environment, FileSystemLoader, select_autoescape

DATA=Path(os.environ.get('XIN_DATA','./data')); DATA.mkdir(parents=True,exist_ok=True)
BASE=os.environ.get('XIN_BASE_URL','https://xin.duojiayi.com').rstrip('/')
SECRET=os.environ.get('XIN_SESSION_SECRET','')
PASSWORD_HASH=os.environ.get('XIN_ADMIN_HASH','')
if not re.fullmatch(r'[a-f0-9]{32}:[a-f0-9]{64}',PASSWORD_HASH):
    raise RuntimeError('请设置 XIN_ADMIN_HASH（见 README）')
app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
ORIGIN=BASE; RP_ID=urlsplit(BASE).hostname
DEV=os.environ.get('XIN_DEV')=='1'
if DEV and RP_ID not in ('localhost','127.0.0.1','testserver'): raise RuntimeError('XIN_DEV is restricted to localhost')
if not RP_ID or (not DEV and (urlsplit(BASE).scheme!='https' or urlsplit(BASE).path or urlsplit(BASE).query or urlsplit(BASE).fragment or urlsplit(BASE).username)):
    raise RuntimeError('XIN_BASE_URL must be an HTTPS origin')
app.add_middleware(TrustedHostMiddleware,allowed_hosts=[RP_ID]+(['testserver','localhost','127.0.0.1'] if DEV else []))
STORE=Store(DATA,key('XIN_DATA_KEY'))
app.add_middleware(SessionMiddleware,store=STORE,secure=not DEV)
app.mount('/static',StaticFiles(directory=Path(__file__).parent/'static'),name='static')
env=Environment(loader=FileSystemLoader(Path(__file__).parent/'templates'),autoescape=select_autoescape(['html']))
LOCK=threading.Lock()

def utc(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def digest(b): return hashlib.sha256(b).hexdigest()
def canonical(x): return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')
def pw_hash(p,salt): return hashlib.scrypt(p.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1,dklen=32).hex()
def password_ok(p):
    s,h=PASSWORD_HASH.split(':'); return hmac.compare_digest(pw_hash(p,s),h)
db=STORE.db
def log(c,event,subject='admin'):append_audit(c,STORE.auditkey,event,subject)
with db() as c:
    c.executescript('''CREATE TABLE IF NOT EXISTS contracts(id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, pin_hash TEXT NOT NULL, created TEXT NOT NULL, lender TEXT NOT NULL, borrower TEXT NOT NULL, principal INTEGER NOT NULL, due TEXT NOT NULL, penalty INTEGER NOT NULL, doc BLOB NOT NULL, ledger BLOB NOT NULL, receipt BLOB, proof BLOB, ots_state TEXT NOT NULL DEFAULT 'none', attempts INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS attachments(id TEXT PRIMARY KEY, contract_id TEXT NOT NULL REFERENCES contracts(id), name TEXT NOT NULL, data BLOB NOT NULL, created TEXT NOT NULL); CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY CHECK(id=1), failures INTEGER NOT NULL, since INTEGER NOT NULL); INSERT OR IGNORE INTO login_attempts VALUES(1,0,0);''')

with db() as c:
    init_security(c)
    cols={r['name'] for r in c.execute('PRAGMA table_info(contracts)')}
    for field in ('pdf','btc_verification'):
        if field not in cols: c.execute('ALTER TABLE contracts ADD COLUMN '+field+' BLOB')
    c.execute('''CREATE TABLE IF NOT EXISTS passkey_flow(contract_id TEXT PRIMARY KEY REFERENCES contracts(id), owner TEXT NOT NULL, stage TEXT NOT NULL, challenge BLOB NOT NULL, expires INTEGER NOT NULL, credential_id BLOB, public_key BLOB, sign_count INTEGER, registration BLOB)''')

with db() as c:
    c.executescript('''CREATE TABLE IF NOT EXISTS admin_passkey(id INTEGER PRIMARY KEY CHECK(id=1),credential_id BLOB NOT NULL,public_key BLOB NOT NULL,sign_count INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS admin_challenges(owner TEXT PRIMARY KEY,stage TEXT NOT NULL,challenge BLOB NOT NULL,expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS party_invites(contract_id TEXT NOT NULL REFERENCES contracts(id),role TEXT NOT NULL CHECK(role IN ('lender','borrower')),token_hash TEXT NOT NULL UNIQUE,pin_hash TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,receipt BLOB,PRIMARY KEY(contract_id,role));
    CREATE TABLE IF NOT EXISTS party_flow(contract_id TEXT PRIMARY KEY,owner TEXT NOT NULL,stage TEXT NOT NULL,challenge BLOB NOT NULL,expires INTEGER NOT NULL,credential_id BLOB,public_key BLOB,sign_count INTEGER,registration BLOB);''')
    verify_audit(c,STORE.auditkey)
    proof_queue.init(c); proof_queue.seed(c)

@app.middleware('http')
async def headers(req,call_next):
    if req.headers.get('content-length'):
        try:
            if int(req.headers['content-length'])>11*1024*1024: return Response('文件过大',413)
        except ValueError: return Response('请求无效',400)
    resp=await call_next(req)
    resp.headers.update({'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})
    return resp

def csrf(req):
    if 'csrf' not in req.session: req.session['csrf']=secrets.token_urlsafe(24)
    return req.session['csrf']
def check_csrf(req,f):
    if not hmac.compare_digest(str(f.get('csrf','')),csrf(req)): raise HTTPException(403,'请求校验失败')
def admin(req):
    if not req.session.get('admin'): raise HTTPException(403,'请先登录管理端')
def page(req,view,**kw): return HTMLResponse(env.get_template('index.html').render(view=view,csrf=csrf(req),request_path=req.url.path+'/unlock' if view=='unlock' and not req.url.path.endswith('/unlock') else req.url.path,**kw))
def redirect(url): return RedirectResponse(url,status_code=303)
def get_contract(c,id):
    row=c.execute('SELECT * FROM contracts WHERE id=?',(id,)).fetchone()
    if not row: raise HTTPException(404,'合同不存在')
    return row
def get_token(c,token):
    party=c.execute('SELECT * FROM party_invites WHERE token_hash=?',(digest(token.encode()),)).fetchone()
    if not party: raise HTTPException(404,'邀请无效、已撤销或为旧版本邀请')
    row=get_contract(c,party['contract_id'])
    if row['revoked']: raise HTTPException(404,'邀请已撤销')
    if not party['receipt'] and datetime.now(timezone.utc)-datetime.fromisoformat(row['created'])>timedelta(days=7): raise HTTPException(410,'邀请已过期')
    r=dict(row); role=party['role']
    r.update(role=role,party_name=row[role],party_key=row['id']+'-'+role,receipt=party['receipt'],attempts=party['attempts'],pin_hash=party['pin_hash'])
    return r
def parties(c,id):
    return {p['role']:p['receipt'] for p in c.execute('SELECT role,receipt FROM party_invites WHERE contract_id=?',(id,))}
def consent_for(role):
    return '本人已阅读全文，确认明细及欠款真实准确，自愿确认并承诺履行还款义务。' if role=='borrower' else '本人已阅读全文，确认借款及还款明细、剩余本金及约定条款真实准确，自愿确认。'
def money(s):
    try:
        d=Decimal(str(s)); cents=d*100
        if not d.is_finite() or cents!=cents.to_integral_value() or not 0<=cents<=10000000000: raise ValueError()
        return int(cents)
    except (InvalidOperation,ValueError,OverflowError): raise HTTPException(400,'金额须为非负人民币金额，最多两位小数')
def yuan(c): return f'{Decimal(c)/100:.2f}'
env.filters['yuan']=yuan

def parse_ledger(raw):
    # date, type, amount, note; real dates mandatory, cents only.
    items=[]; total=0
    for line in raw.splitlines():
        if not line.strip(): continue
        parts=line.split(',',3)
        if len(parts)<3: raise HTTPException(400,'明细每行格式：日期,借款或还款,金额,备注')
        try: day=date.fromisoformat(parts[0].strip()).isoformat()
        except ValueError: raise HTTPException(400,'明细日期不正确')
        kind=parts[1].strip(); amount=money(parts[2].strip())
        if kind not in ('借款','还款') or amount<=0: raise HTTPException(400,'明细类型或金额不正确')
        total+=amount if kind=='借款' else -amount
        items.append({'date':day,'type':kind,'amount_cents':amount,'note':parts[3].strip()[:300] if len(parts)>3 else ''})
    if not items or total<=0 or len(items)>500: raise HTTPException(400,'需有有效明细，净欠款必须大于零，最多500笔')
    return items,total

@app.get('/')
def home(req:Request): return redirect('/admin' if req.session.get('admin') else '/login')
@app.get('/login')
def login(req:Request): return page(req,'login')
@app.post('/login')
async def login_post(req:Request):
    import time
    f=await req.form(); check_csrf(req,f); p=str(f.get('password',''))[:1024]; now=int(time.time())
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); a=c.execute('SELECT * FROM login_attempts').fetchone()
        n=a['failures'] if now-a['since']<900 else 0; since=a['since'] if n else now
        if n>=10: return page(req,'login',error='尝试次数过多，请15分钟后重试')
        if not password_ok(p):
            c.execute('UPDATE login_attempts SET failures=?,since=? WHERE id=1',(n+1,since)); log(c,'admin.password_failed'); return page(req,'login',error='密码错误')
        c.execute('UPDATE login_attempts SET failures=0,since=0 WHERE id=1')
    req.session.clear(); req.session.update(_rotate=True,auth_flow=secrets.token_urlsafe(32),auth_until=int(time.time())+300); return redirect('/auth/passkey')
@app.post('/logout')
async def logout(req:Request):
    f=await req.form(); check_csrf(req,f)
    if req.session.get('admin'):
        with db() as c: log(c,'admin.logout')
    req.session.clear(); req.session['_rotate']=True; return redirect('/login')
@app.get('/admin')
def dashboard(req:Request):
    admin(req)
    with db() as c: rows=c.execute('SELECT id,borrower,principal,due,receipt,ots_state,revoked FROM contracts ORDER BY created DESC').fetchall()
    return page(req,'admin',rows=rows)
@app.get('/new')
def new(req:Request): admin(req); return page(req,'new')
@app.post('/new')
async def create(req:Request):
    admin(req); f=await req.form(); check_csrf(req,f)
    lender=str(f.get('lender','')).strip(); borrower=str(f.get('borrower','')).strip()
    if not lender or not borrower or max(len(lender),len(borrower))>80 or any(ord(ch)<32 for ch in lender+borrower): raise HTTPException(400,'请填写真实双方姓名')
    try: due=date.fromisoformat(str(f.get('due',''))).isoformat()
    except ValueError: raise HTTPException(400,'还款日期错误')
    items,total=parse_ledger(str(f.get('ledger',''))); penalty=money(f.get('penalty','0'))
    id=secrets.token_hex(12); token=secrets.token_urlsafe(32); pin=str(secrets.randbelow(90000000)+10000000); created=utc(); ledger=canonical(items)
    lender_token=secrets.token_urlsafe(32); lender_pin=str(secrets.randbelow(90000000)+10000000)
    lines='\n'.join(f"{x['date']} | {x['type']} | ￥{yuan(x['amount_cents'])} | {x['note']}" for x in items)
    doc=(f'多笔借款结算及债务确认书\n编号：{id}\n出借人：{lender}\n借款人：{borrower}\n'
         f'双方应核实历史多笔借款及还款。借款人确认相关款项已实际收到，经结算尚欠借款本金人民币 {yuan(total)} 元。本文件为既有债务确认，不要求再次交付款项。\n'
         f'借款人承诺最迟于 {due}（含当日）足额偿还剩余本金，期限内免息，可提前还款。\n'
         f'逾期约定一次性违约金人民币 {yuan(penalty)} 元，不重复计收、不计入本金；超出法律司法保护范围的部分依法调减。\n'
         '争议由双方协商解决，协商不成依法向有管辖权的人民法院起诉。\n'
         '本文件记录双方各自在线确认，身份真实性及证据效力需结合实际转账、聊天、纸质原件等材料认定。\n'
         f'借款结算明细（人民币）：\n{lines}\n净欠款：￥{yuan(total)}\n明细 SHA-256：{digest(ledger)}\n').encode()
    pdf=render_pdf(doc.decode('utf-8'))
    with db() as c:
        c.execute('INSERT INTO contracts(id,token_hash,pin_hash,created,lender,borrower,principal,due,penalty,doc,ledger,pdf) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(id,digest(secrets.token_bytes(32)),pw_hash(secrets.token_urlsafe(32),id),created,lender,borrower,total,due,penalty,doc,ledger,pdf))
        for role,t,p in [('borrower',token,pin),('lender',lender_token,lender_pin)]:
            c.execute('INSERT INTO party_invites(contract_id,role,token_hash,pin_hash) VALUES(?,?,?,?)',(id,role,digest(t.encode()),pw_hash(p,id)))
        log(c,'contract.create',id)
    return page(req,'invite',id=id,url=BASE+'/s/'+token,pin=pin,lender_url=BASE+'/s/'+lender_token,lender_pin=lender_pin)
@app.get('/c/{id}')
def detail(req:Request,id:str):
    admin(req)
    with db() as c:
        r=get_contract(c,id); attachments=c.execute('SELECT a.id,a.name,a.created,length(a.data) AS size,j.state AS proof_state FROM attachments a LEFT JOIN proof_jobs j ON j.kind=\'attachment\' AND j.subject=a.id WHERE a.contract_id=?',(id,)).fetchall(); job=c.execute("SELECT state,due,failures,report,lease_until FROM proof_jobs WHERE kind='contract' AND subject=?",(id,)).fetchone(); party_status={k:bool(v) for k,v in parties(c,id).items()}
    return page(req,'detail',r=r,doc=bytes(r['doc']).decode(),sha=digest(r['doc']),attachments=attachments,party_status=party_status,job=job,proof_labels=PROOF_LABELS,queue_due=datetime.fromtimestamp(job['due'],timezone.utc).isoformat(timespec='seconds') if job else None)
@app.post('/c/{id}/revoke')
async def revoke(req:Request,id:str):
    admin(req); f=await req.form(); check_csrf(req,f)
    with db() as c:
        if c.execute('UPDATE contracts SET revoked=1 WHERE id=? AND receipt IS NULL AND revoked=0',(id,)).rowcount: log(c,'contract.revoke',id)
    return redirect('/c/'+id)
def unlocked(req,r):
    return req.session.get('unlocked')==r['party_key'] and req.session.get('unlocked_until',0)>int(time.time())

@app.get('/s/{token}')
def sign(req:Request,token:str):
    with db() as c: r=get_token(c,token)
    if r['receipt']: return page(req,'used')
    if not r['pdf']: raise HTTPException(409,'旧版未确认合同请撤销后重新创建')
    if not unlocked(req,r): return page(req,'unlock')
    return page(req,'sign',r=r,doc=bytes(r['doc']).decode(),sha=digest(r['doc']),pdfsha=digest(r['pdf']),role=r['role'],consent=consent_for(r['role']))

@app.post('/s/{token}/unlock')
async def unlock(req:Request,token:str):
    f=await req.form(); check_csrf(req,f)
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); r=get_token(c,token)
        if r['receipt']: raise HTTPException(409)
        if r['attempts']>=8: raise HTTPException(429,'邀请已锁定')
        if not hmac.compare_digest(pw_hash(str(f.get('pin',''))[:32],r['id']),r['pin_hash']):
            c.execute('UPDATE party_invites SET attempts=attempts+1 WHERE contract_id=? AND role=?',(r['id'],r['role'])); log(c,'party.pin_failed',r['party_key'])
            return page(req,'unlock',error='核验码错误')
    req.session['unlocked']=r['party_key']; req.session['unlocked_until']=int(time.time())+600
    return redirect('/s/'+token)

@app.post('/s/{token}')
async def sign_post(req:Request,token:str):
    raise HTTPException(409,'必须完成 Passkey 用户验证，不允许降级签署')

def pdf_response(r):
    if not r['pdf']: raise HTTPException(404,'旧版无锁定 PDF')
    return Response(r['pdf'],media_type='application/pdf',headers={'Content-Disposition':'attachment; filename=contract.pdf'})

@app.get('/c/{id}/pdf')
def admin_pdf(req:Request,id:str):
    admin(req)
    with db() as c: return pdf_response(get_contract(c,id))

@app.get('/s/{token}/pdf')
def invite_pdf(req:Request,token:str):
    with db() as c: r=get_token(c,token)
    if not unlocked(req,r): raise HTTPException(403)
    return pdf_response(r)

def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')
def new_challenge(r,stage):
    return secrets.token_bytes(32)+hashlib.sha256(canonical({'id':r['id'],'contract_sha256':digest(r['doc']),'pdf_sha256':digest(r['pdf']),'ledger_sha256':digest(r['ledger']),'role':r['role'],'typed_name':r['party_name'],'consent':consent_for(r['role']),'stage':stage})).digest()
def get_flow(c,req,r,stage):
    flow=c.execute('SELECT * FROM party_flow WHERE contract_id=?',(r['party_key'],)).fetchone()
    if not flow or flow['stage']!=stage or flow['expires']<int(time.time()) or not hmac.compare_digest(flow['owner'],csrf(req)):
        raise HTTPException(409,'验证已过期或已使用，请重新开始')
    return flow
async def passkey_input(req):
    if req.headers.get('origin')!=ORIGIN: raise HTTPException(403,'Origin 不匹配')
    if 'application/json' not in req.headers.get('content-type',''): raise HTTPException(415)
    body=await req.body()
    if len(body)>65536: raise HTTPException(413)
    try: f=json.loads(body)
    except (ValueError,UnicodeError): raise HTTPException(400)
    if not isinstance(f,dict): raise HTTPException(400)
    check_csrf(req,f)
    return f

@app.post('/s/{token}/passkey/start')
async def pk_start(req:Request,token:str):
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement, ResidentKeyRequirement
    f=await passkey_input(req)
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); r=get_token(c,token)
        if r['receipt'] or not r['pdf'] or not unlocked(req,r): raise HTTPException(403)
        if str(f.get('name','')).strip()!=r['party_name'] or f.get('consent')!='yes' or f.get('sha')!=digest(r['doc']) or f.get('pdfsha')!=digest(r['pdf']): raise HTTPException(400,'姓名、意愿或文书版本不匹配')
        challenge=new_challenge(r,'registration')
        opts=generate_registration_options(rp_id=RP_ID,rp_name='XIN 信',user_id=hashlib.sha256(r['party_key'].encode()).digest(),user_name=r['party_key'],user_display_name='XIN 合同确认 · '+r['role'],challenge=challenge,timeout=120000,authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,user_verification=UserVerificationRequirement.REQUIRED))
        c.execute('INSERT OR REPLACE INTO party_flow(contract_id,owner,stage,challenge,expires) VALUES(?,?,?,?,?)',(r['party_key'],csrf(req),'register',challenge,int(time.time())+180))
    return JSONResponse(json.loads(options_to_json(opts)))

@app.post('/s/{token}/passkey/register')
async def pk_register(req:Request,token:str):
    from webauthn import verify_registration_response,generate_authentication_options,options_to_json
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor,UserVerificationRequirement
    f=await passkey_input(req)
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); r=get_token(c,token)
        if r['receipt'] or not unlocked(req,r): raise HTTPException(403)
        flow=get_flow(c,req,r,'register')
        c.execute("UPDATE party_flow SET stage='consumed' WHERE contract_id=?",(r['party_key'],))
        try:
            v=verify_registration_response(credential=f.get('credential'),expected_challenge=flow['challenge'],expected_rp_id=RP_ID,expected_origin=ORIGIN,require_user_verification=True)
        except Exception:
            return JSONResponse({'detail':'Passkey 注册验证失败，请重新开始'},status_code=400)
        challenge=new_challenge(r,'assertion')
        opts=generate_authentication_options(rp_id=RP_ID,challenge=challenge,timeout=120000,allow_credentials=[PublicKeyCredentialDescriptor(id=v.credential_id)],user_verification=UserVerificationRequirement.REQUIRED)
        registration=canonical({'credential':f['credential'],'expected_challenge':b64(flow['challenge'])})
        c.execute("UPDATE party_flow SET stage='assert',challenge=?,expires=?,credential_id=?,public_key=?,sign_count=?,registration=? WHERE contract_id=?",(challenge,int(time.time())+180,v.credential_id,v.credential_public_key,v.sign_count,registration,r['party_key']))
    return JSONResponse(json.loads(options_to_json(opts)))

@app.post('/s/{token}/passkey/finish')
async def pk_finish(req:Request,token:str):
    from webauthn import verify_authentication_response
    f=await passkey_input(req)
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); r=get_token(c,token)
        if r['receipt'] or not unlocked(req,r): raise HTTPException(403)
        flow=get_flow(c,req,r,'assert')
        c.execute("UPDATE party_flow SET stage='consumed' WHERE contract_id=?",(r['party_key'],))
        try:
            v=verify_authentication_response(credential=f.get('credential'),expected_challenge=flow['challenge'],expected_rp_id=RP_ID,expected_origin=ORIGIN,credential_public_key=flow['public_key'],credential_current_sign_count=flow['sign_count'],require_user_verification=True)
            if not hmac.compare_digest(v.credential_id,flow['credential_id']): raise ValueError('credential mismatch')
        except Exception:
            return JSONResponse({'detail':'Passkey 验证失败，请重新开始'},status_code=400)
        receipt=canonical({'schema':'xin-party-v3','role':r['role'],'contract_id':r['id'],'contract_sha256':digest(r['doc']),'contract_pdf_sha256':digest(r['pdf']),'ledger_sha256':digest(r['ledger']),'typed_name':r['party_name'],'consent':consent_for(r['role']),'method':'invite + separate PIN + typed name + WebAuthn user verification; not verified legal identity or CA signature','server_recorded_utc':utc(),'webauthn':{'rp_id':RP_ID,'origin':ORIGIN,'credential_id':b64(flow['credential_id']),'public_key_cose':b64(flow['public_key']),'registration':json.loads(flow['registration']),'assertion':f['credential'],'expected_challenge':b64(flow['challenge']),'sign_count_before':flow['sign_count'],'sign_count_after':v.new_sign_count}})
        other=parties(c,r['id']).get('lender' if r['role']=='borrower' else 'borrower')
        if other:
            w=json.loads(other)['webauthn']
            if w['credential_id']==b64(flow['credential_id']) or w['public_key_cose']==b64(flow['public_key']):
                return JSONResponse({'detail':'双方必须使用不同凭据'},status_code=409)
        c.execute('UPDATE party_invites SET receipt=? WHERE contract_id=? AND role=? AND receipt IS NULL',(receipt,r['id'],r['role']))
        c.execute('DELETE FROM party_flow WHERE contract_id=?',(r['party_key'],))
        log(c,'party.confirm',r['party_key'])
        ps=parties(c,r['id'])
        if ps.get('lender') and ps.get('borrower'):
            final=canonical({'schema':'xin-confirmation-v3','contract_id':r['id'],'contract_sha256':digest(r['doc']),'contract_pdf_sha256':digest(r['pdf']),'ledger_sha256':digest(r['ledger']),'parties':{k:json.loads(v) for k,v in ps.items()}})
            c.execute('UPDATE contracts SET receipt=? WHERE id=? AND receipt IS NULL',(final,r['id']))
            log(c,'contract.both_confirmed',r['id'])
            proof_queue.enqueue(c,'contract',r['id'],r['id'],final)
    req.session.pop('unlocked',None); req.session.pop('unlocked_until',None); req.session['confirmed']=r['id']; req.session['confirmed_role']=r['role']
    return JSONResponse({'next':'/confirmed/'+r['id']})

@app.get('/confirmed/{id}')
def confirmed(req:Request,id:str):
    if req.session.get('confirmed')!=id: raise HTTPException(403)
    with db() as c:
        r=get_contract(c,id); own=parties(c,id).get(req.session.get('confirmed_role'))
    if not own: raise HTTPException(409)
    return page(req,'signed',id=id,sha=digest(r['receipt'] or own),both=bool(r['receipt']),revoked=bool(r['revoked']))

@app.get('/copy/{id}')
def copy(req:Request,id:str):
    if not req.session.get('admin') and req.session.get('confirmed')!=id: raise HTTPException(403)
    with db() as c:
        r=get_contract(c,id); ps=parties(c,id)
    if not r['receipt'] and not ps.get(req.session.get('confirmed_role')): raise HTTPException(409,'尚未确认')
    if not r['receipt'] and not req.session.get('admin'):ps={req.session['confirmed_role']:ps[req.session['confirmed_role']]}
    return archive(r,[],ps)

def archive(r,attachments,ps=None):
    files={'contract.txt':r['doc'],'ledger.json':r['ledger']}
    if r['pdf']: files['contract.pdf']=r['pdf']
    if r['receipt']: files['confirmation.json']=r['receipt']
    else:
        for role,value in (ps or {}).items():
            if value:files['party-'+role+'.json']=value
    if r['btc_verification']: files['bitcoin-verification.json']=r['btc_verification']
    if r['proof']: files['confirmation.json.ots']=r['proof']
    for a in attachments:
        name='attachments/'+a['id']+'-'+a['name'];files[name]=a['data']
        if a['attachment_proof']:files['attachment-proofs/'+a['id']+'.ots']=a['attachment_proof']
        if a['attachment_report']:files['attachment-proofs/'+a['id']+'.json']=a['attachment_report']
    files['manifest.json']=canonical({'schema':'xin-export-v1','files':{k:digest(v) for k,v in files.items()},'ots_state':r['ots_state'],'note':'confirmation.json and each attachment have separate OTS proofs. An attachment proof timestamps its bytes, not its relationship to the contract. Reports are historical node observations. Manifest itself is not timestamped.'})
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:
        for k,v in files.items(): z.writestr(k,v)
    return Response(b.getvalue(),media_type='application/zip',headers={'Content-Disposition':f'attachment; filename=xin-{r["id"]}.zip'})
@app.get('/c/{id}/export')
def export(req:Request,id:str):
    admin(req)
    with db() as c:
        r=get_contract(c,id); a=c.execute("SELECT a.*,j.proof AS attachment_proof,j.report AS attachment_report,j.state AS proof_state FROM attachments a LEFT JOIN proof_jobs j ON j.kind='attachment' AND j.subject=a.id WHERE a.contract_id=?",(id,)).fetchall(); ps=parties(c,id);log(c,'contract.export',id)
    return archive(r,a,ps)
@app.post('/c/{id}/attach')
async def attach(req:Request,id:str):
    admin(req); f=await req.form(); check_csrf(req,f); file=f.get('file')
    if not hasattr(file,'read'): raise HTTPException(400,'请选择文件')
    data=await file.read(10*1024*1024+1)
    if not data or len(data)>10*1024*1024: raise HTTPException(400,'文件须小于10 MB')
    name=Path(file.filename or 'evidence').name.replace('\\','_'); name=re.sub(r'[^\w.\-]','_',name)[:100] or 'evidence'
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); get_contract(c,id)
        q=c.execute('SELECT count(*) AS n,coalesce(sum(length(data)),0) AS size FROM attachments WHERE contract_id=?',(id,)).fetchone()
        if q['n']>=30 or q['size']+len(data)>50*1024*1024: raise HTTPException(413,'每份合同附件限30个、合计50MB')
        aid=secrets.token_hex(8)
        c.execute('INSERT INTO attachments VALUES(?,?,?,?,?)',(aid,id,name,data,utc())); log(c,'attachment.add',id)
        proof_queue.enqueue(c,'attachment',aid,id,data)
    return redirect('/c/'+id)
PROOF_LABELS={'queued':'已排队','retry':'提交失败，等待重试','pending':'等待主网核验','verified':'曾通过主网核验','blocked':'原文件异常，需人工处理'}
@app.post('/c/{id}/ots')
@app.post('/c/{id}/bitcoin-verify')
async def ots(req:Request,id:str):
    admin(req);f=await req.form();check_csrf(req,f)
    with db() as c:
        r=get_contract(c,id)
        if not r['receipt']:raise HTTPException(409,'先完成双方确认')
        proof_queue.enqueue(c,'contract',id,id,r['receipt'],r['proof'])
        proof_queue.expedite(c,'contract',id)
        log(c,'proof.expedite',id)
    return redirect('/c/'+id)

def certificate(c,kind,subject,contract_id):
    j=c.execute('SELECT * FROM proof_jobs WHERE kind=? AND subject=? AND contract_id=?',(kind,subject,contract_id)).fetchone()
    if not j or j['state']!='verified' or not j['report'] or not j['proof']:raise HTTPException(409,'没有通过核验的存证结果')
    # Check the stored report binds exactly the retained source and proof.
    data=proof_queue.source(c,j)
    r=json.loads(j['report'])
    if digest(data)!=j['file_hash'] or r.get('file_sha256')!=j['file_hash'] or r.get('proof_sha256')!=digest(j['proof']) or r.get('chain')!='bitcoin-mainnet' or r.get('confirmations_at_verification',0)<6:raise HTTPException(409,'存证结果不一致')
    return r

@app.get('/c/{id}/certificate')
def contract_certificate(req:Request,id:str):
    admin(req)
    with db() as c:r=certificate(c,'contract',id,id)
    return Response(render_certificate(r,BASE,'双方确认记录'),media_type='application/pdf',headers={'Content-Disposition':'attachment; filename=xin-proof.pdf'})

@app.get('/c/{id}/attachments/{aid}/certificate')
def attachment_certificate(req:Request,id:str,aid:str):
    admin(req)
    with db() as c:r=certificate(c,'attachment',aid,id)
    return Response(render_certificate(r,BASE,'独立附件'),media_type='application/pdf',headers={'Content-Disposition':'attachment; filename=xin-attachment-proof.pdf'})

@app.get('/verify')
def verify_center(req:Request):
    # No DB lookup, no session creation, no contract identifiers in URL.
    return HTMLResponse(env.get_template('index.html').render(view='verify',node_enabled=os.environ.get('XIN_PUBLIC_NODE_VERIFY')=='1'))

PUBLIC_VERIFY_LOCK=threading.Lock()
PUBLIC_VERIFY_NEXT=0.0
@app.post('/verify/node')
async def public_verify(req:Request):
    global PUBLIC_VERIFY_NEXT
    if os.environ.get('XIN_PUBLIC_NODE_VERIFY')!='1':raise HTTPException(404)
    if req.headers.get('origin')!=ORIGIN or req.headers.get('content-type','').split(';')[0]!='application/json':raise HTTPException(403)
    # One concurrent request and a global cooldown, intentionally opt-in.
    if not PUBLIC_VERIFY_LOCK.acquire(blocking=False):raise HTTPException(429,'核验繁忙')
    try:
        if time.monotonic()<PUBLIC_VERIFY_NEXT:raise HTTPException(429,'请稍后重试')
        PUBLIC_VERIFY_NEXT=time.monotonic()+60
        import anyio
        body=bytearray()
        try:
            with anyio.fail_after(10):
                async for chunk in req.stream():
                    body.extend(chunk)
                    if len(body)>90000:raise HTTPException(413)
        except TimeoutError:raise HTTPException(408,'请求超时')
        try:
            f=json.loads(body)
            if not isinstance(f,dict) or set(f)!={'sha256','proof'} or not re.fullmatch('[0-9a-f]{64}',f['sha256']):raise ValueError()
            proof=base64.b64decode(f['proof'],validate=True)
            if not 0<len(proof)<=65536:raise ValueError()
        except (TypeError,ValueError,KeyError):raise HTTPException(400,'文件指纹或证明格式无效')
        from bitcoin_proof import verify_digest
        try: report=await run_in_threadpool(verify_digest,bytes.fromhex(f['sha256']),proof)
        except Exception:raise HTTPException(422,'未通过主网核验：可能尚未确认、节点不可用或证明不匹配')
        return JSONResponse(report)
    finally:PUBLIC_VERIFY_LOCK.release()

def pending(req):
    owner=req.session.get('auth_flow')
    if not owner or req.session.get('auth_until',0)<=int(time.time()) or req.session.get('admin'):raise HTTPException(403,'请重新输入管理员密码')
    return owner

@app.get('/auth/passkey')
def admin_passkey(req:Request):
    pending(req)
    with db() as c: enroll=not c.execute('SELECT 1 FROM admin_passkey').fetchone()
    return page(req,'admin_mfa',enroll=enroll)

@app.post('/auth/passkey/start')
async def admin_start(req:Request):
    from webauthn import generate_registration_options,generate_authentication_options,options_to_json
    from webauthn.helpers.structs import AuthenticatorSelectionCriteria,UserVerificationRequirement,ResidentKeyRequirement,PublicKeyCredentialDescriptor
    f=await passkey_input(req); owner=pending(req); ch=secrets.token_bytes(32)
    with db() as c:
        c.execute('BEGIN IMMEDIATE');credential=c.execute('SELECT * FROM admin_passkey WHERE id=1').fetchone()
        if credential:
            stage='assert'
            opts=generate_authentication_options(rp_id=RP_ID,challenge=ch,timeout=120000,allow_credentials=[PublicKeyCredentialDescriptor(id=credential['credential_id'])],user_verification=UserVerificationRequirement.REQUIRED)
        else:
            bootstrap=os.environ.get('XIN_ADMIN_ENROLL_TOKEN','')
            if len(bootstrap)<32 or not hmac.compare_digest(bootstrap,str(f.get('bootstrap',''))):
                log(c,'admin.enroll_denied');return JSONResponse({'detail':'必须使用服务器控制台生成的初始化密钥'},status_code=403)
            stage='register'
            opts=generate_registration_options(rp_id=RP_ID,rp_name='XIN 信',user_id=hashlib.sha256(b'xin-admin-v3').digest(),user_name='xin-admin',user_display_name='XIN administrator',challenge=ch,timeout=120000,authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,user_verification=UserVerificationRequirement.REQUIRED))
        c.execute('DELETE FROM admin_challenges WHERE expires<=?',(int(time.time()),))
        c.execute('INSERT OR REPLACE INTO admin_challenges VALUES(?,?,?,?)',(owner,stage,ch,int(time.time())+120))
    return JSONResponse({'stage':stage,'options':json.loads(options_to_json(opts))})

@app.post('/auth/passkey/finish')
async def admin_finish(req:Request):
    from webauthn import verify_registration_response,verify_authentication_response
    f=await passkey_input(req);owner=pending(req)
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        flow=c.execute('SELECT * FROM admin_challenges WHERE owner=? AND expires>?',(owner,int(time.time()))).fetchone()
        if not flow:raise HTTPException(409,'挑战已过期或使用')
        c.execute('DELETE FROM admin_challenges WHERE owner=?',(owner,))
        stored=c.execute('SELECT * FROM admin_passkey WHERE id=1').fetchone()
        try:
            if flow['stage']=='register' and not stored:
                v=verify_registration_response(credential=f.get('credential'),expected_challenge=flow['challenge'],expected_rp_id=RP_ID,expected_origin=ORIGIN,require_user_verification=True)
                c.execute('INSERT INTO admin_passkey VALUES(1,?,?,?)',(v.credential_id,v.credential_public_key,v.sign_count));log(c,'admin.passkey_enrolled')
                req.session.clear();req.session['_rotate']=True
                return JSONResponse({'next':'/login'})
            if flow['stage']!='assert' or not stored:raise ValueError('wrong stage')
            v=verify_authentication_response(credential=f.get('credential'),expected_challenge=flow['challenge'],expected_rp_id=RP_ID,expected_origin=ORIGIN,credential_public_key=stored['public_key'],credential_current_sign_count=stored['sign_count'],require_user_verification=True)
            if not hmac.compare_digest(v.credential_id,stored['credential_id']):raise ValueError('credential mismatch')
            c.execute('UPDATE admin_passkey SET sign_count=? WHERE id=1',(v.new_sign_count,));log(c,'admin.mfa_verified')
        except Exception:
            log(c,'admin.passkey_failed');return JSONResponse({'detail':'验证失败，请重新开始'},status_code=400)
    req.session.clear();req.session.update(admin=True,_rotate=True);return JSONResponse({'next':'/admin'})

@app.post('/admin/revoke-sessions')
async def revoke_sessions(req:Request):
    admin(req);f=await req.form();check_csrf(req,f)
    with db() as c:
        Sessions(STORE).revoke_all(c);c.execute('DELETE FROM admin_challenges');c.execute('DELETE FROM party_flow');log(c,'admin.revoke_all')
    req.session.clear();req.session['_rotate']=True
    return redirect('/login')
