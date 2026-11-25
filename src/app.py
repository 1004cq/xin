import os, sqlite3, secrets, hashlib, hmac, json, io, zipfile, tempfile, subprocess, threading, re
from pathlib import Path
from datetime import datetime, timezone, date
from decimal import Decimal, InvalidOperation
from contextlib import contextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.concurrency import run_in_threadpool
from jinja2 import Environment, FileSystemLoader, select_autoescape

DATA=Path(os.environ.get('XIN_DATA','./data')); DATA.mkdir(parents=True,exist_ok=True)
BASE=os.environ.get('XIN_BASE_URL','https://xin.duojiayi.com').rstrip('/')
SECRET=os.environ.get('XIN_SESSION_SECRET','')
PASSWORD_HASH=os.environ.get('XIN_ADMIN_HASH','')
if len(SECRET)<32 or not re.fullmatch(r'[a-f0-9]{32}:[a-f0-9]{64}',PASSWORD_HASH):
    raise RuntimeError('请设置 XIN_SESSION_SECRET 和 XIN_ADMIN_HASH（见 README）')
app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
app.add_middleware(SessionMiddleware,secret_key=SECRET,https_only=not (os.environ.get('XIN_DEV')=='1'),same_site='strict',max_age=3600,session_cookie='xin_session')
app.mount('/static',StaticFiles(directory=Path(__file__).parent/'static'),name='static')
env=Environment(loader=FileSystemLoader(Path(__file__).parent/'templates'),autoescape=select_autoescape(['html']))
LOCK=threading.Lock()

def utc(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def digest(b): return hashlib.sha256(b).hexdigest()
def canonical(x): return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')
def pw_hash(p,salt): return hashlib.scrypt(p.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1,dklen=32).hex()
def password_ok(p):
    s,h=PASSWORD_HASH.split(':'); return hmac.compare_digest(pw_hash(p,s),h)
@contextmanager
def db():
    c=sqlite3.connect(DATA/'xin.sqlite3',timeout=15); c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    try:
        yield c; c.commit()
    except BaseException:
        c.rollback(); raise
    finally: c.close()
with db() as c:
    c.executescript('''CREATE TABLE IF NOT EXISTS contracts(id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, pin_hash TEXT NOT NULL, created TEXT NOT NULL, lender TEXT NOT NULL, borrower TEXT NOT NULL, principal INTEGER NOT NULL, due TEXT NOT NULL, penalty INTEGER NOT NULL, doc BLOB NOT NULL, ledger BLOB NOT NULL, receipt BLOB, proof BLOB, ots_state TEXT NOT NULL DEFAULT 'none', attempts INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS attachments(id TEXT PRIMARY KEY, contract_id TEXT NOT NULL REFERENCES contracts(id), name TEXT NOT NULL, data BLOB NOT NULL, created TEXT NOT NULL); CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY CHECK(id=1), failures INTEGER NOT NULL, since INTEGER NOT NULL); INSERT OR IGNORE INTO login_attempts VALUES(1,0,0);''')

@app.middleware('http')
async def headers(req,call_next):
    if req.headers.get('content-length'):
        try:
            if int(req.headers['content-length'])>11*1024*1024: return Response('文件过大',413)
        except ValueError: return Response('请求无效',400)
    resp=await call_next(req)
    resp.headers.update({'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})
    return resp

def csrf(req):
    if 'csrf' not in req.session: req.session['csrf']=secrets.token_urlsafe(24)
    return req.session['csrf']
def check_csrf(req,f):
    if not hmac.compare_digest(str(f.get('csrf','')),csrf(req)): raise HTTPException(403,'请求校验失败')
def admin(req):
    if not req.session.get('admin'): raise HTTPException(403,'请先登录管理端')
def page(req,view,**kw): return HTMLResponse(env.get_template('index.html').render(view=view,csrf=csrf(req),**kw))
def redirect(url): return RedirectResponse(url,status_code=303)
def get_contract(c,id):
    row=c.execute('SELECT * FROM contracts WHERE id=?',(id,)).fetchone()
    if not row: raise HTTPException(404,'合同不存在')
    return row
def get_token(c,token):
    row=c.execute('SELECT * FROM contracts WHERE token_hash=?',(digest(token.encode()),)).fetchone()
    if not row or row['revoked']: raise HTTPException(404,'邀请无效或已撤销')
    return row

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
            c.execute('UPDATE login_attempts SET failures=?,since=? WHERE id=1',(n+1,since)); return page(req,'login',error='密码错误')
        c.execute('UPDATE login_attempts SET failures=0,since=0 WHERE id=1')
    req.session.clear(); req.session['admin']=True; return redirect('/admin')
@app.post('/logout')
async def logout(req:Request):
    f=await req.form(); check_csrf(req,f); req.session.clear(); return redirect('/login')
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
    if not lender or not borrower or max(len(lender),len(borrower))>80: raise HTTPException(400,'请填写真实双方姓名')
    try: due=date.fromisoformat(str(f.get('due',''))).isoformat()
    except ValueError: raise HTTPException(400,'还款日期错误')
    items,total=parse_ledger(str(f.get('ledger',''))); penalty=money(f.get('penalty','0'))
    id=secrets.token_hex(12); token=secrets.token_urlsafe(32); pin=str(secrets.randbelow(90000000)+10000000); created=utc(); ledger=canonical(items)
    lines='\n'.join(f"{x['date']} | {x['type']} | ￥{yuan(x['amount_cents'])} | {x['note']}" for x in items)
    doc=(f'多笔借款结算及债务确认书\n编号：{id}\n出借人：{lender}\n借款人：{borrower}\n'
         f'双方应核实历史多笔借款及还款。借款人确认相关款项已实际收到，经结算尚欠借款本金人民币 {yuan(total)} 元。本文件为既有债务确认，不要求再次交付款项。\n'
         f'借款人承诺最迟于 {due}（含当日）足额偿还剩余本金，期限内免息，可提前还款。\n'
         f'逾期约定一次性违约金人民币 {yuan(penalty)} 元，不重复计收、不计入本金；超出法律司法保护范围的部分依法调减。\n'
         '争议由双方协商解决，协商不成依法向有管辖权的人民法院起诉。\n'
         '本文件仅记录借款人在线确认，身份真实性及证据效力需结合实际转账、聊天、纸质原件等材料认定。\n'
         f'借款结算明细（人民币）：\n{lines}\n净欠款：￥{yuan(total)}\n明细 SHA-256：{digest(ledger)}\n').encode()
    with db() as c: c.execute('INSERT INTO contracts(id,token_hash,pin_hash,created,lender,borrower,principal,due,penalty,doc,ledger) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(id,digest(token.encode()),pw_hash(pin,id[:32]),created,lender,borrower,total,due,penalty,doc,ledger))
    return page(req,'invite',id=id,url=BASE+'/s/'+token,pin=pin)
@app.get('/c/{id}')
def detail(req:Request,id:str):
    admin(req)
    with db() as c:
        r=get_contract(c,id); attachments=c.execute('SELECT id,name,created,length(data) AS size FROM attachments WHERE contract_id=?',(id,)).fetchall()
    return page(req,'detail',r=r,doc=bytes(r['doc']).decode(),sha=digest(r['doc']),attachments=attachments)
@app.post('/c/{id}/revoke')
async def revoke(req:Request,id:str):
    admin(req); f=await req.form(); check_csrf(req,f)
    with db() as c: c.execute('UPDATE contracts SET revoked=1 WHERE id=? AND receipt IS NULL',(id,))
    return redirect('/c/'+id)
@app.get('/s/{token}')
def sign(req:Request,token:str):
    with db() as c: r=get_token(c,token)
    if r['receipt']: return page(req,'used')
    return page(req,'sign',r=r,doc=bytes(r['doc']).decode(),sha=digest(r['doc']))
@app.post('/s/{token}')
async def sign_post(req:Request,token:str):
    f=await req.form(); check_csrf(req,f)
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); r=get_token(c,token)
        if r['receipt']: raise HTTPException(409,'已确认，不可重复签署')
        if r['attempts']>=8: raise HTTPException(429,'邀请已锁定，请联系出借人重新创建')
        pin=str(f.get('pin',''))[:32]
        if not hmac.compare_digest(pw_hash(pin,r['id'][:32]),r['pin_hash']):
            c.execute('UPDATE contracts SET attempts=attempts+1 WHERE id=?',(r['id'],)); return page(req,'sign',r=r,doc=bytes(r['doc']).decode(),sha=digest(r['doc']),error='核验码错误')
        if str(f.get('name','')).strip()!=r['borrower'] or f.get('consent')!='yes' or f.get('sha')!=digest(r['doc']): raise HTTPException(400,'姓名、确认意愿或合同版本不匹配')
        receipt=canonical({'schema':'xin-confirmation-v1','contract_id':r['id'],'contract_sha256':digest(r['doc']),'ledger_sha256':digest(r['ledger']),'typed_name':r['borrower'],'consent':'本人已阅读全文，确认明细及欠款真实准确，自愿确认并承诺履行还款义务。','method':'one-time invite + separate PIN + typed name; not verified identity or CA signature','server_recorded_utc':utc()})
        c.execute('UPDATE contracts SET receipt=? WHERE id=?',(receipt,r['id']))
    req.session['confirmed']=r['id']; return page(req,'signed',id=r['id'],sha=digest(receipt))
@app.get('/copy/{id}')
def copy(req:Request,id:str):
    if not req.session.get('admin') and req.session.get('confirmed')!=id: raise HTTPException(403)
    with db() as c: r=get_contract(c,id)
    if not r['receipt']: raise HTTPException(409,'尚未确认')
    return archive(r,[])

def archive(r,attachments):
    files={'contract.txt':r['doc'],'ledger.json':r['ledger']}
    if r['receipt']: files['confirmation.json']=r['receipt']
    if r['proof']: files['confirmation.json.ots']=r['proof']
    for a in attachments: files['attachments/'+a['id']+'-'+a['name']]=a['data']
    files['manifest.json']=canonical({'schema':'xin-export-v1','files':{k:digest(v) for k,v in files.items()},'ots_state':r['ots_state'],'note':'Only confirmation.json is submitted to OTS; its hashes bind contract and ledger. Attachments added later are not covered. Manifest itself is not timestamped.'})
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:
        for k,v in files.items(): z.writestr(k,v)
    return Response(b.getvalue(),media_type='application/zip',headers={'Content-Disposition':f'attachment; filename=xin-{r["id"]}.zip'})
@app.get('/c/{id}/export')
def export(req:Request,id:str):
    admin(req)
    with db() as c: r=get_contract(c,id); a=c.execute('SELECT * FROM attachments WHERE contract_id=?',(id,)).fetchall()
    return archive(r,a)
@app.post('/c/{id}/attach')
async def attach(req:Request,id:str):
    admin(req); f=await req.form(); check_csrf(req,f); file=f.get('file')
    if not hasattr(file,'read'): raise HTTPException(400,'请选择文件')
    data=await file.read(10*1024*1024+1)
    if not data or len(data)>10*1024*1024: raise HTTPException(400,'文件须小于10 MB')
    name=Path(file.filename or 'evidence').name.replace('\\','_'); name=re.sub(r'[^\w.\-]','_',name)[:100] or 'evidence'
    with db() as c:
        get_contract(c,id); c.execute('INSERT INTO attachments VALUES(?,?,?,?,?)',(secrets.token_hex(8),id,name,data,utc()))
    return redirect('/c/'+id)
@app.post('/c/{id}/ots')
async def ots(req:Request,id:str):
    admin(req); f=await req.form(); check_csrf(req,f)
    await run_in_threadpool(stamp_record,id)
    return redirect('/c/'+id)

def stamp_record(id):
    with LOCK:
        with db() as c: r=get_contract(c,id)
        if not r['receipt']: raise HTTPException(409,'先完成确认')
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'confirmation.json'; p.write_bytes(r['receipt']); proof=Path(str(p)+'.ots')
            if r['proof']: proof.write_bytes(r['proof']); cmd=['ots','upgrade',str(proof)]
            else: cmd=['ots','stamp',str(p)]
            try: result=subprocess.run(cmd,capture_output=True,timeout=90,check=False)
            except (OSError,subprocess.TimeoutExpired): raise HTTPException(503,'OTS 不可用或超时，未标记成功')
            if result.returncode!=0 or not proof.exists(): raise HTTPException(502,'OTS 请求失败，未标记成功')
            with db() as c: c.execute('UPDATE contracts SET proof=?,ots_state=? WHERE id=?',(proof.read_bytes(),'proof_saved_unverified',id))
