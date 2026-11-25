"""Single-host encrypted SQLite store. No plaintext database file is written."""
import contextlib, fcntl, hashlib, hmac, json, os, re, secrets, sqlite3, tempfile, time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC=b'XINDB3\0'; BACKUP=b'XINBACKUP3\0'; LIMIT=256*1024*1024

def key(name):
    value=os.environ.get(name,'')
    if not re.fullmatch('[0-9a-fA-F]{64}',value): raise RuntimeError(name+' must contain 32 random bytes in hex')
    return bytes.fromhex(value)
def derive(master,label): return HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'XIN/v3/'+label).derive(master)
def canonical(x): return json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
def seal(k,magic,data):
    if len(data)>LIMIT: raise ValueError('database size limit')
    nonce=secrets.token_bytes(12)
    return magic+nonce+AESGCM(k).encrypt(nonce,data,magic)
def open_seal(k,magic,data):
    if not data.startswith(magic) or not len(magic)+28<=len(data)<=LIMIT+len(magic)+28: raise ValueError('invalid encrypted container')
    n=len(magic);return AESGCM(k).decrypt(data[n:n+12],data[n+12:],magic)
def atomic(path,data,replace=True):
    path=Path(path);fd,tmp=tempfile.mkstemp(prefix='.xin-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f: f.write(data);f.flush();os.fsync(f.fileno())
        if replace: os.replace(tmp,path)
        else: os.link(tmp,path);os.unlink(tmp)
        d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

class Store:
    def __init__(self,root,master):
        self.root=Path(root);self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.path=self.root/'xin-v3.enc'; self.dbkey=derive(master,b'database');self.auditkey=derive(master,b'audit')
        if (self.root/'xin.sqlite3').exists(): raise RuntimeError('legacy plaintext database present; offline migration required')
    @contextlib.contextmanager
    def lock(self):
        fd=os.open(self.root/'.xin.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally: os.close(fd)
    @contextlib.contextmanager
    def db(self):
        with self.lock():
            old=open_seal(self.dbkey,MAGIC,self.path.read_bytes()) if self.path.exists() else None
            c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row
            try:
                if old is not None:c.deserialize(old)
                c.execute('PRAGMA temp_store=MEMORY');c.execute('PRAGMA foreign_keys=ON')
                yield c;c.commit()
                raw=c.serialize()
                if raw!=old:atomic(self.path,seal(self.dbkey,MAGIC,raw))
            except BaseException:c.rollback();raise
            finally:c.close()
    def backup(self,target,backupkey):
        with self.lock():
            raw=open_seal(self.dbkey,MAGIC,self.path.read_bytes())
            atomic(target,seal(derive(backupkey,b'backup'),BACKUP,raw),replace=False)
    def restore(self,source,backupkey):
        # Only into a new, isolated data directory; never overwrite active data.
        with self.lock():
            if self.path.exists():raise FileExistsError('restore into a new data directory')
            raw=open_seal(derive(backupkey,b'backup'),BACKUP,Path(source).read_bytes())
            c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row
            try:
                c.deserialize(raw)
                if c.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('SQLite integrity check failed')
                verify_audit(c,self.auditkey)
                for table in ('server_sessions','admin_challenges','party_flow','passkey_flow'):
                    if c.execute('SELECT 1 FROM sqlite_master WHERE type=? AND name=?',('table',table)).fetchone():c.execute('DELETE FROM '+table)
                audit(c,self.auditkey,'backup.restore','system');c.commit()
                atomic(self.path,seal(self.dbkey,MAGIC,c.serialize()),replace=False)
            finally:c.close()

def init(c):
    c.executescript('''CREATE TABLE IF NOT EXISTS server_sessions(sid TEXT PRIMARY KEY, state BLOB NOT NULL, expires INTEGER NOT NULL, revision INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS audit_log(seq INTEGER PRIMARY KEY,event BLOB NOT NULL,prev TEXT NOT NULL,tag TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_head(id INTEGER PRIMARY KEY CHECK(id=1),seq INTEGER NOT NULL,tag TEXT NOT NULL);
    INSERT OR IGNORE INTO audit_head VALUES(1,0,'');
    CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT,'append only'); END;
    CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT,'append only'); END;''')
def audit(c,k,event,subject):
    head=c.execute('SELECT seq,tag FROM audit_head WHERE id=1').fetchone();seq=head['seq']+1;prev=head['tag']
    data=canonical({'event':event,'subject':subject,'time_ns':time.time_ns()})
    tag=hmac.new(k,canonical([seq,prev,data.hex()]),hashlib.sha256).hexdigest()
    c.execute('INSERT INTO audit_log VALUES(?,?,?,?)',(seq,data,prev,tag));c.execute('UPDATE audit_head SET seq=?,tag=? WHERE id=1',(seq,tag))
def verify_audit(c,k):
    seq=0;prev=''
    for r in c.execute('SELECT * FROM audit_log ORDER BY seq'):
        seq+=1;tag=hmac.new(k,canonical([seq,prev,r['event'].hex()]),hashlib.sha256).hexdigest()
        if r['seq']!=seq or r['prev']!=prev or not hmac.compare_digest(r['tag'],tag):raise ValueError('audit chain mismatch')
        prev=tag
    head=c.execute('SELECT seq,tag FROM audit_head WHERE id=1').fetchone()
    if not head or head['seq']!=seq or head['tag']!=prev:raise ValueError('audit head mismatch')
    return seq,prev

def sid_hash(s):return hashlib.sha256(s.encode()).hexdigest()
class Sessions:
    def __init__(self,store,ttl=3600):self.store=store;self.ttl=ttl
    def load(self,sid):
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}',sid or ''):return {},None
        with self.store.db() as c:
            r=c.execute('SELECT * FROM server_sessions WHERE sid=? AND expires>?',(sid_hash(sid),int(time.time()))).fetchone()
            return (json.loads(r['state']),r['revision']) if r else ({},None)
    def save(self,sid,rev,state,rotate=False):
        # Never resurrect an expired/revoked session, nor overwrite a newer revision.
        with self.store.db() as c:
            now=int(time.time());c.execute('DELETE FROM server_sessions WHERE expires<=?',(now,))
            if rev is not None:
                r=c.execute('SELECT revision FROM server_sessions WHERE sid=?',(sid_hash(sid),)).fetchone()
                if not r or r['revision']!=rev:return None
                if rotate or not state:c.execute('DELETE FROM server_sessions WHERE sid=?',(sid_hash(sid),))
                else:
                    c.execute('UPDATE server_sessions SET state=?,revision=revision+1 WHERE sid=?',(canonical(state),sid_hash(sid)));return sid
            if not state:return ''
            new=secrets.token_urlsafe(32);c.execute('INSERT INTO server_sessions VALUES(?,?,?,0)',(sid_hash(new),canonical(state),now+self.ttl));return new
    def revoke_all(self,c):c.execute('DELETE FROM server_sessions')

class SessionMiddleware:
    def __init__(self,app,store,secure=True):self.app=app;self.sessions=Sessions(store);self.secure=secure
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        from starlette.requests import Request
        from starlette.datastructures import MutableHeaders
        from starlette.concurrency import run_in_threadpool
        cookie='__Host-xin_v3' if self.secure else 'xin_v3'
        sid=Request(scope).cookies.get(cookie,'');state,rev=await run_in_threadpool(self.sessions.load,sid)
        original=canonical(state);scope['session']=state
        async def wrapped(message):
            if message['type']=='http.response.start':
                rotate=bool(state.pop('_rotate',False))
                if rotate or canonical(state)!=original:
                    new=await run_in_threadpool(self.sessions.save,sid,rev,state,rotate)
                    if new is not None:
                        suffix='; Path=/; HttpOnly; SameSite=Strict'+('; Secure' if self.secure else '')
                        value=f'{cookie}={new}'+suffix+('' if new else '; Max-Age=0')
                        MutableHeaders(scope=message).append('set-cookie',value)
            await send(message)
        await self.app(scope,receive,wrapped)
