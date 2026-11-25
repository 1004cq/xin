"""Persistent encrypted proof queue; leased, idempotent jobs; no network in DB transaction."""
import time, secrets, hashlib, json, tempfile, subprocess
from pathlib import Path
from security_core import audit, canonical
from bitcoin_proof import verify_digest
LEASE=600
RECHECK=21600
PENDING=900
MAX_PROOF=1024*1024

def init(c):
    c.execute("""CREATE TABLE IF NOT EXISTS proof_jobs(
        kind TEXT NOT NULL CHECK(kind IN ('contract','attachment')),
        subject TEXT NOT NULL, contract_id TEXT NOT NULL REFERENCES contracts(id),
        file_hash TEXT NOT NULL, proof BLOB, report BLOB,
        state TEXT NOT NULL DEFAULT 'queued', due INTEGER NOT NULL,
        failures INTEGER NOT NULL DEFAULT 0, lease TEXT, lease_until INTEGER,
        last_error TEXT, PRIMARY KEY(kind,subject))""")

def enqueue(c,kind,subject,contract_id,data,proof=None,now=None):
    if kind not in ('contract','attachment') or (kind=='contract' and subject!=contract_id):raise ValueError('invalid job target')
    h=hashlib.sha256(data).hexdigest()
    c.execute('INSERT OR IGNORE INTO proof_jobs(kind,subject,contract_id,file_hash,proof,due) VALUES(?,?,?,?,?,?)',(kind,subject,contract_id,h,proof,int(time.time()) if now is None else now))
    r=c.execute('SELECT file_hash,contract_id FROM proof_jobs WHERE kind=? AND subject=?',(kind,subject)).fetchone()
    if r['file_hash']!=h or r['contract_id']!=contract_id:raise ValueError('immutable source changed')

def seed(c):
    # Startup reconciliation for pre-v0.4 records, including old receipts and attachments.
    for r in c.execute('SELECT id,receipt,proof FROM contracts WHERE receipt IS NOT NULL').fetchall():
        exists=c.execute("SELECT 1 FROM proof_jobs WHERE kind='contract' AND subject=?",(r['id'],)).fetchone()
        enqueue(c,'contract',r['id'],r['id'],r['receipt'],r['proof'])
        if not exists:c.execute("UPDATE contracts SET btc_verification=NULL,ots_state=? WHERE id=?",('proof_saved_unverified' if r['proof'] else 'none',r['id']))
    for a in c.execute('SELECT id,contract_id,data FROM attachments').fetchall():
        enqueue(c,'attachment',a['id'],a['contract_id'],a['data'])

def expedite(c,kind,subject,now=None):
    t=int(time.time()) if now is None else now
    c.execute('UPDATE proof_jobs SET due=min(due,?) WHERE kind=? AND subject=? AND (lease_until IS NULL OR lease_until<=?)',(t,kind,subject,t))

def claim(store,now=None):
    t=int(time.time()) if now is None else now
    with store.db() as c:
        r=c.execute('SELECT * FROM proof_jobs WHERE due<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY due,kind,subject LIMIT 1',(t,t)).fetchone()
        if not r:return None
        lease=secrets.token_hex(24)
        c.execute('UPDATE proof_jobs SET lease=?,lease_until=? WHERE kind=? AND subject=?',(lease,t+LEASE,r['kind'],r['subject']))
        return dict(r)|{'lease':lease,'lease_until':t+LEASE}

def source(c,j):
    if j['kind']=='contract':
        r=c.execute('SELECT receipt AS data FROM contracts WHERE id=?',(j['subject'],)).fetchone()
    else:
        r=c.execute('SELECT data FROM attachments WHERE id=? AND contract_id=?',(j['subject'],j['contract_id'])).fetchone()
    if not r or r['data'] is None:raise ValueError('missing source')
    return r['data']

def ots_update(data,proof):
    # CLI blinds commitments before calendar submission; original bytes stay local.
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp)/'evidence.bin';p.write_bytes(data);q=Path(str(p)+'.ots')
        if proof:q.write_bytes(proof);cmd=['ots','upgrade',str(q)]
        else:cmd=['ots','stamp',str(p)]
        r=subprocess.run(cmd,capture_output=True,timeout=90,check=False)
        if r.returncode!=0 or not q.is_file():
            if proof:return proof
            raise RuntimeError('calendar unavailable')
        if q.stat().st_size>MAX_PROOF:raise ValueError('proof too large')
        return q.read_bytes()

def outcome(data,j,update=ots_update,verify=verify_digest):
    if hashlib.sha256(data).hexdigest()!=j['file_hash']:return ('blocked',j['proof'],None,'source_changed')
    proof=j['proof']
    try:
        if not proof or j['state']!='verified':
            proof=update(data,proof)
        if not proof or len(proof)>MAX_PROOF:raise ValueError('invalid proof')
    except Exception:return ('retry',j['proof'],None,'calendar_unavailable')
    try:
        report=verify(bytes.fromhex(j['file_hash']),proof)
        if (report.get('chain')!='bitcoin-mainnet' or report.get('file_sha256')!=j['file_hash'] or report.get('proof_sha256')!=hashlib.sha256(proof).hexdigest() or report.get('confirmations_at_verification',0)<6):
            raise ValueError('inconsistent verification report')
        return ('verified',proof,canonical(report),None)
    except Exception:return ('pending',proof,None,'mainnet_not_verified')

def finish(store,j,result,now=None):
    t=int(time.time()) if now is None else now
    state,proof,report,error=result
    failures=j['failures']+1 if state in ('retry','pending') else 0
    delay=RECHECK if state=='verified' else min(21600,60*2**min(failures,8)) if state=='retry' else min(21600,PENDING*2**min(max(failures-1,0),4)) if state=='pending' else 365*86400
    with store.db() as c:
        # Lease fencing: a late worker cannot overwrite the newer result.
        r=c.execute('SELECT lease,lease_until FROM proof_jobs WHERE kind=? AND subject=?',(j['kind'],j['subject'])).fetchone()
        if not r or r['lease']!=j['lease'] or r['lease_until']<=t:return False
        try:valid=hashlib.sha256(source(c,j)).hexdigest()==j['file_hash']
        except ValueError:valid=False
        if not valid:state,report,error='blocked',None,'source_changed';delay=365*86400
        c.execute('UPDATE proof_jobs SET state=?,proof=?,report=?,last_error=?,failures=?,due=?,lease=NULL,lease_until=NULL WHERE kind=? AND subject=?',(state,proof,report,error,failures,t+delay,j['kind'],j['subject']))
        if j['kind']=='contract':
            status='bitcoin_verified' if state=='verified' else 'proof_saved_unverified' if proof else 'none'
            c.execute('UPDATE contracts SET proof=?,btc_verification=?,ots_state=? WHERE id=?',(proof,report,status,j['subject']))
        audit(c,store.auditkey,'proof.'+state,j['kind']+':'+j['subject'])
        return True

def run_one(store,update=ots_update,verify=verify_digest,now=None):
    j=claim(store,now)
    if not j:return False
    try:
        with store.db() as c:data=source(c,j)
        result=outcome(data,j,update,verify)
    except Exception:result=('blocked',j['proof'],None,'source_missing')
    finish(store,j,result,now)
    return True
