"""Queue regression uses explicitly synthetic fixtures; never claims real mainnet."""
import hashlib,sys,json
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from security_core import Store,init as security_init,verify_audit
from proof_queue import init,seed,enqueue,claim,finish,run_one,expedite,LEASE,RECHECK
from proof_certificate import render_certificate
K=bytes(range(32))
def fixture(tmp_path):
    s=Store(tmp_path,K)
    with s.db() as c:
        security_init(c)
        c.executescript("""CREATE TABLE contracts(id TEXT PRIMARY KEY,receipt BLOB,proof BLOB,btc_verification BLOB,ots_state TEXT);
        CREATE TABLE attachments(id TEXT PRIMARY KEY,contract_id TEXT,data BLOB);
        INSERT INTO contracts VALUES('c',X'616263',NULL,NULL,'none');
        INSERT INTO attachments VALUES('a','c',X'646566');""")
        init(c);enqueue(c,'contract','c','c',b'abc',now=100);enqueue(c,'attachment','a','c',b'def',now=100)
    return s
def report(d,p):
    return {'chain':'bitcoin-mainnet','file_sha256':d.hex(),'proof_sha256':hashlib.sha256(p).hexdigest(),'confirmations_at_verification':6,'height':1,'block_hash':'0'*64,'block_time_utc':'2009-01-01T00:00:00+00:00','verified_at_utc':'2026-01-01T00:00:00+00:00'}
def fail(*a):raise RuntimeError('synthetic failure')
def get(s,kind):
    with s.db() as c:return dict(c.execute('SELECT * FROM proof_jobs WHERE kind=?',(kind,)).fetchone())

def test_retry_pending_and_verify(tmp_path):
    s=fixture(tmp_path)
    assert run_one(s,update=fail,verify=fail,now=100)
    j=get(s,'attachment');assert j['state']=='retry' and j['due']>100 and j['proof'] is None
    assert run_one(s,update=lambda *_:b'pending-proof',verify=fail,now=100)
    j=get(s,'contract');assert j['state']=='pending' and j['proof']==b'pending-proof' and j['report'] is None
    with s.db() as c:expedite(c,'contract','c',101)
    assert run_one(s,update=lambda *_:b'upgraded-proof',verify=report,now=101)
    j=get(s,'contract');assert j['state']=='verified' and j['due']==101+RECHECK
    with s.db() as c:
        assert c.execute('SELECT ots_state FROM contracts').fetchone()[0]=='bitcoin_verified'
        assert verify_audit(c,s.auditkey)[0]==3
        expedite(c,'contract','c',102)
    assert run_one(s,update=fail,verify=fail,now=102)
    j=get(s,'contract');assert j['state']=='pending' and j['report'] is None and j['proof']==b'upgraded-proof'
    with s.db() as c:assert c.execute('SELECT ots_state FROM contracts').fetchone()[0]=='proof_saved_unverified'

def test_lease_reclaim_and_fencing(tmp_path):
    s=fixture(tmp_path);first=claim(s,100);second=claim(s,100)
    assert first['subject']!=second['subject'] and claim(s,101) is None
    recovered=claim(s,100+LEASE);assert recovered['subject']==first['subject'] and recovered['lease']!=first['lease']
    assert not finish(s,first,('pending',b'old',None,None),100+LEASE)
    assert finish(s,recovered,('pending',b'new',None,None),100+LEASE)
    assert get(s,recovered['kind'])['proof']==b'new'

def test_source_changed_and_dedup(tmp_path):
    s=fixture(tmp_path)
    with s.db() as c:
        enqueue(c,'contract','c','c',b'abc',now=100)
        assert c.execute('SELECT count(*) FROM proof_jobs').fetchone()[0]==2
        with pytest.raises(ValueError):enqueue(c,'contract','c','c',b'tampered',now=100)
        c.execute("UPDATE attachments SET data=X'00' WHERE id='a'")
    assert run_one(s,update=fail,verify=fail,now=100)
    assert get(s,'attachment')['state']=='blocked'

def test_seed_legacy_and_certificate(tmp_path):
    s=fixture(tmp_path)
    with s.db() as c:
        c.execute("INSERT INTO contracts VALUES('old',X'616263',X'11',X'22','bitcoin_verified')")
        seed(c)
        assert c.execute("SELECT ots_state FROM contracts WHERE id='old'").fetchone()[0]=='proof_saved_unverified'
        assert c.execute("SELECT proof FROM proof_jobs WHERE subject='old'").fetchone()[0]==b'\x11'
    r=report(hashlib.sha256(b'abc').digest(),b'test-proof')
    assert render_certificate(r,'https://xin.example','测试').startswith(b'%PDF')
    with pytest.raises(ValueError):render_certificate(dict(r,confirmations_at_verification=5),'https://xin.example','测试')
