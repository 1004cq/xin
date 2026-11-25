import sys,sqlite3
from pathlib import Path
import pytest
from cryptography.exceptions import InvalidTag
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from security_core import Store,init,audit,verify_audit,Sessions,seal,open_seal,MAGIC
K=bytes(range(32));B=bytes(reversed(range(32)))
def fresh(path):
    s=Store(path,K)
    with s.db() as c:init(c);c.execute('CREATE TABLE private_text(x TEXT)');c.execute('INSERT INTO private_text VALUES(?)',('private-contract-unique',));audit(c,s.auditkey,'create','id')
    return s

def test_encryption_and_wrong_key(tmp_path):
    s=fresh(tmp_path);raw=s.path.read_bytes();assert b'private-contract-unique' not in raw and b'SQLite format 3' not in raw
    with s.db() as c:assert c.execute('SELECT x FROM private_text').fetchone()[0]=='private-contract-unique'
    with pytest.raises(InvalidTag):
        with Store(tmp_path,B).db():pass
    assert s.path.read_bytes()==raw
    a=seal(K,MAGIC,b'x');b=seal(K,MAGIC,b'x');assert a!=b
    with pytest.raises(InvalidTag):open_seal(K,MAGIC,a[:-1]+bytes([a[-1]^1]))

def test_rollback_and_audit(tmp_path):
    s=fresh(tmp_path)
    with pytest.raises(RuntimeError):
        with s.db() as c:c.execute('DELETE FROM private_text');raise RuntimeError()
    with s.db() as c:
        assert c.execute('SELECT count(*) FROM private_text').fetchone()[0]==1
        assert verify_audit(c,s.auditkey)[0]==1
        with pytest.raises(sqlite3.IntegrityError):c.execute('DELETE FROM audit_log')
        c.execute('UPDATE audit_head SET seq=0')
        with pytest.raises(ValueError):verify_audit(c,s.auditkey)
        c.rollback()

def test_revoke_rotation_and_stale_write(tmp_path):
    s=fresh(tmp_path);ss=Sessions(s);sid=ss.save('',None,{'pending':True});state,rev=ss.load(sid)
    new=ss.save(sid,rev,{'admin':True},True);assert new!=sid and ss.load(sid)==({},None)
    assert ss.save(sid,rev,state) is None
    state,rev=ss.load(new);assert state['admin']
    with s.db() as c:ss.revoke_all(c)
    assert ss.load(new)==({},None) and ss.save(new,rev,state) is None

def test_encrypted_backup_restore(tmp_path):
    s=fresh(tmp_path/'a');ss=Sessions(s);sid=ss.save('',None,{'admin':True});p=tmp_path/'backup.enc';s.backup(p,B)
    assert b'private-contract-unique' not in p.read_bytes()
    with pytest.raises(FileExistsError):s.backup(p,B)
    dst=Store(tmp_path/'b',K)
    with pytest.raises(InvalidTag):dst.restore(p,K)
    assert not dst.path.exists();dst.restore(p,B)
    with dst.db() as c:assert verify_audit(c,dst.auditkey)[0]==2;assert c.execute('SELECT x FROM private_text').fetchone()[0]=='private-contract-unique'
    assert Sessions(dst).load(sid)==({},None)
    with pytest.raises(FileExistsError):dst.restore(p,B)

def test_legacy_fail_closed(tmp_path):
    (tmp_path/'xin.sqlite3').write_bytes(b'legacy')
    with pytest.raises(RuntimeError):Store(tmp_path,K)
