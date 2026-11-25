"""Offline migration/recovery/backup operations. Run as trusted local operator."""
import argparse, getpass, os, sqlite3, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from security_core import Store,key,init,audit,verify_audit,seal,atomic,MAGIC
p=argparse.ArgumentParser();p.add_argument('action',choices=['backup','restore','migrate','audit','reset-admin']);p.add_argument('--data',default=os.environ.get('XIN_DATA','./data'));p.add_argument('--file');a=p.parse_args()
master=key('XIN_DATA_KEY');store=Store(a.data,master)
if a.action in ('backup','restore'):
    if not a.file:p.error('--file required')
    text=getpass.getpass('Independent backup key (64 hex characters): ')
    if len(text)!=64:raise SystemExit('invalid backup key')
    bk=bytes.fromhex(text)
    if len(bk)!=32 or bk==master:raise SystemExit('backup key must be independent')
    if a.action=='backup':store.backup(Path(a.file),bk)
    else:store.restore(Path(a.file),bk)
elif a.action=='migrate':
    if not a.file:p.error('--file points to stopped legacy SQLite database in another directory')
    source=Path(a.file).resolve()
    if not source.is_file():raise SystemExit('source does not exist')
    with store.lock():
        if store.path.exists():raise SystemExit('target already exists')
        old=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True);c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row
        try:
            old.backup(c)
            if c.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('legacy integrity failed')
            if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='contracts'").fetchone():raise ValueError('not an XIN database')
            init(c);c.execute('UPDATE contracts SET revoked=1 WHERE receipt IS NULL')
            if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='passkey_flow'").fetchone():c.execute('DELETE FROM passkey_flow')
            audit(c,store.auditkey,'legacy.migrate','system');c.commit()
            atomic(store.path,seal(store.dbkey,MAGIC,c.serialize()),replace=False)
        finally:old.close();c.close()
elif a.action=='audit':
    with store.db() as c:print(verify_audit(c,store.auditkey))
else:
    if input('Type RESET ADMIN (offline only): ')!='RESET ADMIN':raise SystemExit('cancelled')
    with store.db() as c:
        c.execute('DELETE FROM admin_passkey');c.execute('DELETE FROM admin_challenges');c.execute('DELETE FROM server_sessions');c.execute('DELETE FROM party_flow');audit(c,store.auditkey,'admin.offline_reset','system')
print('OK. Keep keys and legacy originals protected. Never expose backup paths.')
