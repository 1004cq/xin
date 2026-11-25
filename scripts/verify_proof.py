"""Run independently on a trusted Bitcoin Core node; verify original bytes, never trust report alone."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from bitcoin_proof import verify_bitcoin
p=argparse.ArgumentParser();p.add_argument('file',type=Path);p.add_argument('proof',type=Path);a=p.parse_args()
if a.file.stat().st_size>50*1024*1024 or a.proof.stat().st_size>1024*1024:raise SystemExit('file too large')
try: print(json.dumps(verify_bitcoin(a.file.read_bytes(),a.proof.read_bytes()),ensure_ascii=False,indent=2))
except Exception as e:raise SystemExit('NOT VERIFIED: '+str(e))
