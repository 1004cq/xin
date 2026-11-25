"""Run on a machine with real OTS calendars and a synced Bitcoin Core node.
No mock; a pending proof is not a successful test. Never use personal data.
"""
import argparse, pathlib, secrets, subprocess, sys, json
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'src'))
from bitcoin_proof import verify_bitcoin
p=argparse.ArgumentParser(); p.add_argument('stage',choices=['stamp','verify']);p.add_argument('file',type=pathlib.Path);a=p.parse_args()
proof=pathlib.Path(str(a.file)+'.ots')
if a.stage=='stamp':
    with a.file.open('xb') as f:f.write(b'XIN synthetic mainnet acceptance '+secrets.token_bytes(32))
    subprocess.run(['ots','stamp',str(a.file)],check=True,timeout=120)
    if not proof.is_file():raise SystemExit('No OTS proof')
    print('Submitted to calendars; NOT verified on chain.')
else:
    if not a.file.is_file() or not proof.is_file():raise SystemExit('Missing original or proof')
    subprocess.run(['ots','upgrade',str(proof)],check=False,timeout=120)
    data=a.file.read_bytes(); stamp=proof.read_bytes()
    result=verify_bitcoin(data,stamp)
    try:verify_bitcoin(data+b'tampered',stamp)
    except ValueError:pass
    else:raise SystemExit('FAIL: tampered file accepted')
    print(json.dumps(result,indent=2));print('PASS: real Bitcoin mainnet verification and tamper rejection')
