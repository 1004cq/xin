"""Independent verification against a trusted, synced Bitcoin Core mainnet node.
No external block explorer and no fabricated confirmation status.
"""
import os, io, json, base64, hashlib
from datetime import datetime, timezone
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError('RPC redirects forbidden')

def rpc(method,*params):
    url=os.environ.get('XIN_BITCOIN_RPC_URL','')
    p=urlsplit(url)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password: raise ValueError('Configure private Bitcoin Core RPC URL')
    user=os.environ.get('XIN_BITCOIN_RPC_USER',''); password=os.environ.get('XIN_BITCOIN_RPC_PASSWORD','')
    if not user or not password: raise ValueError('RPC credentials required')
    auth=base64.b64encode((user+':'+password).encode()).decode()
    payload=json.dumps({'jsonrpc':'1.0','id':'xin','method':method,'params':list(params)}).encode()
    request=Request(url,data=payload,headers={'Content-Type':'application/json','Authorization':'Basic '+auth})
    with build_opener(ProxyHandler({}),NoRedirect()).open(request,timeout=10) as r:
        response=json.loads(r.read(1024*1024))
    if response.get('error') or response.get('id')!='xin': raise ValueError('RPC error')
    return response['result']

def verify_bitcoin(data,proof):
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpSHA256
    from bitcoin.core import CBlockHeader
    if len(proof)>1024*1024: raise ValueError('oversized proof')
    detached=DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(proof)))
    expected=hashlib.sha256(data).digest()
    if not isinstance(detached.file_hash_op,OpSHA256) or detached.file_digest!=expected: raise ValueError('file hash mismatch')
    info=rpc('getblockchaininfo')
    if info.get('chain')!='main' or info.get('initialblockdownload') is not False: raise ValueError('mainnet node must be synced')
    for msg,att in detached.timestamp.all_attestations():
        if not isinstance(att,BitcoinBlockHeaderAttestation): continue
        if not 0<=att.height<=info['blocks']-5: continue
        bh=rpc('getblockhash',att.height)
        meta=rpc('getblockheader',bh,True)
        if meta.get('confirmations',0)<6 or meta.get('height')!=att.height: continue
        raw=bytes.fromhex(rpc('getblockheader',bh,False))
        if len(raw)!=80 or hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()!=bh: continue
        try: ts=att.verify_against_blockheader(msg,CBlockHeader.deserialize(raw))
        except Exception: continue
        if rpc('getblockhash',att.height)!=bh: continue
        return {'schema':'xin-bitcoin-verification-v1','chain':'bitcoin-mainnet','height':att.height,'block_hash':bh,'confirmations_at_verification':meta['confirmations'],'block_time_utc':datetime.fromtimestamp(ts,timezone.utc).isoformat(),'verified_at_utc':datetime.now(timezone.utc).isoformat(),'file_sha256':expected.hex(),'proof_sha256':hashlib.sha256(proof).hexdigest(),'note':'Validated against operator-configured Bitcoin Core; repeat independently. Block time is not exact signing time.'}
    raise ValueError('no verified mainnet attestation with six confirmations')
