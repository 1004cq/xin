"""Verify internal archive consistency and v2 cryptographic WebAuthn assertions.
A receipt can still be fabricated by an operator; verify its OTS separately.
"""
import hashlib,json,zipfile,sys,base64,hmac
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def unb(s):return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
def require(ok,msg):
    if not ok:raise ValueError(msg)
def verify_archive(path):
    with zipfile.ZipFile(path) as z:
        require(len(z.namelist())<=100 and sum(i.file_size for i in z.infolist())<=100*1024*1024,'归档过大')
        require(len(set(z.namelist()))==len(z.namelist()),'重复路径')
        m=json.loads(z.read('manifest.json'))
        require(set(z.namelist())==set(m['files'])|{'manifest.json'},'文件清单不一致')
        for name,h in m['files'].items():require(sha(z.read(name))==h,'哈希不符 '+name)
        if 'confirmation.json' not in z.namelist():return '未确认；仅归档内部一致'
        r=json.loads(z.read('confirmation.json'))
        require(r['contract_sha256']==sha(z.read('contract.txt')),'合同不匹配')
        require(r['ledger_sha256']==sha(z.read('ledger.json')),'明细不匹配')
        if r.get('schema')=='xin-confirmation-v2':
            from webauthn import verify_registration_response,verify_authentication_response
            require(r['contract_pdf_sha256']==sha(z.read('contract.pdf')),'PDF 不匹配')
            w=r['webauthn']; reg=w['registration']
            def check_binding(encoded,stage):
                ch=unb(encoded)
                h=hashlib.sha256(canonical({'id':r['contract_id'],'contract_sha256':r['contract_sha256'],'pdf_sha256':r['contract_pdf_sha256'],'ledger_sha256':r['ledger_sha256'],'stage':stage})).digest()
                require(len(ch)==64 and hmac.compare_digest(ch[32:],h),'挑战未绑定文书')
                return ch
            v=verify_registration_response(credential=reg['credential'],expected_challenge=check_binding(reg['expected_challenge'],'registration'),expected_origin=w['origin'],expected_rp_id=w['rp_id'],require_user_verification=True)
            require(v.credential_id==unb(w['credential_id']) and v.credential_public_key==unb(w['public_key_cose']) and v.sign_count==w['sign_count_before'],'注册公钥/计数不一致')
            a=verify_authentication_response(credential=w['assertion'],expected_challenge=check_binding(w['expected_challenge'],'assertion'),expected_origin=w['origin'],expected_rp_id=w['rp_id'],credential_public_key=v.credential_public_key,credential_current_sign_count=v.sign_count,require_user_verification=True)
            require(a.credential_id==v.credential_id and a.new_sign_count==w['sign_count_after'],'认证凭据/计数不一致')
            return '归档、PDF 与 WebAuthn 密码学验证通过；未验证法定身份或区块链'
        return 'v1 归档内部一致；无 WebAuthn 证明'
if __name__=='__main__':
    try:print(verify_archive(sys.argv[1]))
    except Exception as e:raise SystemExit('FAIL: '+str(e))
