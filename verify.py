"""Offline consistency checker. This does NOT validate a blockchain proof."""
import hashlib, json, zipfile, sys

def sha(b): return hashlib.sha256(b).hexdigest()
with zipfile.ZipFile(sys.argv[1]) as z:
    assert len(set(z.namelist()))==len(z.namelist()), '重复路径'
    m=json.loads(z.read('manifest.json'))
    assert set(z.namelist())==set(m['files'])|{'manifest.json'}, '文件清单不一致'
    for name,h in m['files'].items():
        if sha(z.read(name))!=h: raise SystemExit('文件哈希不符：'+name)
    if 'confirmation.json' in z.namelist():
        r=json.loads(z.read('confirmation.json'))
        assert r['contract_sha256']==sha(z.read('contract.txt')), '合同不匹配'
        assert r['ledger_sha256']==sha(z.read('ledger.json')), '明细不匹配'
        if 'contract_pdf_sha256' in r and r['contract_pdf_sha256']!=sha(z.read('contract.pdf')): raise SystemExit('PDF 哈希不符')
        print('确认记录与合同、明细及适用的 PDF 哈希相符。')
    print('归档内部一致；这不是身份、时间或链上真实性验证。')
    print('OTS 文件存在：', 'confirmation.json.ots' in z.namelist())
