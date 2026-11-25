import secrets, hashlib, getpass, os
from pathlib import Path
p=Path('.env')
if p.exists(): raise SystemExit('.env 已存在，不覆盖')
pw=getpass.getpass('设置管理员密码（至少16字符）：')
if len(pw)<16 or pw!=getpass.getpass('再次输入：'): raise SystemExit('密码过短或两次不一致')
s=secrets.token_hex(16); h=hashlib.scrypt(pw.encode(),salt=bytes.fromhex(s),n=16384,r=8,p=1,dklen=32).hex()
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f:f.write(f'XIN_BASE_URL=https://xin.duojiayi.com\nXIN_SESSION_SECRET={secrets.token_hex(32)}\nXIN_ADMIN_HASH={s}:{h}\nXIN_DATA_KEY={secrets.token_hex(32)}\nXIN_ADMIN_ENROLL_TOKEN={secrets.token_urlsafe(32)}\n')
print('已生成 .env；请离线备份数据密钥。首次管理员注册从服务器 .env 读取 XIN_ADMIN_ENROLL_TOKEN，勿提交 GitHub。')
