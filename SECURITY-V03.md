# v0.3 安全验收（开发分支）

本版本以小型单机部署为目标，不宣称司法认证或法定可靠电子签名。双方独立邀请 + 不同 WebAuthn 凭据不等同于两个经法定核验的人。

## 验收与限制
- 数据库在内存中解密，使用 AES-256-GCM 及 HKDF 域分离，每次变更原子替换密文。整个数据库最大 256 MiB，单机串行访问，不用于高并发。磁盘 swap、宿主内存、容器管理员、明文证据下载不在此加密保护范围。关闭明文 swap/核心转储，使用加密磁盘及严格主机权限。
- 容器临时目录采用 tmpfs，避免上传与 OTS 临时文件落普通磁盘；仍须核对宿主交换分区。服务端会话可撤销，已进入处理的请求不能保证立即取消。
- 首次管理员注册需要密码及独立服务器初始化密钥；注册后重新登录并完成 Passkey。务必安全保存数据密钥及独立备份密钥，离线恢复时使用原数据密钥（审计 HMAC 依赖它）。恢复清除旧会话和挑战；遗失管理员凭据须停服、离线重置并轮换初始化密钥。
- 审计日志有追加限制及 HMAC 链，不防掌握密钥/主机权限的人重写或回滚整个数据库。生产前应在独立位置定期保存审计链头及时间证明。
- 备份使用独立 32 字节密钥，不覆盖已有文件。恢复只到新的目录，先验完整性及审计链。旧版迁移必须停服、保留加密原始备份、用新的目录作为目标；旧版未确认邀请全部撤销并重新创建。既有正文、确认记录、证明字节不重写。
- 生产阻断项：完整 CI、主网真实存证、iPhone/Safari 实机、服务器 TLS/权限/防火墙、恢复演练、独立安全审计。当前不能宣称生产就绪。

## 运维命令（停服或隔离测试实例）
在安全终端通过环境变量设置 XIN_DATA_KEY；不要把密钥粘贴至聊天或提交仓库。脚本要求预先存在的安全目标目录。

```sh
python scripts/ops.py migrate --data /secure/new-data --file /secure/legacy/xin.sqlite3
python scripts/ops.py audit --data /secure/new-data
python scripts/ops.py backup --data /secure/new-data --file /secure/backup/xin.enc
python scripts/ops.py restore --data /secure/restore-test --file /secure/backup/xin.enc
python scripts/ops.py audit --data /secure/restore-test
```
验收应对照原始数据库中已签合同、PDF、receipt 和 OTS 的 SHA-256，禁止使用真实资料做公开 CI 测试。
