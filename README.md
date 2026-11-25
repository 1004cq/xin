# XIN v0.4 自动化存证（预发布）

详见 [v0.4 自动化存证说明](PROOF-V04.md)。以下为历史版本说明。

# v0.3 安全核心（预发布）

详见 [v0.3 安全验收与运维](SECURITY-V03.md)。下方为旧版历史说明，不作为 v0.3 的当前操作指南。请先在隔离环境中验证迁移及恢复，不可直接复用旧明文数据卷。

# XIN 信 · v0.2 预发布

## v0.2 预发布（需验收）

新增 PIN 解锁（未签邀请 7 天过期）、每份新合同冻结 PDF、必须 WebAuthn 用户验证的确认流程、Bitcoin Core 独立核验与真实主网验收脚本。旧版未确认合同应撤销后重建；既有确认记录不得重签覆盖。Passkey 可由设备 PIN 或生物识别完成，不是身份证实名认证。管理员密码登录仍未升级 MFA。

PDF 字体依赖 fonts-wqy-zenhei（Docker 自动安装），本地测试可设置 XIN_PDF_FONT 指向支持中文的 TrueType 字体。冻结 PDF 和正文都纳入 v2 确认记录；签名原始数据与 COSE 公钥一并归档。

真实 Bitcoin 主网验收（在 Ubuntu 私有网络配置已同步节点）：
```sh
python scripts/ots_live.py stamp /tmp/xin-acceptance.dat
# 日历升级及至少六个主网区块确认之后，再运行：
python scripts/ots_live.py verify /tmp/xin-acceptance.dat
```
先通过安全的环境变量设置 XIN_BITCOIN_RPC_URL、XIN_BITCOIN_RPC_USER、XIN_BITCOIN_RPC_PASSWORD。容器中的节点地址必须从容器可访问，禁止将 8332 暴露公网；HTTP 仅用于受保护的私有网络。无节点时仅显示未验证。不要将密码提交仓库。报告的链上时间不等于精确签署时间。

安全审查见 SECURITY-AUDIT.md。以下旧版介绍仅供 v0.1 历史参考；以本节及新代码为准。尚未真实联网测试、依赖漏洞扫描、生产部署或第三方安全审计，不得标为生产就绪。

# XIN 信 · 私人数字存证 MVP 0.1.0

目标域名：`xin.duojiayi.com`。Ubuntu 私人部署，不调用商业实名认证、CA 或电子合同 API。

## 当前功能

- 单管理员登录、CSRF、防重复提交、登录及核验码错误次数限制。
- 逐笔录入多笔历史借款、还款，按整数分计算余额。还款日期由用户填写，一次性逾期违约金默认 0 元，可修改；不预置任何真实个人数据。
- 合同正文及流水在创建时锁定。独立随机邀请链接与 8 位核验码；姓名输入与同意勾选，明确记录实际使用的确认方式。借款人可下载自己的副本。
- 保存原始合同、结算明细、确认记录及哈希。管理员补充归档原始证据；附件未被已提交的时间戳覆盖。
- OTS 命令提交及更新证明，始终标明未独立核验。证据 ZIP 和离线内部一致性校验工具。

## 部署（Ubuntu 24.04 LTS 推荐）

先到域名 DNS 控制台添加 A 记录：主机名 `xin`，值为服务器公网 IPv4；仅在有正确 IPv6 时添加 AAAA。开放 TCP 80/443；不要开放应用端口 8000。若服务器已有反向代理，请合并配置而不是占用已有端口。Caddy 自动申请 HTTPS；应先确认 DNS 指向正确服务器。

安装官方 Docker Engine 和 Compose 插件：https://docs.docker.com/engine/install/ubuntu/ 。把源码包解压上传到服务器，进入 `xin` 目录：

```sh
python3 setup_env.py
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs --tail=80 xin
```

浏览器打开 https://xin.duojiayi.com，使用刚才设置的管理员密码。`.env` 仅保存于服务器，不要上传。请勿用示例测试密码。

## 开源仓库

源码仓库：https://github.com/1004cq/xin 。公开源码不代表公开部署或公开用户数据。禁止提交真实借条、证件、数据库、密钥及证据包。

```sh
git clone https://github.com/1004cq/xin.git
cd xin
```

## 实际业务操作

1. 核对真实转账日期、金额及还款，录入逐笔明细；不用此前未经核实的总额。
2. 创建后，向借款人本人分别发送链接与核验码。链接持有者即可查看合同，请勿群发或放到公共网页；核验码只能防止部分未授权确认，并不证明真实身份。若发现链接泄露，立即撤销未确认邀请。
3. 借款人阅读、核对、确认并自行保存副本；建议另外签署纸质原件，留存聊天与真实转账记录。
4. 管理端点击“提交 OTS 存证”；如成功返回证明，只表示保存了 OTS 文件。待日历服务有更新后点击“更新 OTS 证明”。服务器须能访问 OTS 日历服务。
5. 导出证据 ZIP，并交给独立保管方。不得将未核验的证明标注为上链成功。

## 独立验证

```sh
python3 verify.py xin-XXXX.zip
```

该脚本只做内部一致性检查，不能排除整包被重做。另行解压归档，使用受信任的独立机器安装 OpenTimestamps 客户端，保留原始 `confirmation.json` 与 `confirmation.json.ots`，配置可访问的 Bitcoin Core 完整节点后：

```sh
ots info confirmation.json.ots
ots verify confirmation.json.ots
```

`ots info` 不是独立验证；`ots verify` 必须实际取得成功结果才可说验证通过。区块链时间证明约束文件不晚于相应区块时间已存在，不证明服务器记录的签署时间准确，也不证明本人身份或欠款事实。参考：https://github.com/opentimestamps/opentimestamps-client 。

## 运维、安全与限制

- 本版为小规模、单管理员、单进程 MVP；采用 FastAPI + SQLite + Caddy，而不是之前规划的 Next.js/PostgreSQL，以缩小第一版部署范围。未进行第三方安全审计或压力测试。
- 不是法定可靠电子签名、实名认证或公证服务。未实现 WebAuthn、手写签名采集、双人数字签署、在线独立区块链核验、PDF 自动生成、到期提醒、签后还款管理或附件单独时间戳。可通过纸质签字原件扫描后归档，不能把在线确认说成已签纸质原件。
- 数据库未实现应用层加密；真实数据使用前应启用加密磁盘、严格限制服务器管理权限、做好加密离线备份和恢复演练。管理员能直接修改底层数据库；独立证据副本及已验证时间戳只能降低事后修改风险。补充附件未上链，不能证明其时间。
- 私密链接无自动过期，未确认可手动撤销。全局登录失败限制可能被恶意触发造成短期拒绝服务。管理员 cookie 有一小时有效期，修改 SESSION_SECRET 可使旧 cookie 失效。禁止第三方访问分析及代理访问日志记录邀请 URL。外部反向代理应限制请求速率和大小。
- 如需要备份，可在计划维护期间停应用并复制 SQLite 数据卷到加密备份位置。不要执行 `docker compose down -v`（会删除数据卷）。升级前先备份并在测试环境验证恢复。
- 不允许未经同意收集身份证、人脸等敏感个人信息；本版仅需双方姓名。不要公开运营或声称官方司法存证资质。
- 约定违约金条款附依法调减约定，不保证法院全额支持。本文档不替代律师对实际债权及条款的审查。

## 本地测试

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt pytest httpx
python -m pytest -q
```

测试覆盖登录权限、CSRF、金额结算、错误核验码、合同哈希锁定、重复确认、证据导出及附件哈希。OTS 使用模拟不可用分支，不代表真实公链测试。当前源码未在真实 Ubuntu/Docker 环境构建验证，也未部署域名。
