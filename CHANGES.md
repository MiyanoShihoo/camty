# 变更记录

## P0-1 范围护栏 URL 解析绕过 + IPv6 损坏修复

- 任务号：P0-1
- 涉及文件：`camty/guardrail/scope.py`、`tests/test_scope_hardening.py`（新增）
- 变更摘要：
  - `Scope.require` 不再手写 `split("://")`/`split(":")` 提取 host，改用 `urllib.parse.urlsplit`（无 scheme 时先补 `//`），按 RFC 3986 语义解析 netloc；
  - `username`/`password` 非空一律抛 `ScopeError`，堵死 `http://target.com:80@evil.com/x` 这类 userinfo 解析歧义绕过（旧代码校验 target.com、HTTP 客户端实际连 evil.com）；
  - hostname 统一小写并去掉尾部 `.`（`https://target.com./` 不再触发对 `target.com.` 的真实 DNS 查询）；
  - 单 IP 等价网络按地址版本取 `/32`（IPv4）或 `/128`（IPv6），修复 `Scope({"ips":["::1"]})` 初始化 `ValueError` 崩溃（旧代码硬编码 `/32` 产生 `::1/32` 带主机位报错）；
  - IP 字面量（含 IPv6 方括号形式）直接用 `ipaddress` 按授权集合校验，不经平台 resolver，`cidrs=["::1/128"]` 时 `http://[::1]:8080/` 正常放行（旧代码把 `[` 当 host 误杀）；
  - 域名白名单含子域、白名单外域名解析后按 IP 白名单校验、速率限制、`require_cidr` 语义全部保留；
  - DNS pinning（TOCTOU/DNS rebinding）本轮不做，在 `getaddrinfo` 调用处加 TODO 注释说明风险。
- 新增测试：`tests/test_scope_hardening.py` 共 11 个（TestUserinfoBypass 2、TestWhitelistedForms 3、TestIpv6Handling 4、TestEmptyAndMalformed 2）；修复前 5 个用例按预期失败复现问题，测试中 DNS 全部 monkeypatch，无真实网络。
- 全量测试：`python -m pytest tests/ -q` → 267 passed（基线 256 + 新增 11，无既有测试失败）。

## P1-4 审计哈希链：尾部截断与全量重算不可检测修复

- 任务号：P1-4
- 涉及文件：`camty/guardrail/audit.py`、`camty/storage.py`、`camty/agent/state.py`、`camty/cli.py`、`camty/report.py`、`README.md`、`README.en.md`、`tests/test_audit_chain.py`（新增）
- 变更摘要：
  - `Audit.record` 新条目加单调 `seq`（从既有文件最大 seq 续）；`verify` 对含 seq 的条目校验严格 +1 连续（检测重排序/删除中间行后重算链），旧格式无 seq 条目兼容跳过；
  - 可选 HMAC：设置 `CAMTY_AUDIT_KEY` 时条目追加 `hmac = HMAC-SHA256(key, canonical(含 hash 的完整条目))`；verify 在有 key 时校验，应有 hmac 而缺失 → fail（检测"篡改全部记录并重算整条链"——重算者拿不到 key 伪造不出 hmac）；无 key 时行为 = 现状 + seq（带 hmac 字段的旧条目被忽略）；
  - 锚定：`StateDB` 新增 `audit_anchor` 表（`CREATE TABLE IF NOT EXISTS`，旧库重开自动补建）与 `add_audit_anchor`/`load_audit_anchors`；`Engagement.save_state()` 与报告生成（`write_report`/`write_docx`）把 `(count, head_hash)` 追加写入锚定表；`verify(anchors=...)` 比对"文件条数 ≥ 锚定 count 且锚定位置 hash 一致"（检测尾部截断）；
  - `python -m camty audit` 输出当前 `(count, head_hash)` 供外部存档（离线锚点，防 state.db 一并被改），并改为带锚点校验、`finally` 关闭 Engagement（顺带修复 sqlite 句柄在 Windows 上锁住临时目录的问题）；退出码语义保持（链完整 0 / 断裂 1）；
  - README/README.en"防篡改"表述改为准确边界：无 key/锚点仅能检测局部编辑；有 key/锚点可检测全量重算重写与尾部截断，并补 `CAMTY_AUDIT_KEY` 与锚点存档说明；
  - JSONL 协议仅新增字段（seq/hmac），旧格式文件读入、续链、校验全部兼容。
- 新增测试：`tests/test_audit_chain.py` 共 16 个（TestTailTruncationAnchor 2、TestSeqContinuity 3、TestHmacKey 5、TestStateAnchorTable 2、EngagementFixture 锚定/报告/CLI 4）；修复前 15 个用例按预期失败复现问题（1 个为无 key 兼容性回归守卫，修复前后均应通过）。测试无真实网络、无新依赖（HMAC 用标准库 hmac/hashlib）。
- 全量测试：`python -m pytest tests/ -q` → 283 passed（P0-1 后 267 + 新增 16，既有测试无失败）。
