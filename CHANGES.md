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

## P0-2 面板存储型 XSS（目标 → 操作员）

- 任务号：P0-2
- 涉及文件：`camty/api/app.py`、`tests/test_panel.py`
- 变更摘要：
  - 内嵌单页 `_PAGE` 新增 JS `esc()`（转义 `& < > " '`），全部动态插值改为 `${esc(...)}` 包裹：finding/traffic/graph/todo/activity/usage 各字段、`JSON.stringify(...)` 结果、`.slice(...)` 截断文本、`sev()` 入参、`data-*` 属性值、fdg-detail、SSE live-activity、toast 等；恶意目标返回的 `resp_body/req_body` 不再能注入 `<img onerror>` 之类窃取面板 token；
  - 行构造（findings/资产/todolist/复测记录/流量行等）改为先拼装行 HTML 再插入模板，变量插入点与 sev 内部插值在测试白名单中逐个列明（详见 `tests/test_panel.py` `WHITELIST`，含分类注释）；
  - URL 构造（`/api/engagements/${eng}/...`）改用 `engURL()` 助手 + `encodeURIComponent(eng)`（HTML 转义会破坏 URL 语义，故改连接方式消除插值；SSE `?token=` 同样 `encodeURIComponent`）；
  - toast/steer/引擎提示全部改 `textContent` + 字符串拼接（textContent 本身是安全 sink，拼接避免无谓插值）；
  - token 存储 `localStorage` → `sessionStorage`（同步 `api()` 读取、401 写入、EventSource URL 构造 3 处），关掉 XSS 偷 token 后的持久化窗口；
  - `<head>` 增加 `<meta http-equiv="Content-Security-Policy" content="object-src 'none'; base-uri 'none'; frame-ancestors 'none'">`（按规格不加 script-src，避免破坏内联脚本）；
  - 静态模板 HTML 结构未改动；JSONL/协议无改动。
- 新增测试：`tests/test_panel.py` 新增 `TestPanelXssHardening` 共 5 个（test_no_bare_interpolations / test_interpolation_inventory / test_esc_escapes_xss_payload / test_csp_meta_present / test_token_storage_moved_to_session_storage）；修复前 5 个全部按预期失败复现问题。插值静态断言：花括号配平提取 `_PAGE` 全部 `${...}`（含嵌套模板，共 117 处）＝ 77 处 `esc(` 包裹 + 40 处显式白名单（计数/索引 20、sev 内部与调用点 4、行构造变量 13、静态字面量三元/查表 3，测试内逐个列明原因）。esc 单测从 `_PAGE` 中提取真实映射表并应用到 `</pre><img src=x onerror=alert(1)>`，断言转义后不含 `<img`。纯标准库，无真实网络。
- 全量测试：`python -m pytest tests/ -q` → 288 passed（基线 283 + 新增 5，既有测试无失败）。
