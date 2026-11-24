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
