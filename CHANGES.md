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

## P0-3 面板鉴权 fail-open → fail-secure

- 任务号：P0-3
- 涉及文件：`camty/api/app.py`、`tests/test_panel.py`、`tests/test_sidequestion.py`、`README.md`、`README.en.md`
- 变更摘要：
  - `_panel_token()` 改为模块级单例惰性初始化：优先 `CAMTY_PANEL_TOKEN`；未设置时用 `secrets.token_hex(16)` 生成随机 token（对齐 `c2/server/camty_c2.py` 的缺省随机 token 模式），进程生命周期内复用，首次生成打印到 stderr（提示可用 `CAMTY_PANEL_TOKEN` 显式指定）；
  - `auth_middleware` 对 `/api/*` 一律强制鉴权（原先未设置环境变量时完全无鉴权），保留 Bearer 与 `?token=`（SSE 用）两条通道；比较改 `hmac.compare_digest`，按 UTF-8 字节比较（str 形式对非 ASCII 输入会 `TypeError`，拒绝场景应得 401 而非 500）；不做回环判断（反向代理下恒为 127.0.0.1，不可靠）；
  - 测试专用重置入口 `_reset_panel_token_for_tests()`（只清生成态，不影响环境变量优先级与生产语义）；只读获取生成 token 直接用 `_panel_token()`；
  - 行为变更同步：`tests/test_panel.py` 原 `test_no_token_required_by_default` 断言的正是本任务要修复的 fail-open 行为，按验收要求重写为 `test_unset_token_fail_secure`（无 token → 401，携带生成 token → 200）；其余面板测试请求统一带生成 token 的 Bearer 头；`tests/test_sidequestion.py::TestAskAPI` 同理改为固定 `CAMTY_PANEL_TOKEN` 并携带 Bearer 头（其关于 200/400/503 的既有断言全部保留，仅补鉴权管道）；
  - README.md / README.en.md 面板说明补一句 token 行为（未设置时自动生成随机 token 并打印到 stderr，设置后用指定值）。
- 新增测试：`tests/test_panel.py` 新增 `TestPanelAuthFailSecure` 共 5 个（test_unset_env_generates_token_and_blocks_unauthenticated / test_non_ascii_token_rejected_not_500 / test_token_reused_and_env_precedence / test_generation_prints_token_to_stderr / test_uses_constant_time_compare），另重写 1 个既有 fail-open 断言（见上）；修复前 5 个新增用例按预期失败复现问题（无 token 请求得 200、无单例生成、无 stderr 提示、无常时比较）。纯标准库（secrets/hmac），无真实网络。
- 全量测试：`python -m pytest tests/ -q` → 293 passed（P0-2 后 288 + 新增 5，既有测试无失败；`tests/test_sidequestion.py` 3 个用例仅同步鉴权管道后继续通过）。

## P2-9 面板日志与并发状态

- 任务号：P2-9
- 涉及文件：`camty/api/app.py`、`tests/test_panel.py`
- 变更摘要：
  - `_ENGINE_STATE`/`_RETEST_STATE` 的 check-then-act（检查 running + 置 running）改为在模块级 `threading.Lock`（`_ENGINE_LOCK`/`_RETEST_LOCK`）内原子完成，并发 POST 仅一个进入（原先 running 由后台线程置位，存在多 caller 同时通过检查的双开窗口）；后台执行保留 `threading.Thread`（`Engine.run` 是阻塞同步代码，不能改 asyncio.create_task）；引擎/复测的终态写入（done/stopped/error）同样在锁内完成；
  - `app.py` 四处宽泛 `except Exception`（list_engagements 坏配置、start_engine/start_retest 后台失败、ask_question LLM 失败）补 `logging.exception`（根 logger，带完整异常栈），返回行为全部不变；
  - 面板行为不变项：dashboard/SSE 读状态、already-running 返回值、错误态 error 字段截断 300 字符，均保持原样。
- 新增测试：`tests/test_panel.py` 新增 `TestPanelConcurrencyAndLogging` 共 4 个（test_concurrent_engine_start_single_entry / test_concurrent_retest_single_entry / test_engine_error_logged_with_exception / test_all_broad_excepts_log）；修复前并发两用例（8 线程在 `_engagement` 入口对齐后同时进 handler）稳定复现竞态——全部 "started"、双开引擎/复测会话；修复后仅 1 个 "started"、其余 7 个 "already-running"（既有 check-then-act 竞态在裸跑下靠 GIL 时序多数轮侥幸不触发，测试用入口对齐消除该不确定性）。日志断言用 `assertLogs` 验证引擎失败栈被记录，静态断言验证全部 4 处宽泛 except 均含 `logging.exception`。无真实网络、无新依赖。
- 全量测试：`python -m pytest tests/ -q` → 297 passed（P0-3 后 293 + 新增 4，既有测试无失败）。

## P1-5 beacon.c HTTP 响应读取堆溢出

- 任务号：P1-5
- 涉及文件：`c2/implant/beacon.c`（`http_post` 响应循环）
- 变更摘要：
  - 漏洞：`WinHttpQueryDataAvailable` 返回的 `avail` 直接作为 `WinHttpReadData` 的请求字节数写入 `resp + total`，未钳制到缓冲剩余空间（`resp_max - total - 1`）。响应体超过 `HTTP_BUF_MAX`(256KB) 时（恶意/被劫持 C2、反代异常响应），`total` 接近 `resp_max` 的最后一次读取越界写堆；
  - 修复：读取量钳制 `to_read = min(avail, (DWORD)(resp_max - total - 1))`（预留 1 字节），`WinHttpReadData` 传 `to_read`，剩余空间 `room` 为 0 时 break；截断的响应随后经 `cmt1_open` MAC 校验必然失败（fail-closed），协议字节格式零改动；
  - 可运行 PoC（本机）：用 `#include` 方式把真实 `http_post` 编进独立 harness，响应缓冲改用 `VirtualAlloc(262144)`（恰好 64 页，越界即撞未映射页）；本地起 1MB 响应的 HTTP 服务端对拍：修复前（HEAD 源码）harness 稳定 `Segmentation fault`，修复后 `survived: http_post rc=0 resp_len=262143`；另用旧/新源码各编完整 beacon.exe 实跑对拍确认修复版在超长响应下持续存活且行为正常；
  - 验证边界说明：Linux CI 无法编译 Win32 目标，本项无 pytest 用例；本机 zig cc（build.ps1 同一工具链）编译零警告通过，并用修复后源码重建 `c2/implant/beacon.exe`（未跟踪产物，不入库）跑通真实 E2E（`tests/test_c2_implant.py` 2 passed）。Windows 构建/E2E 流程不变。
- 新增测试：无 pytest 新增（C 侧代码，CI 无法编译；验证方式见上——本地编译 + VirtualAlloc 边界 harness PoC + 真实 E2E）。
- 全量测试：`python -m pytest tests/ -q` → 297 passed（基线 297，既有测试无失败；其中 `tests/test_c2_implant.py` 已切换为运行修复后源码构建的 beacon.exe）。

## P1-6 CSPRNG 替换（IV 复用风险）

- 任务号：P1-6
- 涉及文件：`c2/implant/crypto.c`、`c2/implant/crypto.h`、`c2/implant/beacon.c`、`c2/implant/build.ps1`、`c2/implant/build_beacon.py`、`docs/c2-design.md`、`tests/test_c2_hardening.py`（新增）
- 变更摘要：
  - 新增 `cmt1_random_bytes(buf, n)`（crypto.c/crypto.h）：主随机源 `BCryptGenRandom(NULL, buf, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`（bcrypt.lib）；运行失败或构建链不支持（编译期 `-DCMT1_NO_BCRYPT`）时退 `SystemFunction036`（RtlGenRandom，advapi32 导出，无公开头文件手动声明）。两种来源失败一律返回 -1，`cmt1_seal` 的 IV 填充 fail-closed（放弃本次封包）；
  - `cmt1_seal` IV 从 `rand()`（srand=GetTickCount）改为 `cmt1_random_bytes`——多植入体共享 PSK 时 CBC IV 不再因同毫秒启动而复用；beacon id 从 `rand() & 0xFFFF` 改为 2 字节 CSPRNG。**线上字节协议零改动**：仍为 `magic|iv(16)|ct|mac`，beacon id 仍为 `host-%04X`（16 位十六进制，仅随机源更换，实测注册 id `DESKTOP-…-0C33`）；
  - jitter 保留 `rand()`（非密码学用途，srand 播种保留，注释标明）；
  - 构建脚本同步：`build_beacon.py` 链接 `-lbcrypt -ladvapi32`，`build.ps1` 链接 `-lwinhttp -lbcrypt -ladvapi32`（原脚本仅 `-lws2_32`，自 WinHTTP 迁移后已无法链接），两者均带"bcrypt 链接失败 → `-DCMT1_NO_BCRYPT` 回退重试"逻辑；顺带修复 `build.ps1` 一个既有缺陷：PowerShell 逗号优先级高于 `+`，`@('x' + $a, 'y' + $b)` 会被折叠成单个字符串导致全部 define 丢失（原脚本从未可用，元素拼接现加括号）；
  - `docs/c2-design.md` v1 边界更新：IV 与 beacon id 来自 BCryptGenRandom（退 RtlGenRandom），协议字节格式不变，jitter 仍用 rand()。
- 新增测试：`tests/test_c2_hardening.py` `TestCsprngSubstitution` 共 7 个（test_iv_uses_csprng / test_csprng_sources / test_header_declares_csprng / test_beacon_id_uses_csprng / test_rand_only_for_jitter / test_build_scripts_link_bcrypt_with_fallback / test_design_doc_boundary_updated）——源码级断言锁定 CSPRNG 语义与协议格式不变（C 侧 Linux CI 无法编译，静态守卫 + 本机构建验证）。
- 验证：本机 zig cc 两条构建路径（bcrypt 链接 / CMT1_NO_BCRYPT 回退）均零警告编译；crypto KAT（FIPS-197 / SHA-256 / RFC 4231 / CMT1 往返与篡改拒绝）全绿；`tests/test_c2_implant.py` + `tests/test_c2_e2e.py` 真实 E2E 全绿；build.ps1/build_beacon.py 正常与回退路径实测通过（用假 zig 模拟无 bcrypt 工具链）。
- 全量测试：`python -m pytest tests/ -q` → 304 passed（297 + 新增 7，既有测试无失败）。

## P2-7 beacon.c 健壮性（run_cmd / build_beacon_json）

- 任务号：P2-7
- 涉及文件：`c2/implant/beacon.c`、`tests/test_c2_hardening.py`
- 变更摘要：
  - `run_cmd` 读循环重构：`PeekNamedPipe` 探测 + 50ms 进程轮询 + 60s 截止（`GetTickCount` 回绕安全的差值比较）。输出达 `OUT_MAX` 后继续 drain 管道（读入 4KB `discard` 丢弃，`total` 不推进），子进程不再因写满的管道永久阻塞；进程退出后排空管道剩余输出再收尾；超过 60s 仍存活则 `TerminateProcess` + 等 5s 防僵尸，输出尾追加 `\n(timeout killed)`，退出码上报 -1；
  - `STILL_ACTIVE(259)` 是"仍在运行"哨兵值：超时路径上报 -1，非超时路径也以 `(code == STILL_ACTIVE) ? -1 : code` 兜底，不再当真实退出码上报；
  - `build_beacon_json`：id/host/user/arch 四个字段全部先 `json_escape` 再拼装（引号/反斜杠/控制字符不再破坏 JSON 结构）；beacon_json 缓冲 512 → 4096（最坏转义后 ≈1.5KB 不截断 sleep 字段）。协议格式与字段名零改动；
  - 行为边界说明：持续产出输出超过 60s 的命令同样在截止时间被杀并标注（原行为是无限期阻塞在管道读，更糟）。
- 新增测试：`tests/test_c2_hardening.py` `TestRunCmdRobustness` 共 4 个（test_drains_pipe_after_buffer_full / test_timeout_kills_and_annotates / test_still_active_not_reported_as_exit_code / test_build_beacon_json_escapes_all_fields）；既有植入体 E2E（`tests/test_c2_implant.py`）保持绿。
- 运行时验证（本机，修复后 beacon.exe 实跑）：短命令 `echo` exit=0 约 1s；>64KB 输出命令（`for /l 1..3000 echo AAA…`，约 99KB）3s 完成且输出截断在 65535（修复前子进程会在 64KB 处写满管道永久阻塞）；挂死命令（`ping -n 200`）60.4s 被 `TerminateProcess`，输出尾 `\n(timeout killed)`、exit=-1（非 259）。另用 `#include` 真实 `build_beacon_json` 的 harness 喂入含引号/反斜杠/控制字符的恶意字段，Python `json.loads` 解析成功且 roundtrip 值精确一致。
- 全量测试：`python -m pytest tests/ -q` → 308 passed（304 + 新增 4，既有测试无失败）。

## P2-8 小项加固（C2 token 恒时比较 + vault 明文兜底收紧）

- 任务号：P2-8
- 涉及文件：`c2/server/camty_c2.py`、`camty/llm/vault.py`、`tests/test_c2_hardening.py`、`tests/test_vault_fallback.py`（新增）、`tests/test_c2_e2e.py`
- 变更摘要：
  - `camty_c2.py` `_authorized`：token 比较 `==` → `hmac.compare_digest`（新增 `import hmac`），并按 UTF-8 字节比较（compare_digest 的 str 形式对非 ASCII 输入会 TypeError，拒绝场景应得 401 而非 500——与 P0-3 面板修复同一模式）；判定结果语义不变（恰好匹配才放行）；
  - `camty/llm/vault.py` 收紧：cryptography 缺失时 `encrypt_text` 默认拒绝写入新密钥（RuntimeError，提示 `pip install cryptography` 并指明逃生口）；仅当显式设置 `CAMTY_ALLOW_PLAINTEXT_KEYS=1` 才允许明文兜底——返回 `{"encrypted": false, "payload": ...}` 标记 blob 并发 `UserWarning`（警告保留）；新增 `plaintext_fallback_allowed()`（严格匹配 `=1`）与 `PLAINTEXT_ENV` 常量；`decrypt_text` 支持读回标记 blob（写入已获显式同意，读取不设二次门禁），已加密 blob 无 cryptography 时仍拒绝、opt-in 不放宽；有 cryptography 的加密路径行为不变；
  - 范围边界说明（router.py 不在本任务范围）：`router.save()` 在"未设 CAMTY_MASTER_KEY"或"cryptography 缺失"时的明文写分支（camty/llm/router.py:168-171）不属于本任务（router.py 由其他任务持有，本任务红线禁碰），既有"已加密 vault 拒绝降级"检查未动；vault 模块自身的写入门禁已按规格收紧，router 侧如需把 `plaintext_fallback_allowed()` 接进 save() 的 else 分支，属 router 任务的后续接线点。可运行反证 PoC（本机实测）：环境无 `CAMTY_MASTER_KEY`、无 opt-in 时，`LLMRouter(vault_path=...).set_provider(...)` 仍写出明文 keys.json——即该分支现状如实记录于此，非本任务引入也非本任务可修；
  - 环境事实修正：任务书"本机未安装 cryptography"与实际不符——cryptography 50.0.2 以 `--target` 方式装在仓库 `vendor/`，由 `camty/__init__.py`（CAMTY_NO_VENDOR=1 可禁用）自动挂载 sys.path；"无 cryptography 环境"对应 `CAMTY_NO_VENDOR=1`，实测该模式下 `TestVault` 按既有 skipUnless 跳过、本任务新增的 vault/hardening 用例全部通过，而 `TestC2EndToEnd` 整类在 setUpClass 失败为**既有行为**（C2 服务端协议层 protocol.py 硬性要求 cryptography，非本任务引入、超出本任务范围）。
- 新增测试：`tests/test_vault_fallback.py` 共 6 个（test_fallback_requires_explicit_one / test_encrypt_refuses_without_cryptography / test_encrypt_plaintext_fallback_optin / test_plaintext_blob_roundtrip / test_decrypt_encrypted_blob_refuses_without_cryptography / test_real_crypto_unchanged——均用 mock 强制 `_fernet_cls` 为 None，装不装 cryptography 断言都成立，最后一个 skipUnless 守卫真实加密路径）；`tests/test_c2_hardening.py` `TestApiTokenCompare` 共 4 个（test_compare_digest_in_source / test_authorized_exact_match / test_authorized_rejects_variants / test_authorized_non_ascii_no_500）；`tests/test_c2_e2e.py` 新增 1 个真实服务端行为用例（test_api_rejects_missing_or_wrong_bearer：无 token / 错 token / 错前缀均 401）。
- 全量测试：`python -m pytest tests/ -q` → 319 passed（308 + 新增 11，既有测试无失败）。

## R2-P0 traffic.py socket 属性暂存（Python 3.13+ 崩溃源）
- **任务**：`sock._camty_leftover` 在 Python 3.13+ 的 socket 对象（无 `__dict__`）上直接 AttributeError；本机实测复现（3.14.4 同样崩）。此缺陷潜伏的原因：仅在 `_recv_until` 单 chunk 过读越过 `\r\n\r\n` 时触发，既有 MITM E2E 未踩到该 chunk 边界。
- **涉及文件**：camty/traffic.py、tests/test_artex_port.py（新增 TestTrafficLeftoverPlumbing）
- **修复**：`_read_headers` 返回 `(headers, 过读尾部)`，`_read_body(sock, headers, leftover)` 显式收参——零隐藏状态，任意 Python 版本可移植。回归测试用真实 `socket.socketpair()` 复现旧代码必崩场景。
- **测试**：+1；全量 326 passed（修复前该新测试对旧代码必失败）。

## R2-P1 test_run_impacket_env 平台无关化
- **任务**：与 test_vendor_root 同源问题——用例内仍用 Windows 字面量路径，Linux 上 PYTHONPATH 解析成无关目录断言失败。
- **涉及文件**：tests/test_upgrades.py
- **修复**：改平台原生临时目录路径构造，断言精确到 `base/vendor`。
- **测试**：既有用例重写（断言语义保留），平台无关。

## R2-P1 requirements.txt 补 cryptography
- **任务**：fresh clone 缺 cryptography（vendor/ 不入库），C2/vault 相关功能在干净环境直接缺包失败。
- **涉及文件**：requirements.txt
- **修复**：`cryptography>=42` 入核心依赖（vendor/ 缓存副本仍保留，作者环境可离线）。

## R2-P2 面板纵深防御：sev() 内移 esc + 色板查表守卫
- **任务**：①sev() 函数体 `${s}` 裸插值（调用点已包 esc 但属防御单点）；②`colors[hit.kind]` 原型链取值（`kind="constructor"` 时取到函数对象串进 style 属性——不构成 XSS，属健壮性）。
- **涉及文件**：camty/api/app.py、tests/test_panel.py
- **修复**：esc 移入 sev() 函数体（调用点去外层 esc 防双重转义）；两处 colors 取值加 `Object.hasOwn` 守卫。守卫测试白名单同步：`sev(f.severity)`（函数体已内部 esc）、`Object.hasOwn(...)` 查表（守卫静态字面量），清点数字不变（117 = 77 esc + 40 白名单）。
- **测试**：面板 24 全绿（清点守卫同步后）。

## R2-P1 repeater TLS 回退静默降级
- **任务**：repeater.py 的 urllib 回退路径无条件 `CERT_NONE`——缺 curl_cffi 的机器静默变成不验证证书，携会话 Cookie 的流量可被 MITM。
- **涉及文件**：camty/repeater.py、tests/test_repeater.py
- **修复**：回退路径默认走系统证书校验（不再自定义 HTTPSHandler）；curl_cffi 路径对称 `verify=not _tls_insecure()`；自签场景须显式 `CAMTY_TLS_INSECURE=1`，首次生效打 stderr 警告（进程内只打一次）。
- **测试**：+2（默认关、显式开+警告一次性）。

## R2-P1 repeater_api 六端点 fail-secure 鉴权
- **任务**：/req /vector /seq /log /state /stop 零鉴权——本机任意进程可借用会话 Cookie 发请求、读 /log 历史。缓解因素（绑 127.0.0.1、scope.require、审计链）不足。
- **涉及文件**：camty/repeater_api.py、tests/test_repeater.py
- **修复**：复用面板 fail-secure 模式（`CAMTY_REPEATER_TOKEN` 优先，未设 `secrets.token_hex(16)` 生成 + stderr 打印，`hmac.compare_digest` 字节比较，Bearer + `?token=` 双通道，测试重置入口）。全端点生效；仓内无 HTTP 消费方，零破坏。
- **测试**：+4（无 token 401 / 生成 token 200 含 ?token= 通道 / 错误 token 401 / 显式 env token）。

## R2 全量测试结果
- 319（上轮终态）→ **326 passed**（+7：回归 1 + TLS 2 + API 鉴权 4），零既有失败。

# R3 测试隔离与 CI 收尾

## 步骤0 复现定性（干净 venv = CAMTY_NO_VENDOR=1 + 仅 requirements(+dev)，Windows 3.14.4）
- 复现集合 ≠ 9：**14 failed + 4 errors + 1 skipped**，且与交战报告的 9 完全不相交——按规矩先回报差异清单，未强行凑定性。
- **A1 簇（17 条）**：`starlette.testclient requires httpx2`——干净安装拉到新版 fastapi 0.165/starlette 1.10（requirements 未锁上界），TestClient 改依赖 httpx2，而它是未声明的 test-only 依赖。panel×10、ask×3、repeater-api×4。
- **A2 簇（1 条）**：test_auto::test_full_auto_chain 的 docx 断言"可用时应出 docx"未做可用性门控，缺 python-docx 时直接红。
- **交战报告的 9（8 artex 污染 + 1 asreproast）在本机 Windows 干净环境全绿**——指纹定案：
  | 项 | 本机（win32） | 交战环境/CI（linux）推断 |
  |---|---|---|
  | getproxies() | {'http':'127.0.0.1:7897',…}（注册表系统代理，env 为空） | 仅 env，无系统代理 |
  | proxy_bypass('127.0.0.1') | **True**（注册表 bypass 名单含 localhost） | **False**（no_proxy 未设） |
  | curl_cffi | 0.17.0 在场（requirements 内） | 同 |
  - 机制链：test_scope_enforcement 设 http_proxy 后调全局 urlopen → 代理焊进进程级 `urllib.request._opener` 缓存 → finally pop 救不回。Windows 下游打本地靶被 bypass 名单豁免 → 全绿；Linux localhost 也进死代理 → 8 连带红。asreproast 为工具发现路径的平台差异。**CI ubuntu 腿天然复现该场景**，是最终裁决。

## 修复清单
1. **P0 焊点（test_scope_enforcement）**：改显式 `ProxyHandler` 局部 opener（build_opener+opener.open），403 断言语义不变；env set/pop 删除，不再碰全局 opener。同文件 mitm 测试已是局部 opener，核验未动。
2. **conftest 三件套（新建 tests/conftest.py，autouse）**：env 全量快照 → 收尾先采样代理四变量 → clear+update 恢复 → `urllib.request._opener = None`（私有属性，仅测试兜底）→ 泄漏则 pytest.fail 点名测试。正向验证：临时造漏恢复 http_proxy 的测试，teardown 即标红并报泄漏变量。
3. **asreproast 可用性边界 mock**：`camty.adapters.base.find_tool`（非 spec 原文的 impacket 命名空间——该符号由 base.py:11 导入，按原文写会 AttributeError）返回伪路径；解析断言未动。mock 返回值用 POSIX 路径避开盘符守卫自伤。
4. **test_auto docx 门控**：python-docx 可用性探针，可用断言产出、缺失断言不产出（原语义"可用时"补真），不 skip（其余断言保留覆盖）。
5. **全 tests/ 排查清单（设代理 env + 全局 urlopen 交叉）**：除 P0 焊点外**无新焊点**；env 写入逐处核验——audit_chain/countermeasures/engine/platform/vault_fallback 均 mock.patch.dict 托管还原，repeater/panel/sidequestion 均 saved/restore 或 setUp/tearDown 模式正确，c2_implant 只读。
6. **CI 矩阵（新建 .github/workflows/ci.yml）**：push+PR(main) × `ubuntu-latest/windows-latest` × Python 3.10/3.11/3.12/3.13 八腿，fail-fast=false，安装 `requirements.txt + requirements-dev.txt` 后全量 pytest；不预装任何外部工具（依赖声明缺口的永久探针）；无 allow-failure。YAML 细节：版本号加引号（裸 3.10 在 YAML 1.1 被 PyYAML 解析为浮点 3.1）。
7. **requirements-dev.txt（新建）**：pytest>=8 + httpx2>=1（A1 根因——新版 starlette TestClient 的必需依赖）。
8. **文档同步**：badge Python-3.12+ → 3.10+（双语）；快速开始补 dev 依赖行；支持底线声明"3.10–3.13（CI 矩阵在 Ubuntu/Windows 实测）"；AGENTS.md §0 补 dev 依赖安装。
9. **双守卫**：tests/test_hygiene.py 盘符守卫（正则 [A-Z]:\ 扫全 tests/，命中即红；白名单项须含 skipUnless，当前为空）+ test_e2e_tools docstring 改写去盘符。注入验证：向 test_engine.py 注入 C:\guard\check → 守卫红并报文件:行 → 字节级还原后复绿。

## 前后计数（干净 venv 口径）
- 修复前：14 failed + 4 errors + 1 skipped（httpx2 簇 17 + docx 门控 1）
- 修复后：**326 passed + 1 skipped（0 failed / 0 errors）**；主环境 327 passed。
- 交战报告的 Linux 侧 8 污染 + 1 asreproast 由 CI ubuntu 腿作最终裁决（proxy_bypass 平台差异在本机不可复现，但机制已双保险修复：焊点摘除 + conftest 兜底）。

## 偏差记录
- find_tool patch 目标改 base 命名空间（见上）；mock 返回值 POSIX 化；conftest 收尾顺序改为"采样→恢复→清 opener→判红"（先恢复再比较会让断言恒真）；A2 不用 skip 而用条件断言（保留其余覆盖）；CI 版本号加引号。

## R3 增补：CI run#1/#2 事故记录与双根因修复（产品代码，另行授权批次）

### CI 首跑（run#1，fe0aaec）7/8 红的分层定性
- **cp1252 簇（windows 全腿）**：CI Windows 控制台默认 cp1252，`python -m camty` 子进程打印中文（[multi] 汇总 / orchestrator 横幅 / C2 服务端横幅）即 UnicodeEncodeError 崩——连锁打掉 test_gapclosure×1、test_c2_e2e×3（服务端未就绪）、test_countermeasures×2（拒连）。修法：ci.yml job 级 `PYTHONUTF8: "1"`（4bac311，CI 层）。本机全绿的掩盖原因：Git Bash 控制台为 UTF-8。
- **run#2（4bac311）**：3.12/3.13 四腿全绿；剩余 3.10/3.11 四腿红，失败恰为 test_pack_plan_run + test_https_mitm_record 两个，双 OS × 两轮确定复现 → 非竞态噪声，进入根因挖掘。

### 根因 1：Todolist.mark RMW 竞态（并发丢失更新）
- 证据：① CI stdout 精确形态——[worker] I-005 done 后 todolist 仍 T1 [pending]、T3 [done]（两 worker 并发 mark，后提交者以旧快照全表重写覆盖前者）；② 代码检查：items() 读→内存改→sync_todolist DELETE 全表+重插，无跨操作原子性；③ PoC：setswitchinterval(1e-6) 下 300 轮并发 mark **丢失 270 次**（正常调度 0/300——CI ≤3.11 满载调度密度恰落在必中区间，故呈"版本边界"假象，实为全版本潜伏）。
- 修复：storage 新增 mark_todolist_item（单条 UPDATE，sqlite 原子；note 语义保留：显式传入才覆写），Todolist.mark 改走该路径。
- 回归：TestTodolistMarkConcurrency——放大切换密度 × 200 轮三线程并发，断言零丢失（旧实现此测试必红）。

### 根因 2：CONNECT 排空死锁（TrafficProxy × ≤3.11 urllib）
- 证据：① CPython 3.11 源码 do_open 的 tunnel_headers={}（CONNECT 裸发、零头）；② 3.14.4 实测 CONNECT 带 Host 头；③ 代理 _read_line 吃首行后 _recv_until(b"\r\n\r\n") 在裸形态下剩余恰为 "\r\n" 永等不齐——代理等字节、客户端等 200，双向死锁 → 30s 超时（CI 3.10/3.11 四腿两轮确定复现；3.12 起 urllib 给 CONNECT 加了头所以绿）。
- 修复：提取 _drain_connect_headers——读至 buf==b"\r\n"（裸）或 endswith(b"\r\n\r\n")（带头）即止，双形态兼容。
- 回归：TestConnectDrainShapes——socketpair 双形态回放，死锁形态以 settimeout(5) 快速失败而非挂死。

### 修复后计数
- 主环境 327 → **330 passed**；干净 venv 326+1s → **329 passed + 1 skipped**（新增 3 回归）。
- 修复属产品代码（camty/storage.py、camty/agent/explore.py、camty/traffic.py），按 R3 裁决规则经操作者单独授权执行。
- 撤 3.10/3.11 腿的替代方案被否决：两个缺陷均为全版本潜伏，撤腿等于静默真实缺陷，违背 CI"依赖/缺陷永久探针"定位。

## R3 补记（审查意见落地）

### httpx2 依赖澄清（操作者已核 PyPI）
- httpx2 非 typosquat：PyPI 所有权归 pydantic 组织、维护者 Kludex、作者署名 Tom Christie——httpx 的官方延续（Pydantic 接管维护）。dev 依赖正确且必要（starlette 1.10 的 TestClient 直接要求）。
- 记录项：httpx2 最新 2.16.2 要求 Python≥3.11，3.10 腿由 pip 自动解析到旧版 httpx2，属预期行为（resolves 一致，TestClient 两代均可用）。

### P2c 补实现：README 计数一致性守卫
- tests/test_hygiene.py 新增 TestReadmeCountConsistency：①tests badge 数字 == 正文两处测试计数（双语）；②正文套件数 == tests/test_*.py 实际文件数。增删测试文件漏改 README 必红。
- 顺手同步：badge 245→330（实际主环境计数）、正文六处（自检/测试计数 245→330、套件数 16→26）。
- 权威计数口径：全依赖主环境（330）；CI 各环境因 skip 差异计数不同，守卫只做静态一致性不做动态收集。

### 可选未做项记录
- A1 根因是 fastapi/starlette 无上界漂移；后续可加 constraints 锁文件求 CI 复现性（记录为可选项，不阻塞，与"探针暴露漂移"的现有哲学权衡后由操作者定夺）。

### 惯例确立
- Release notes 双语（中英）；v0.3.0 / v0.3.1 已补英文节。
- About 描述按审查指示改英文；正文口径以 README 双语为准。

# R4：实验捕获缺陷修复批次（PE2 全权执行实验的六 bug + 适配器三修）

依据：Camty 全权执行 PE2 两轮实验的 buglog（scripts/pe2_buglog.md）——8 项缺陷全部
实锤留痕，其中 BUG-08（done 恒真桩）经平台权威裁决（0/3 completed）升级为 P0。

## 引擎簇（camty/agent/engine.py + camty/storage.py）
- **F-02 [P0] blocked 释放**：`mark_todolist_item` 对 blocked 同步 `intent_id = NULL`
  ——三次终态的楔死根因（blocked intent 永久占用派发位）拔除；历史意图节点保留，
  MAX_RESPAWN 防死循环。
- **F-08a [P0] 完成判定去叙事化**：`_intent_produced` 从恒真桩（`return bool(intent)`）
  改为 `real_calls > 0`——worker 纯叙事不再换 done，blocked → 规划者重派。
- **F-08b [P0] 提示词硬化**：WORKER_SYSTEM 新增证据锚定规则——声称"偷到会话/读到
  文件"的唯一合法依据是工具返回中真实出现该证据，无证据必须自述未达成。
- **F-03 [P1] worker 决策重试**：`_chat_with_retry` 两次尝试——供应商瞬时抖动不再
  整杀意图（实验实录：I-005 首枪未发即死于 120s 超时）。
- **F-01 [P0] mission 注入**：objective.mission 全文（900 字符截断）进规划者提示词
  ——此前只传 goal['title']，冷启动引擎不知道目标是谁（constraints 通道曾为绕过）。
- **F-06 [P0] 空计划守卫**：LLM 输出空 todolist 时保留既有计划——91 步积累不被一次
  空输出抹掉。

## 适配器簇（browser / skill_lookup / recon_web）
- **F-07 [P1] 动作透明化**：browser-action 摘要逐动作可见（`goto:{url}` / `click:{selector}` /
  `fill:{selector}={值30字符}` 等 7 类），data 增结构化 actions 数组与 actions_digest；
  browser-visit 补输入框计数——worker 自述完成从此可被外部审计（BUG-08 的观测面）。
- **F-04 [P1] skill-lookup 双语别名**：26 组中英术语双向（password reset poisoning↔密码重置
  等），短词词边界防误伤，别名命中降档评分——worker 英文主题不再对中文技能库落空。
- **F-05 [P2] dir-scan 去重**：URL 归一化 key（scheme/host/path 小写+query 排序）运行内
  去重，跨状态码保留首个，evidence 保留原始全量。

## 计数
- 全量测试 332 → **349 passed**（+6 引擎回归 +11 适配器回归）；主环境验证。
- README 计数守卫同步：badge/正文 330→349、套件 26→27。

## R4b：BUG-09/10 修复（第三轮 1h 检测实锤，fail-closed 结果判定）

依据：第三轮 1h 检测（03:03 收网）——R4 后引擎机械健康质变（三轮零楔死、断点续跑、
动作全透明），但平台仍 0/3，取证定位两个新缺陷：

- **BUG-09 [P0] done 验证"动了手"不验证"成了"**：worker 真实开枪（4 次登录全被拒）
  如实报告失败，`real_calls > 0` 仍机械记 done——修复为**结果标记协议**：
  WORKER_SYSTEM 规则 6 约定总结末行 `[RESULT: 成功|失败]`；引擎 `_claimed_success`
  fail-closed 解析——无标记/失败标记一律 blocked，诚实失败获得重派机会；
  "确认无此漏洞"类侦察结论属成功。
- **BUG-10 [P0] 规划者状态越权**：merge 时规划者 LLM 输出可直接写 item 状态，
  可把 worker 判 blocked 的项翻成 done（幻觉翻案）——守卫：blocked→done 的
  翻案路径封死，done 的唯一合法来源是 worker 的成功标记。
- 顺带修正：R4 批次中 F-08b（WORKER_SYSTEM 证据锚定规则 5）因脚本中途失败
  实际未落盘（本轮复核发现），已随规则 6 一并补齐。
- 回归：tests/test_engine_fixes.py 增至 10 项（标记协议三态/规划者翻案守卫），
  test_artex_port 既有用例按标记协议同步；全量 **353 passed**，README 计数同步。

## R5：BUG-11/12 修复 + agent-orchestrator 内置（第四轮 1h 检测实锤）

依据：第四轮 1h 检测（R4b 引擎，17:15 收网，平台 0/3）——修复生效的部分全部生效
（三轮零楔死、动作可取证），但两个新缺陷让引擎 27 分钟冻结在 47 条 activity：

- **BUG-11 [P0] 标记协议不遵从**：I-002 侦察输出质量极高（完整 sitemap、错误语义、
  认证机制全带证据）但总结未带 `[RESULT: 成功]` 标记 → fail-closed 判 blocked。
  长总结场景 LLM 对"末行格式"类指令遵从率极低——修复为**结果上报工具化**：
  worker 工具集新增 `report-result`（verdict=成功|失败 + evidence），拦截不计
  real_calls（纯叙事上报不算产出，BUG-08a 语义不放松）；`_evaluate_result` 以工具
  上报为权威判定（覆盖文本标记），未上报时回退 `_claimed_success` 文本解析
  （老协议兜底，向后兼容）。工具调用遵从率≈100%，文本格式协议退役为遗留通道。
- **BUG-12 [P0] blocked 依赖饿死（死锁新形态）**：T1/T2 blocked 后 T3 的
  depends_on 永不满足 → 整链冻结、重启全部秒退。修复为 **blocked 生命周期**：
  ①引擎无事可派时 `_rearm_blocked` 回收仍有重派预算的 blocked 项置 pending
  （重臂不变量 rearms < dispatches：每次重臂必须先兑现成一次真实派发，防规划者
  状态乒乓空转）；②dispatches ≥ MAX_RESPAWN 的项永久 blocked，note 标注
  "重派预算耗尽"；③`Todolist.summary()` 行尾附 note 片段——规划者可见失败原因
  与耗尽标记；④PLANNER_SYSTEM 规则 6：重派前必须改写打法，依赖耗尽项的条目
  必须重排路线；⑤死循环检测改 `count > MAX_RESPAWN`（重臂后的合法重派不得误拦）。
- **BUG-10 守卫扩展（规格外必要修正，测试实跑暴露）**：两步翻案路径
  blocked → 引擎重臂 pending → 规划者翻 done 会绕过原守卫——现对"重臂后
  pending"的 done 翻案同样拒绝（恢复为 pending 待重派），done 唯一来源仍是
  worker 判定。
- **agent-orchestrator 编排技能内置**：ZCode 的 agent-orchestrator 技能全包
  入库 skills/（grill 质询/独立评审/SDS 设计规格/恢复协议）；skill-lookup 别名表
  新增 orchestrator ↔ 编排/多智能体协作/任务编排 双向组，工具描述同步。
- **planner_skill 注入通道**：配置 `planner_skill: <技能名>` → 规划者每轮
  system 提示词追加该技能正文（复用 skill-lookup 根目录探测与 6000 字符截断，
  惰性缓存，缺失静默降级）——规划者开局即按编排方法论工作，不等 worker 卡住
  才检索。psxam2 启用 agent-orchestrator（第五轮 2h 完整测试配置）。
- 修复：test_blackboard 两个引擎用例的 MockRouter 脚本按 R4b 语义升级
  （worker 走真实调用 + report-result 上报，消除了 R5 重臂带来的 30s×2 退避睡眠），
  断言不变；0.13s 完成。
- 回归：tests/test_engine_fixes.py 增至 16 项（工具化判定三态/重臂三态）；
  新增 tests/test_planner_skill.py（注入/缺失降级/无配置三态）；
  test_modules.py 新增编排别名端到端 + 真实库内置契约（打包环境 skip 先例沿用）；
  全量 **364 passed**，套件 27→28，README 计数同步。
