# Camty C2 v1 — 协议与设计（功能基线）

> 交付形态：服务端（Python）+ C 植入体（零依赖）+ camty 工作台适配器（c2-sessions / c2-task / c2-collect）。
> v1 原则：先跑稳，再低可见。规避层从 v2 起分层迭代。

## 1. 组件

| 组件 | 位置 | 说明 |
|---|---|---|
| 服务端 | `c2/server/camty_c2.py` | 双监听：beacon 端口（植入体）+ api 端口（operator/工作台） |
| 线缆协议 | `c2/server/protocol.py` | framing + 加密（Python 侧），含自测入口 |
| 模拟 beacon | `c2/server/fake_beacon.py` | 协议正确的 Python 替身（CI/E2E 用，可执行真实命令） |
| 植入体 | `c2/implant/beacon.c` + `crypto.c/.h` | 零外部依赖（自带 AES/SHA/HMAC），zig cc 构建 |
| 构建 | `c2/implant/build.ps1` | PSK/目标注入；工具链 `E:\AI tools\zig`（`zig cc`） |
| 工作台接入 | `camty/adapters/c2.py` | 三适配器，护栏与利用门控自动生效 |

## 2. 线缆协议（CMT1）

body（/beacon 与 /result 请求与响应通用）：

```
"CMT1"(4) | iv(16) | ciphertext(n) | mac(32)
mac        = HMAC-SHA256(psk, "CMT1" || iv || ciphertext)
ciphertext = AES-256-CBC(psk, iv, PKCS7(plaintext))
```

- PSK：32 字节，构建时注入植入体、`--psk` 给服务端；MAC 失败一律 403
- **明文 JSON 一律紧凑格式**（`separators=(",", ":")`，冒号后无空格）——植入体的极简解析器按此假设（这是真实联调抓出来的契约点）
- 传输层 v1 为明文 HTTP 回环（可插拔位：`http_post()` 是植入体唯一传输函数）；生产信道 v2 接入

消息流：

```
植入体 → POST /beacon   {"id","host","user","arch","sleep"}（每次注册，服务端重启自愈）
服务端 →               {"tasks":[{"id","type","args"}]}
植入体 → POST /result   {"results":[{"task_id","output","exit"}]}
服务端 →               {"ack":true}
```

任务类型 v1 仅 `cmd`（`args.command` 经 `cmd.exe /c` 执行，stdout+stderr 并管道捕获，上限 64KB，超时 60s）。

## 3. Operator API（camty 工作台契约）

认证 `Authorization: Bearer <token>`：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/sessions` | `{"sessions":[{id,host,user,arch,sleep,first_seen,last_seen}]}` |
| POST | `/api/sessions/{id}/tasks` | `{"type":"cmd","args":{"command":"..."}}` → `{"task_id"}` |
| GET | `/api/tasks/{task_id}` | `{"status":"queued\|running\|done","output","exit","command","session"}` |

camty 侧护栏（引擎自动生效，无需 C2 感知）：

- `c2-sessions`：范围外会话被过滤进 in_scope 列表
- `c2-task`：`requires_confirm + requires_finding` 双门控；下发前 `scope.require(会话主机)`
- 所有 operator 动作进 camty 审计哈希链

## 4. 加密实现正确性

植入体 C 侧自带实现，验证链：

1. KAT（`crypto_test.c`）：FIPS-197 AES-256 全零向量、SHA-256("abc")/空串、RFC 4231 HMAC 向量 1、CMT1 往返与篡改拒绝
2. **跨语言双向对拍**：C 解 Python seal ✓ / Python 解 C seal ✓
3. 真实 E2E（`tests/test_c2_implant.py`）：beacon.exe 注册 → camty 下发 → 执行回传 → 收集，含坏 PSK 403 拒绝

sbox/轮常量由算法推导（GF(2⁸) 逆元 + 仿射 / xtime），非手抄表——KAT 过即全对。

## 5. v1 明确不做（边界）

- 无持久化：进程消亡即掉线（重启靠 beacon 自动重注册，服务端会话自愈）
- IV 来自 `rand()`（GetTickCount 播种）；v2 换 BCryptGenRandom
- 无规避层：正常 PE、CreateProcess、明文 PE 元数据
- 无并发任务、无文件传输、无 socks（按需进 v2/v3）
- 存储在内存 + JSONL 动作日志（c2-ops.jsonl，无哈希链；operator 侧审计在 camty 已有链）

## 6. v2+ 路线（按优先级）

1. **传输可插拔落地**：HTTPS（rustls 风格可调栈对齐 JA4）或云 API 死信箱；malleable profile（URI/包头/节奏可配置）
2. **执行与内存**：回调执行（threadpool callback）、RW→RX 转换不留 RWX、sleep 休眠加密（ROP 变体，不抄公开实现）
3. **会话密钥**：每次 checkin 派生子密钥（HKDF(nonce)），前向保密
4. **CSRF 式任务模型扩展**：upload/download/screenshot/socks 任务类型
5. **服务端硬化**：任务结果哈希链、多 operator、TLS 终止在反向代理

## 7. 测试矩阵

| 测试 | 文件 | 覆盖 |
|---|---|---|
| 协议自测 | `python c2/server/protocol.py` | seal/open 往返、篡改拒绝 |
| 加密 KAT | `c2/implant/crypto_test.c` | AES/SHA/HMAC 已知答案 |
| 契约 E2E | `tests/test_c2_e2e.py` | 服务端 + 模拟 beacon + camty 适配器全链（scope 拦截、token 拒绝） |
| 真实 E2E | `tests/test_c2_implant.py` | beacon.exe 全链 + 坏 PSK 403 |
