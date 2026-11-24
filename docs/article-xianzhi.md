# Camty：证据链优先的红队交战工作台——从架构到实战

## 前言

在过去的渗透测试实践中，我一直在思考一个问题：**为什么攻击工具遍地都是，但"证据链"始终靠手工拼？** 从侦察到利用到横向到报告，每一步的产出散落在终端输出、截图、Burp 历史、脑内记忆里。事后写报告时，要么凭记忆拼凑，要么翻半天终端 scrollback。

Camty 的出发点很朴素：**把一次渗透测试的全部动作纳入一条可审计的流水线，证据链自动生长，报告是自然产物而非事后作业。**

本文不讲功能列表（GitHub README 有了），讲三个核心设计决策和它们在真实交战中的表现。

## 核心设计一：证据链优先（Evidence-Chain-First）

### 问题

传统工具的输出是"信息"，不是"证据"。信息不构成结论：nuclei 命中了一个 CVE 模板，但你不知道这条命中是哪次扫描、什么参数、什么响应产生的。报告时要么信任工具输出，要么重新验证。

### 方案

Camty 把每个动作强制纳入四层治理：

```
scope 白名单 → 动作执行 → 审计哈希链 → 证据台账
    ↓                ↓            ↓            ↓
 deny-by-default   落盘证据     防篡改       血缘关联
```

**范围白名单**（`guardrail/scope.py`）：deny-by-default，域名先 DNS 解析再校验 IP 防形似目标绕过。授权范围外的目标在引擎层直接拒绝——不是提示，是拒绝。

**审计哈希链**（`guardrail/audit.py`）：每个动作一条 JSONL 记录，上一条记录的 SHA-256 摘要嵌入当前记录。篡改任何一条，后续哈希全部断裂。`camty audit` 命令可实时验链。这在护网场景中意味着：蓝队拿到红队的审计文件，可以验证红队声称的操作范围与实际操作范围是否一致。

**证据台账 + 血缘**（`agent/state.py`）：每个"发现"（finding）进台账时带血缘字段。例如：

```
F-001 [vuln][high] kerberoastable-spn（验证发现）
F-005 [access][high] captured-ntlm-hash ← F-001（利用发现，引用 F-001）
```

血缘关系不是装饰。它驱动一个硬门控：**利用级动作（secretsdump、lateral-move 等）必须在参数中引用台账中已验证发现的 ID，否则引擎拒绝执行。** 这意味着你不可能"跳过验证直接打"——引擎替你守住了方法论底线。

### 实战表现

在一次对 Go+GORM 后端站点的交战中，25+ 条攻击线全部排除（注入参数化、越权有权限门、JWT 随机密钥 13 万字典未中……）。这个"没找到洞"的结论本身就是报告的核心交付物——台账中的每条排除记录都带证据文件路径和审计链验证，支撑"这些方向确实测过了"的结论。

## 核心设计二：双图认知 + 多 Agent 引擎

### 问题

LLM 驱动的自动化渗透有一个致命缺陷：**会话无状态**。每次调用 LLM 都从零开始，没有"我测过了什么、还剩什么没测"的概念。GPT 帮你扫描一次没问题，但十步攻击链就会开始重复或遗漏。

### 方案

Camty 借鉴了"双图"架构：

**资产图**（`agent/assets.py`）：交战的真值库。节点为 root_domain / subdomain / host / service / endpoint，父子关系程序自动推导（子域→根域、端点→服务）。覆盖度回答"测了多少、剩多少"。

**探索图**（`agent/explore.py`）：推进过程。节点为 goal / intent / fact / finding，边为 spawns / yields / proves。回答"哪个方向派生自哪些事实、产出了什么"。

在这两张图之上，多 agent 引擎（`agent/engine.py`）运行：

```
LLM 规划者 → 读取台账+资产覆盖度 → 生成攻击链 todolist
     ↓
N 个 worker 并行 → 领取意图 → 执行 → 写回双图
     ↓
图变更触发 → 规划者重读态势 → 更新 todolist → 下一轮
```

关键机制：
- **todolist 跨轮常驻**：规划者每次会话无状态，但 todolist 持久化在 SQLite 中，依赖关系跨轮保留
- **限流退避**：LLM 请求失败后按次数退避（实战校准：某 Free 分组限流窗口约 60 秒）
- **降级兜底**：连续 3 次规划失败后，引擎自动降级为确定性 pack 模式继续执行——LLM 不可用不阻塞交战
- **人在环路**（`guardrail/steer.py`）：operator 通过面板随时注入转向指令，worker 下一轮消费——不阻塞引擎、消费即标记、断点续跑不重复注入

### 实战表现

在一次交战测试中，GLM-5.3 作为规划者展现了**台账感知**：它读取台账后发现已有 3 条发现（账号突破、leaderboard 测绘、攻击线排除），自动将它们标记为已完成步骤，然后基于剩余资产覆盖度规划下一步（68 个端点的认证态遍历）。这是"跨轮稳定攻击链"语义的真实体现——不是靠 prompt 工程模拟的，是靠数据结构支撑的。

## 核心设计三：对抗层不是附加品

### 问题

很多"自动化渗透框架"本质上是 nmap + sqlmap + nikto 的 subprocess 调用包装。问题：**目标有 WAF、有 CF、有 bot 检测怎么办？**

### 方案

Camty 的对抗层是内建的，不是外挂：

**HTTP 指纹伪装**（`modules/http_fp.py`）：全部纯 HTTP 流量（侦察/注入/越权/secret 扫描）走 curl_cffi 的 Chrome TLS/HTTP2 指纹。某 LLM API 网站的 CF 部署对 Python urllib 直接 403（error 1010），Chrome 指纹秒过。

**浏览器 stealth 三态**（`adapters/browser.py`）：`auto / true / false`。实战发现：**stealth 注入与 Turnstile 互斥**（chrome runtime 伪装破坏 CF 脚本环境，token 永不签发）。auto 模式默认关闭注入，visit 自动探测 Turnstile 组件并输出下一步建议。这个结论写进了代码注释——下次不再踩坑。

**注入七变体 + chunked**（`modules/inj_probe.py`）：大小写混淆 / 内联注释 / 注释分拆 / URL 编码 / 双重编码 / HPP 参数污染 / chunked 传输。evasion 开关默认关——对正常目标保持克制，WAF 在场时显式开启。

**MITM 流量留痕**（`traffic.py`）：自研 MITM 代理，CA + 按域动态叶子证书，HTTPS 解密落盘。一条纪律：**留痕先于响应**——调用方收到 200 时记录必然已落盘（审计完整性语义）。范围外主机 403 纵深拦截。

## 交战产出

```
HTML 报告（资产覆盖度 + 血缘链 + 探索图 + 流量统计）
docx 报告（docx 格式，可直接交客户）
SRC 平台提交格式（按 finding 逐条：级别/复现/POC/修复建议映射）
复测对比报告（上次 vs 本次，新增/已修复/仍存在）
IM 推送（飞书/钉钉/企微/TG——high/critical 实时通知）
```

## 诚实的边界

Camty 不会让你一夜拿下 0day。它的价值在于：

1. **可审计**：每一步有证据、有链、有血缘——护网复盘和法律合规的底气
2. **可复现**：断点续跑 + pack 确定性链——同命令同结果
3. **可扩展**：41 适配器覆盖侦察→注入→越权→AD→C2，接入外部 MCP 工具源
4. **对抗就绪**：Chrome 指纹 + stealth + evasion + MITM——不是从零拼

**它不会自动找到洞**。它自动的是"过程"——范围管控、证据归档、台账维护、报告生成。找洞仍然需要方法论和经验，但 Camty 保证你的经验不散落在终端 scrollback 里。

## 开源

GitHub: https://github.com/MiyanoShihoo/camty

Apache License 2.0，仅供已获明确书面授权的安全测试与研究使用。

## 技术栈

Python 3.12+，核心依赖仅 PyYAML + FastAPI（面板）+ curl_cffi（指纹伪装）。41 个适配器中 13 个为自研纯 Python 模块，其余包装外部工具（subfinder/httpx/nuclei/fscan/hashcat 等）。C2 植入体为纯 C（零依赖 AES/SHA/HMAC，WinHTTP/schannel 加密信道），服务端单文件 Python。245 项测试覆盖核心逻辑与真实 TLS MITM E2E。
