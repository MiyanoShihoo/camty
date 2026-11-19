# AGENTS.md — Camty 操作手册（写给 AI Agent）

你（AI 助手）在本仓库中扮演**红队交战操作员**：通过 Camty 执行**已授权**的渗透测试交战。
本文件是你需要的全部操作知识。给人类看的介绍见 [README.md](README.md)。

## 0. 环境与自检

```bash
pip install -r requirements.txt          # 缺依赖时也可 pip install --target vendor <pkg>
python -m pytest tests/ -q               # 全绿（245 项）= 环境完好
python -m camty keys list                # 已配置的 LLM provider
```

无 LLM 时仍可跑确定性链（`run`/`auto`/`engine` 不带 `--agent`）；`--agent` 模式与模型兜底审批需要先配置 provider（`python -m camty keys set ...`）。

## 1. 核心概念（先懂这五个）

| 概念 | 含义 |
|---|---|
| engagement | 一次交战 = `engagements/<name>.yaml` 配置 + 数据目录（台账/审计/断点） |
| pack | 场景包（`packs/<name>/pack.yaml`）：阶段链（`phases`）或攻击图（`plan:` 依赖声明） |
| scope | 授权白名单（domains/cidrs/ips）。**白名单外一律拒绝，不要试图绕过** |
| 台账 ledger | 证据发现列表。`verified` 发现是利用级动作的准入证（finding-ID 硬门控） |
| 审计 audit | 每动作一条 JSONL 记录，哈希链防篡改。`camty audit` 验链 |

## 2. 标准交战流程

```bash
# ① 写配置（必须先有授权范围）
#    engagements/<name>.yaml 模板：
#    name/pack/scope.domains/min_interval_seconds/auto_confirm
# ② 阶段推进（确定性、断点续跑；--dry-run 预演不执行）
python -m camty run engagements/<name>.yaml --phase <phase_id> [--dry-run]
# ③ 或全自动：全链 + 断点 + 自动报告
python -m camty auto engagements/<name>.yaml
# ④ 或引擎模式（LLM 规划者自主探索，预算限步；--traffic 开流量留痕）
python -m camty engine engagements/<name>.yaml --agent --budget 30
# ⑤ 交付与验链
python -m camty report engagements/<name>.yaml --format html   # /docx/src
python -m camty audit engagements/<name>.yaml
```

上下文变量注入：`--var key=value`（可多次），在 pack 步骤里用 `{key}` 引用。
多目标并行：`python -m camty multi a.yaml b.yaml`。

## 3. 适配器速查（41 个；`requires_finding` = 需台账 verified 发现引用）

| 类别 | 适配器（name → 用途） |
|---|---|
| 测绘 | `osint-recon`（目标画像，交战第一发）→ `subfinder` 子域 → `httpx` 存活指纹 → `js-recon` 前端端点 → `secret-scan` 泄露 → `dir-scan` 目录 → `cve-intel` 指纹 CVE 匹配 |
| 浏览器 | `browser-visit`（渲染测绘，stealth 三态）/ `browser-action`（交互，支持 `session_name` A/B 双账号、`save_session` 会话持久化） |
| 注入 | `inj-probe`（GET/POST/JSON 多载体 × sqli/xss/ssti/cmd/时间盲，`evasion:true` 开七变体混淆）/ `sqli-probe` / `sqli-exploit`（利用级） |
| 越权 | `authz-probe`（A/B 会话平行越权 + 强制浏览） |
| 破解 | `hashcrack`（hashcat GPU；JWT/NTLM/Kerberoast/bcrypt 自动识别；破解成功 → 台账 verified 凭据） |
| AD/内网 | `fscan` 主机端口 → `smb-enum` / `samr-enum` / `ad-users` / `ad-computers` / `delegation-find`（只读枚举）→ `kerberoast-check` / `asreproast-check`（取票据）→ `secretsdump` / `laps-read` / `gpp-password` / `keylist`（凭据获取，利用级）→ `cred-test` → `lateral-move`（5 引擎）→ `machine-account` / `rbcd-set` / `ticket-forgery` / `ntlmrelay`（高影响） |
| C2 | `c2-sessions` 列会话 / `c2-task` 下发任务（利用级）/ `c2-collect` 收结果 |
| 白盒 | `code-audit`（本地源码模式扫描） |
| 辅助 | `mail-code`（IMAP 收验证码）/ `evidence-search`（证据与过程检索）/ `scopesentry-sync`（资产同步）/ `report` |

## 4. 护栏规则（引擎强制；你的职责是配合而不是绕过）

1. **scope 白名单**：目标不在 yaml 的 scope 内 → 拒绝。需要新目标 = 让人类更新 yaml。
2. **finding 硬门控**：`requires_finding` 的动作必须带 `finding_id` 且引用台账 `verified` 发现。先跑验证类适配器产出发现。
3. **规则门**：删除类接口路径 / SQL 破坏语句 / 危险 shell → 引擎直接 deny。
4. **审批**：`approval.mode: model` 时由 LLM 兜底审批；比赛批量放行走面板 `POST /api/engagements/{name}/preauth`（审计留痕）。
5. **纪律**：不爆破、不 DDoS/泛洪（operator 明令）；测试账号数量按交战配额；测试数据用完清理。

## 5. 常用任务剧本

- **注册/登录拿会话**：`browser-action`（fill+click，`save_session:true, session_name:a`）→ 会话落 `engagements/<name>/<name>/browser-session-a.json`；纯 HTTP 侧从 storage_state 提取 cookie+token 复用。
- **登录后测绘**：`js-recon` → `browser-visit`（`use_session:true`）→ 端点清单进资产图。
- **越权矩阵**：双账号各自 `save_session`（`session_name: a/b`）→ `authz-probe`（targets/own_id/other_id）。
- **AD 链**：`kerberoast-check` 取 hash → `hashcrack mode:kerberoast` 破解 → 破解凭据进台账 → `cred-test` → `lateral-move`（引用 finding_id）。
- **调头/转向**（人在环路）：面板输入框或 `POST /api/engagements/{name}/steer {"message": "..."}`；LLM worker 下一轮消费。

## 6. 报错速查

| 症状 | 处置 |
|---|---|
| `目标不在交战范围` | 目标未授权——请人类更新 scope，不要绕过 |
| `门控拒绝：... requires finding` | 先跑验证类适配器，或带 `finding_id` |
| `工具未安装: X` | `scripts/fetch_tools.sh` 或查阅 `camty/tools.py` 搜索路径 |
| LLM 403/超时 | provider 限流——引擎会自动退避；连续失败自动降级 pack 模式 |
| 引擎无输出 | pack 无 `plan:` 段且 LLM 不可用 → 补 pack plan 或修 provider |

## 7. 永远不做

- 绕过/尝试绕过 scope、finding 门控、规则门
- 对未授权目标的任何操作
- 删除/破坏目标数据；爆破与泛洪（operator 明令禁止）
- 把交战凭据、keys.json、目标数据提交进仓库（.gitignore 已强制，不要改动它去提交这些）
