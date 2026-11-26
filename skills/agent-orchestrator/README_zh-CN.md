# Agent Orchestrator v1.1 — 全自主优先，集成 grill-me / SDS / Superpowers

**默认：`AUTO_FIRST + FULL`。** 一个 Skill 入口，内置 grill-me 的自主深度质询和风险选择、计划与 SDS 独立审核、子 Agent 实施/代码审核、测试、断点恢复。无需单独安装 grill-me。原版 Superpowers 是可选增强，需要宿主实际支持并安装。

## 两种工作模式

| 流程节点 | AUTO_FIRST（默认） | HUMAN_GATE（备选） |
| --- | --- | --- |
| 仓库调查、计划初稿 | 自动 | 自动 |
| grill-me 追问 | 内部逐题挑战，自主选择有证据的可逆方案 | 同左 |
| 计划独立审核、修订、冻结 | 自动；记录 AUTO_FROZEN | 自动 |
| SDS 编写、独立审核、修订 | 自动 | 自动 |
| SDS 定稿 | 审核通过后自动冻结 | **人工批准具体版本** |
| 编码、测试、独立审查、打包 | 自动 | SDS 批准后自动 |
| 本地交付 | 自动 | 自动 |
| 正式对外发布/部署 | 必须已获得**明确、具体的操作授权**，否则只准备发布包 | 明确操作授权 + **发布前人工批准** |

注意：**全自主不等于无限权限。** 未授权的生产环境部署、公开发布、删除真实数据、付费操作、读取秘密或超出原始范围的更改都不能只凭模式名称自动执行。可以自动做好本地构建、审查、测试、制品打包和发布准备。

## 使用方式

安装完整 `agent-orchestrator/` 文件夹到客户端支持的 Skills 目录（不是只复制 SKILL.md）。常见 Codex 路径 `~/.agents/skills/agent-orchestrator/`；项目级 `.agents/skills/agent-orchestrator/`；其他客户端以其自身 Skill 加载支持为准。没有子 Agent 工具就不能凭 Markdown 凭空创建 Agent。

**默认全自主启动：**

```text
启动 agent-orchestrator，AUTO_FIRST + FULL 模式。读取当前项目，先写 PLAN 初稿，
内部自主运行 grill-me 挑战决策，随后独立审核计划并自动冻结；编写 SDS，
独立审核并自动冻结；生成实施任务、HANDOFF，按可用 Superpowers 能力
调度开发 Agent 和独立审查 Agent；自动执行测试、集成和本地制品交付。
只在授权边界、无法解决的阻塞问题或高风险动作时询问我。
```

**备选：只在 SDS 与最终发布停下来审批：**

```text
启动 agent-orchestrator，HUMAN_GATE + FULL 模式。自动完成计划、内部 grill-me、
计划审核和 SDS 审查；在 SDS 最终冻结前请我批准具体修订版。
批准后自动实施、测试和审核；正式对外发布前再次请我批准。
```

**希望亲自回答 grill-me 时：**

```text
切换 INTERACTIVE_GRILL，逐次仅问我一个重要问题并提供推荐答案和原因。
答完后恢复 AUTO_FIRST。
```

**继续任务：**

```text
启动 agent-orchestrator RESUME，读取 docs/agent-orchestrator/HANDOFF.md
及 AUTONOMY.md、STATE.md，检查 Git / SDS 冻结版本和任务证据，
从未完成任务继续，无需重新问已经解决的决定。
```

## 关于新会话及连续执行

SDS 冻结后必须写 `HANDOFF.md`，**但默认不强制停止工作等用户开新会话**：宿主若能自动创建独立上下文就用；否则调用可用的隔离子 Agent；两者都没有则主会话保持文件化短上下文继续执行。不要虚构客户端支持的功能，也不能保证真正离线后台工作或连续运行一天。

## 目录

```text
agent-orchestrator/
├── SKILL.md
├── README_zh-CN.md
├── references/
│   ├── AUTONOMY_PROTOCOL.md
│   ├── GRILL_ENGINE.md
│   ├── SDS_STANDARD.md
│   └── REVIEW_AND_AGENT_PROTOCOL.md
├── assets/                 # 含 AUTONOMY、PLAN、SDS、HANDOFF 等模板
├── scripts/init_project.py
└── tests/test_skill_contract.py
```

**可选项目初始化（默认预览，不覆盖已有文档）：**

```bash
python agent-orchestrator/scripts/init_project.py --project /path/to/project
python agent-orchestrator/scripts/init_project.py --project /path/to/project --apply
```

**原始参考思想：** grill-me: https://github.com/mattpocock/skills ； Superpowers: https://github.com/obra/superpowers 。本 Skill 是独立编写的融合流程，不包含它们的上游源码，不是官方发布版本。
