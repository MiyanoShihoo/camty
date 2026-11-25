"""方法论技能查询适配器：LLM worker 自主调用——按主题/名称检索内置技能库。

技能库在仓库 skills/ 目录（网安全谱：逆向/渗透/C2/云/AD/取证/无线/供应链…），
fresh clone 自带；CAMTY_SKILL_EXTRA_DIRS（os.pathsep 分隔）可追加本地目录。
"""

from __future__ import annotations

import os
from pathlib import Path

from camty.adapters.base import RunContext, ToolAdapter, ToolResult

MAX_SKILL_CHARS = 6000   # 单技能正文回传上限（runner 层还有 TOOL_RESULT_LIMIT 截断）
MAX_HITS = 3             # 主题检索最多回传技能数
EXCERPT_CHARS = 1800     # 非首位命中的摘录长度


class SkillLookupAdapter(ToolAdapter):
    name = "skill-lookup"
    description = (
        "检索内置红队方法论技能库（40+ 网安技能：逆向/渗透/C2/云/AD/取证/无线/供应链…）。"
        "面对不熟悉的攻击面或打法卡住时主动调用：按主题词（如 xss、ssrf、反序列化、"
        "横向移动、免杀、固件、协议逆向）或精确技能名检索，返回最匹配技能的要点正文。"
        "只读本机知识库，不发任何网络请求。"
    )

    def available(self) -> bool:
        return True  # 知识查询无外部工具依赖

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "topic": {"type": "string",
                          "description": "主题词，支持中英（如 xss / 反序列化 / ssrf / 横向移动 / evasion；英文无命中时换中文重试）"},
                "name": {"type": "string",
                         "description": "精确技能名（可选，如 api-security / pwn-chain）"},
            },
            "required": [],
        }

    # ---- 技能库定位 ----

    def _roots(self) -> list[Path]:
        here = Path(__file__).resolve()
        candidates = [
            here.parent.parent.parent / "skills",  # 仓库根：camty/adapters/ 上两级
            Path.cwd() / "skills",                 # 从仓库根启动的兜底
        ]
        roots: list[Path] = []
        for c in candidates:
            if c.is_dir():
                r = c.resolve()
                if r not in roots:
                    roots.append(r)
        for extra in os.environ.get("CAMTY_SKILL_EXTRA_DIRS", "").split(os.pathsep):
            if extra.strip():
                p = Path(extra.strip())
                if p.is_dir():
                    roots.append(p)
        return roots

    def _read_skill(self, skill_dir: Path) -> str:
        md = skill_dir / "SKILL.md"
        if not md.is_file():
            return ""
        try:
            return md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    # ---- 主入口 ----

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        name = str(args.get("name", "")).strip()
        topic = str(args.get("topic", "")).strip().lower()
        if not name and not topic:
            return ToolResult(summary="topic 与 name 均为空", data={"hits": []})
        roots = self._roots()

        # 1) 精确名命中
        if name:
            for root in roots:
                d = root / name
                if d.is_dir():
                    body = self._read_skill(d)[:MAX_SKILL_CHARS]
                    return ToolResult(
                        summary=f"技能 {name}（{len(body)} 字符正文）",
                        data={"hits": [{"name": name, "path": str(d), "content": body}]},
                    )
            return ToolResult(summary=f"未找到名为 {name} 的技能", data={"hits": []})

        # 2) 主题词检索：名称 > frontmatter 描述 > 正文
        scored: list[tuple[int, str, Path]] = []
        for root in roots:
            if not root.is_dir():
                continue
            for d in sorted(p for p in root.iterdir() if p.is_dir()):
                body = self._read_skill(d)
                if not body:
                    continue
                low = d.name.lower()
                head = body[:400].lower()
                full = body.lower()
                if topic in low:
                    score = 100
                elif topic in head:
                    score = 50
                elif topic in full:
                    score = 20
                else:
                    continue
                scored.append((score, d.name, d))
        scored.sort(key=lambda x: (-x[0], x[1]))
        hits = []
        for i, (score, sname, d) in enumerate(scored[:MAX_HITS]):
            body = self._read_skill(d)
            content = body[:MAX_SKILL_CHARS] if i == 0 else body[:EXCERPT_CHARS]
            hits.append({"name": sname, "path": str(d), "content": content})
        summary = f"主题 '{topic}' 命中 {len(hits)} 个技能: {', '.join(h['name'] for h in hits)}" if hits \
            else f"主题 '{topic}' 无命中"
        return ToolResult(summary=summary, data={"hits": hits})
