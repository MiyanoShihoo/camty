"""方法论技能查询适配器：LLM worker 自主调用——按主题/名称检索内置技能库。

技能库在仓库 skills/ 目录（网安全谱：逆向/渗透/C2/云/AD/取证/无线/供应链…），
fresh clone 自带；CAMTY_SKILL_EXTRA_DIRS（os.pathsep 分隔）可追加本地目录。
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from camty.adapters.base import RunContext, ToolAdapter, ToolResult

MAX_SKILL_CHARS = 6000   # 单技能正文回传上限（runner 层还有 TOOL_RESULT_LIMIT 截断）
MAX_HITS = 3             # 主题检索最多回传技能数
EXCERPT_CHARS = 1800     # 非首位命中的摘录长度

# 中英术语别名表（EN↔CN 双向，红队常用词）。worker 常用英文主题查询而技能库
# 正文多为中文，整词匹配全落空——查询时自动把 topic 展开为 {原词, 命中别名}
# 集合逐一匹配（同组互为别名），命中分数：原名 > 别名。
TERM_ALIAS_GROUPS: list[tuple[str, ...]] = [
    ("password reset poisoning", "密码重置投毒"),
    ("password reset", "密码重置"),
    ("deserialization", "反序列化"),
    ("ssrf", "服务端请求伪造"),
    ("lateral movement", "横向移动"),
    ("xss", "跨站脚本"),
    ("sql injection", "sql注入"),
    ("command injection", "命令注入"),
    ("file read", "文件读取"),
    ("path traversal", "路径穿越"),
    ("privilege escalation", "提权"),
    ("c2", "命令与控制"),
    ("edr bypass", "edr绕过", "免杀"),
    ("reverse engineering", "逆向"),
    ("fuzzing", "模糊测试"),
    ("forensics", "取证"),
    ("brute force", "爆破"),
    ("phishing", "钓鱼"),
    ("mitm", "中间人"),
    ("idor", "越权"),
    ("jwt", "json web token"),
    ("oauth", "认证授权"),
    ("waf", "web应用防火墙"),
    ("rce", "远程代码执行"),
    ("upload", "文件上传"),
    ("xxe", "xml外部实体注入"),
    ("orchestrator", "编排", "多智能体协作", "任务编排"),
]

# 双向索引：词 → 同组别名列表
_ALIAS_MAP: dict[str, list[str]] = {}
for _group in TERM_ALIAS_GROUPS:
    for _term in _group:
        _bucket = _ALIAS_MAP.setdefault(_term, [])
        for _other in _group:
            if _other != _term and _other not in _bucket:
                _bucket.append(_other)

# 短 ASCII 词用词边界匹配（防止 "rce" 命中 "force"、"c2" 命中 "sc2" 这类子串误伤）
_SHORT_KEY_RES = {
    key: re.compile(r"(?<![a-z0-9])" + re.escape(key) + r"(?![a-z0-9])")
    for key in _ALIAS_MAP if key.isascii() and len(key) <= 5
}


def _expand_terms(topic: str) -> list[str]:
    """topic → [原词, 命中的别名...]：表内任一方向的词出现在 topic 中即带上同组别名。"""
    terms = [topic]
    for key, aliases in _ALIAS_MAP.items():
        matcher = _SHORT_KEY_RES.get(key)
        hit = bool(matcher.search(topic)) if matcher else key in topic
        if hit:
            for alias in aliases:
                if alias not in terms:
                    terms.append(alias)
    return terms


def _term_score(term: str, low: str, head: str, full: str) -> int:
    """词频档位分（沿用既有评分结构）：名称100 / 头部50 / 正文20；未命中0。"""
    if term in low:
        return 100
    if term in head:
        return 50
    if term in full:
        return 20
    return 0


# 别名命中分：同档低于原名（原名>别名），名称90 / 头部40 / 正文10
_ALIAS_SCORE_BY_TIER = {100: 90, 50: 40, 20: 10}


class SkillLookupAdapter(ToolAdapter):
    name = "skill-lookup"
    description = (
        "检索内置红队方法论技能库（40+ 网安技能：逆向/渗透/C2/云/AD/取证/无线/供应链…"
        "及 agent-orchestrator 编排方法论：多智能体协作/方案评审/SDS 设计规格）。"
        "面对不熟悉的攻击面或打法卡住时主动调用：按主题词（如 xss、ssrf、反序列化、"
        "横向移动、免杀、固件、协议逆向、多智能体协作）或精确技能名检索，"
        "返回最匹配技能的要点正文。只读本机知识库，不发任何网络请求。"
    )

    def available(self) -> bool:
        return True  # 知识查询无外部工具依赖

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "topic": {"type": "string",
                          "description": "主题词，支持中英（如 xss / 反序列化 / ssrf / 横向移动 / evasion）。"
                                         "中英术语别名自动展开匹配（如 password reset poisoning 会同时检索 密码重置投毒）"},
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

        # 2) 主题词检索：名称 > frontmatter 描述 > 正文；topic 自动展开别名（原名分 > 别名分）
        aliases = _expand_terms(topic)[1:]
        scored: list[tuple[int, str, Path, str]] = []
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
                score = _term_score(topic, low, head, full)
                matched = topic
                if not score:
                    for alias in aliases:  # 同一技能只计一次，取最高档别名
                        tier = _term_score(alias, low, head, full)
                        if tier and _ALIAS_SCORE_BY_TIER[tier] > score:
                            score = _ALIAS_SCORE_BY_TIER[tier]
                            matched = alias
                if not score:
                    continue
                scored.append((score, d.name, d, matched))
        scored.sort(key=lambda x: (-x[0], x[1]))
        hits = []
        for i, (score, sname, d, matched) in enumerate(scored[:MAX_HITS]):
            body = self._read_skill(d)
            content = body[:MAX_SKILL_CHARS] if i == 0 else body[:EXCERPT_CHARS]
            hits.append({"name": sname, "path": str(d), "matched": matched, "content": content})
        summary = f"主题 '{topic}' 命中 {len(hits)} 个技能: {', '.join(h['name'] for h in hits)}" if hits \
            else f"主题 '{topic}' 无命中"
        return ToolResult(summary=summary, data={"hits": hits})
