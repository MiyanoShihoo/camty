"""自然语言目标分解（ARTEX goals 语义）：一句话任务 → 交战配置。

流程：
1. LLM 从任务描述提取：目标资产（root_domain/cidr）、操作约束（deny/allow，
   自包含写死具体值，只登记明确写出的、拿不准归 deny）、最终目标拆分。
2. 本地确定性分类器把约束映射为可硬执行的手段：
   - no-portscan  → rules.extra 全量 deny fscan
   - no-bruteforce→ rules.extra 全量 deny cred-test
   - no-write     → authz-probe 写操作回退确认（authz.write_confirm）
   - manual       → 仅注入 planner/worker/retester 提示词（scope 仍是硬边界）
3. build_engagement 产出可直接落盘的交战 YAML；constraints 段全程注入决策面。
"""

from __future__ import annotations

import json
import re

from camty.agent.state import Engagement
from camty.llm.router import ROLE_DECIDE, LLMRouter

GOALS_TIMEOUT = 150.0

GOALS_SYSTEM = """你是渗透测试目标分解器。从用户输入中识别**最终要达成的结果**，而不是规划攻击步骤。

第一步（拆分目标之前先做）：抽取操作约束
- 从任务描述里识别操作员对【可以做什么、不可以做什么】的明确规定。
- type=deny：禁止的操作（如「不扫端口」「不得做写操作」「禁止爆破」「不碰某子域」）。
- type=allow：明确允许/限定的操作范围（如「只允许被动侦察」「仅针对某域名」）。
- 约束 ≠ 目标，也 ≠ 攻击步骤：它是对操作行为边界的规定。
- 约束必须【自包含、写死具体目标】：把「当前目标/本站/该域名」这类指代词替换成任务
  描述里的具体值。例：目标是 https://abc.example.net → 写「只允许测试 abc.example.net」
  而不是「只允许测试当前目标」。
- 只登记任务描述里【明确写出或强调】的约束，严禁臆造；拿不准类型时用 deny（更保守）。
- 描述里没有操作约束就不输出 constraints。

第二步：识别目标资产
- root_domain：主域名（如 abc.example.net）；cidrs：网段（如 10.0.0.0/24）。
- 只登记任务描述里明确出现的目标，不推断未提及的资产。
- 同时出现域名与网段时都登记，pack 会选 int-ad。

第三步：目标拆分
- goals 是最终要达成的结果（如「取得 abc.example.net 的已验证 Web 漏洞清单」），
  不是攻击步骤。每个目标给 done_when 判定标准。

只输出 JSON，无其它文本。输出格式：
{"root_domain": "", "cidrs": [], "extra_domains": [],
 "constraints": [{"type": "deny", "rule": "不扫描 abc.example.net 的 80/8080 以外端口"}],
 "goals": [{"title": "取得已验证漏洞清单", "done_when": "台账存在 ≥1 个 verified vuln finding"}],
 "suggested_pack": "ext-web", "name": "abc-web"}"""

_CONSTRAINT_CATEGORIES: list[tuple[str, str, tuple[str, ...], str]] = [
    # (类别, 分类正则, 全量 deny 的适配器元组, 规则说明)
    ("no-portscan", r"端口|port\s*scan|fscan|masscan", ("fscan",),
     "约束：禁止端口扫描"),
    ("no-bruteforce", r"爆破|喷洒|spray|brute", ("cred-test",),
     "约束：禁止凭据爆破/喷洒"),
]

_WRITE_SQL_PATTERN = r"\b(update\s+\w+\s+set|insert\s+into)\b"


def classify_constraint(rule: str) -> tuple[str, tuple[str, ...]]:
    """确定性分类：返回（类别, 全量 deny 的适配器元组）。manual = 仅提示词注入。"""
    for category, pattern, adapters, _ in _CONSTRAINT_CATEGORIES:
        if re.search(pattern, rule, re.I):
            return category, adapters
    if re.search(r"写操作|写入|修改(数据|记录)|上传", rule, re.I):
        return "no-write", ()
    return "manual", ()


def _decision_to_rules(constraints: list[dict]) -> list[dict]:
    """约束 → 规则门（可机械执行的部分）。deny/allow 约束都按 deny 规则处理。"""
    extra: list[dict] = []
    seen: set[str] = set()
    for constraint in constraints or []:
        rule_text = str(constraint.get("rule", "")).strip()
        if not rule_text:
            continue
        category, adapters = classify_constraint(rule_text)
        if category == "manual" or category in seen:
            continue
        seen.add(category)
        if category == "no-write":
            # 写操作禁令：deny 写类 SQL 语句（读类 SELECT 不受影响）
            extra.append({
                "id": "nl-no-write",
                "description": rule_text[:120],
                "applies": ["sqli-exploit", "inj-probe", "c2-task", "lateral-move"],
                "pattern": _WRITE_SQL_PATTERN,
            })
            continue
        extra.append({
            "id": f"nl-{category}",
            "description": rule_text[:120],
            "applies": list(adapters),
            "pattern": r"^",  # 序列化参数非空即命中 → 全量 deny
        })
    return extra


def _suggested_pack(decision: dict) -> str:
    if decision.get("cidrs"):
        return "int-ad"
    return str(decision.get("suggested_pack") or "ext-web")


def _slug_name(decision: dict) -> str:
    name = str(decision.get("name") or "").strip()
    if name:
        return re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")[:40] or "nl-engagement"
    domain = str(decision.get("root_domain") or "").strip()
    if domain:
        return re.sub(r"[^A-Za-z0-9_-]+", "-", domain).split("-")[0][:30] or "nl-engagement"
    return "nl-engagement"


def decompose(router: LLMRouter, text: str) -> dict:
    """任务描述 → 结构化决策（targets/constraints/goals）。LLM 失败抛 LLMError。"""
    resp = router.chat(ROLE_DECIDE, [
        {"role": "system", "content": GOALS_SYSTEM},
        {"role": "user", "content": text},
    ], None, timeout=GOALS_TIMEOUT)
    content = resp.get("content") or ""
    start, end = content.find("{"), content.rfind("}")
    if start < 0 or end <= start:
        raise ValueError(f"目标分解输出不可解析: {content[:200]}")
    decision = json.loads(content[start:end + 1])
    if not decision.get("root_domain") and not decision.get("cidrs"):
        raise ValueError(
            "任务描述中未识别出目标资产（root_domain / cidrs）。"
            "请在描述里明确授权目标，范围白名单是硬边界。")
    return decision


def build_engagement(decision: dict) -> dict:
    """决策 → 交战配置 dict（可直接 yaml 落盘）。"""
    domains = []
    root = str(decision.get("root_domain") or "").strip()
    if root:
        domains.append(root)
    for extra_domain in decision.get("extra_domains") or []:
        extra_domain = str(extra_domain).strip()
        if extra_domain and extra_domain not in domains:
            domains.append(extra_domain)
    constraints = [c for c in decision.get("constraints") or [] if c.get("rule")]
    extra_rules = _decision_to_rules(constraints)
    goals = decision.get("goals") or []
    cfg: dict = {
        "name": _slug_name(decision),
        "pack": _suggested_pack(decision),
        "scope": {
            "domains": domains,
            "cidrs": [str(c) for c in decision.get("cidrs") or []],
            "min_interval_seconds": 1,
        },
        "constraints": constraints,
    }
    if root:
        cfg["root_domain"] = root
    cidrs = decision.get("cidrs") or []
    if cidrs:
        cfg["target_cidr"] = str(cidrs[0])
    if extra_rules:
        cfg["rules"] = {"extra": extra_rules}
    if any(classify_constraint(c["rule"])[0] == "no-write" for c in constraints):
        cfg["authz"] = {"write_confirm": True}
    if goals:
        cfg["objective"] = {
            "title": goals[0].get("title", ""),
            "min_verified_findings": 1,
        }
    return cfg


def constraints_prompt(cfg: dict) -> str:
    """操作约束 → 注入决策面（planner/worker/retester）的提示段。无约束返回空。"""
    constraints = cfg.get("constraints") or []
    if not constraints:
        return ""
    lines = [
        f"- [{c.get('type', 'deny')}] {c.get('rule', '')}".rstrip()
        for c in constraints if c.get("rule")
    ]
    return "操作约束（操作员明确规定，违反即越界）:\n" + "\n".join(lines)


def save_engagement(decision: dict, path) -> str:
    """决策 → 交战 YAML 落盘，并验证 Engagement 可加载。返回路径。"""
    import yaml

    cfg = build_engagement(decision)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False),
                    encoding="utf-8")
    # 落盘即验证：pack 存在 + scope 非空（Engagement 构造会抛出明确错误）
    Engagement(path)
    return str(path)
