"""动作规则门：内置破坏性规则 deny + 交战配置扩展规则。

ARTEX 拦截审批思路的确定性落地：序列化参数过规则匹配，命中 deny 直接拒绝
（审计留痕），不做模糊判断。规则域 applies 指定适用的适配器名列表。
"""

from __future__ import annotations

import json
import re

BUILTIN_RULES: list[dict] = [
    {
        "id": "http-delete-path",
        "description": "删除类接口路径（GET/POST 也能触发真实删除）",
        "applies": ("browser-action", "browser-visit", "c2-task", "inj-probe",
                     "dir-scan", "sqli-exploit", "lateral-move"),
        "pattern": r"/(delete|del|remove|unlink|erase|destroy|wipe|purge)(?=[/?&=._\"'-]|$)",
        "flags": re.I,
    },
    {
        "id": "sql-destructive",
        "description": "SQL 破坏性语句（DROP/TRUNCATE/DELETE FROM）",
        "applies": ("sqli-exploit", "inj-probe", "browser-action", "c2-task", "lateral-move"),
        "pattern": r"\b(drop\s+(table|database|schema)|truncate\s+table|delete\s+from)\b",
        "flags": re.I,
    },
    {
        "id": "shell-destructive",
        "description": "破坏性 shell 命令（rm -rf / mkfs / format / fork 炸弹）",
        "applies": ("c2-task", "lateral-move"),
        "pattern": r"(rm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)|mkfs(\.\w+)?\b|shutdown\s+/s|format\s+[a-z]:|:\(\)\{.*\};:)",
        "flags": re.I,
    },
    {
        "id": "cloud-metadata-ssrf",
        "description": "云元数据端点（SSRF 打实例凭据）",
        "applies": ("browser-visit", "browser-action", "js-recon", "inj-probe", "httpx"),
        "pattern": r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)",
        "flags": 0,
    },
]


def active_rules(cfg: dict) -> list[dict]:
    """内置规则 - 交战禁用项 + 交战扩展规则。"""
    rules_cfg = cfg.get("rules", {}) or {}
    disabled = set(rules_cfg.get("disable", []) or [])
    rules = [r for r in BUILTIN_RULES if r["id"] not in disabled]
    for extra in rules_cfg.get("extra", []) or []:
        rules.append({
            "id": extra.get("id", "custom"),
            "description": extra.get("description", ""),
            "applies": tuple(extra.get("applies", [])),
            "pattern": extra["pattern"],
            "flags": re.I if extra.get("ignore_case", True) else 0,
        })
    return rules


def check_rules(cfg: dict, adapter_name: str, args: dict) -> str | None:
    """命中返回拒绝原因，放行返回 None。"""
    try:
        serialized = json.dumps(args, ensure_ascii=False, default=str)
    except TypeError:
        serialized = str(args)
    for rule in active_rules(cfg):
        if adapter_name not in rule["applies"]:
            continue
        if re.search(rule["pattern"], serialized, rule.get("flags", 0)):
            return f"[{rule['id']}] {rule['description']}"
    return None
