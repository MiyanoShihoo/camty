"""预授权规则表：比赛场景一键放行（面板批量授权 → decide_confirm 前置命中即放行）。

设计原则（用户立场：真实伤害证明是渗透价值所在）：
- 预授权是显式动作：面板/API 写入 + 审计留痕（"谁在何时放行了什么模式"）
- 命中即放行（mode=preauth），未命中走原审批链
- 规则存 eng.context["preauth_rules"]（随 SQLite 持久化，交战隔离）
"""

from __future__ import annotations

import json
import re
import time


def _rules(eng) -> list[dict]:
    return eng.context.setdefault("preauth_rules", [])


def add_rule(eng, adapter: str, pattern: str = ".*", note: str = "") -> dict:
    """添加预授权规则：adapter 名 + 参数正则（.* = 该适配器全放行）。"""
    rule = {
        "adapter": adapter,
        "pattern": pattern,
        "note": note,
        "created_ts": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _rules(eng).append(rule)
    eng.save_state()
    eng.audit.record("preauth-add", rule, ok=True,
                     note=f"批量放行 {adapter}（{pattern}）{note}".strip())
    return rule


def clear_rules(eng) -> int:
    n = len(_rules(eng))
    eng.context["preauth_rules"] = []
    eng.save_state()
    if n:
        eng.audit.record("preauth-clear", {}, ok=True, note=f"清空 {n} 条预授权")
    return n


def check(eng, adapter_name: str, args: dict) -> bool:
    """预授权命中判定：adapter 精确匹配 + 参数 JSON 序列化后正则匹配。"""
    try:
        serialized = json.dumps(args, ensure_ascii=False, default=str)
    except TypeError:
        serialized = str(args)
    for rule in _rules(eng):
        if rule.get("adapter") != adapter_name:
            continue
        try:
            if re.search(rule.get("pattern", ".*"), serialized):
                return True
        except re.error:
            continue
    return False
