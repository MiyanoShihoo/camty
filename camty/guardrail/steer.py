"""人在环路（steer）：operator 跑动中转向——队列存 context，worker/planner 消费注入。

ARTEX mainagent 对话引导的 Camty 落地：不阻塞引擎，operator 随时注入指令，
LLM worker 下一轮消息携带；消费即标记（断点续跑不重复注入）。
面板入口：POST /api/engagements/{name}/steer {"message": "..."}
"""

from __future__ import annotations

import time


def steer(eng, message: str) -> dict:
    """operator 注入转向指令（审计留痕）。"""
    notes = eng.context.setdefault("steer_notes", [])
    note = {"id": f"S-{len(notes) + 1:03d}", "message": message,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"), "consumed": False}
    notes.append(note)
    eng.save_state()
    eng.audit.record("operator-steer", {"id": note["id"], "message": message[:200]},
                     ok=True, note="人在环路转向")
    return note


def take_pending(eng, limit: int = 5) -> list[dict]:
    """取未消费转向指令并标记消费。返回空列表表示无指令。"""
    notes = eng.context.get("steer_notes") or []
    pending = [n for n in notes if not n.get("consumed")]
    taken = pending[:limit]
    if not taken:
        return []
    consumed_ids = {n["id"] for n in taken}
    for n in notes:
        if n["id"] in consumed_ids:
            n["consumed"] = True
    eng.save_state()
    return taken


def as_prompt(notes: list[dict]) -> str:
    """转向指令 → prompt 片段。"""
    if not notes:
        return ""
    lines = [f"operator 转向指令（{n['id']}，{n['ts']}）：{n['message']}" for n in notes]
    return "【operator 转向指令——优先级高于当前意图，按其调整方向】\n" + "\n".join(lines)


def pending_summary(eng) -> list[dict]:
    """面板用：未消费指令列表。"""
    return [n for n in (eng.context.get("steer_notes") or []) if not n.get("consumed")]
