"""侧问（ARTEX side question 语义）：跑动中向 agent 提问，不干扰主流程。

与 steer 的区别：steer 注入转向指令改变 worker 行为；侧问是**只读快照问答**——
拿当前台账/黑板/todolist/执行过程回答 operator 的问题，不调用工具、不改状态。
答案落 activity（tool=side-question），面板过程页可查。
"""

from __future__ import annotations

import json

from camty.agent.state import Engagement
from camty.llm.router import ROLE_DECIDE, LLMRouter

ANSWER_TIMEOUT = 120.0

SIDEQ_SYSTEM = """你是渗透交战工作台的观察员，operator 正在交战进行中向你提问。
基于下面的**当前态势快照**回答问题；快照里没有的信息就说"快照里没有"，不臆测、不推测。
只读回答：不调用工具、不给执行建议清单、不改变交战状态。简洁中文。

{snapshot}"""


def _snapshot(eng: Engagement) -> str:
    from camty.agent.blackboard import Blackboard, ledger_digest
    from camty.agent.explore import Todolist

    parts = [f"台账:\n{ledger_digest(eng)}",
             f"todolist:\n{Todolist(eng).summary()[:800]}"]
    blackboard = Blackboard(eng).summary()
    if blackboard:
        parts.append(blackboard)
    traces = eng.db.load_activity(limit=20)
    if traces:
        lines = [f"[{t['ts']}] {t.get('node_id') or ''} {t['tool']}: "
                 f"{(t.get('result_digest') or '')[:120]}" for t in traces]
        parts.append("最近执行过程:\n" + "\n".join(reversed(lines)))
    return "\n\n".join(parts)


def answer_question(eng: Engagement, router: LLMRouter, question: str) -> str:
    """回答一个侧问：单次只读 LLM 调用，答案落 activity。"""
    question = question.strip()
    if not question:
        raise ValueError("问题不能为空")
    resp = router.chat(ROLE_DECIDE, [
        {"role": "system", "content": SIDEQ_SYSTEM.format(snapshot=_snapshot(eng))},
        {"role": "user", "content": question},
    ], None, timeout=ANSWER_TIMEOUT)
    answer = (resp.get("content") or "").strip()
    eng.db.add_activity(None, 0, "side-question",
                       json.dumps({"question": question[:400]}, ensure_ascii=False),
                       answer[:800], None)
    return answer
