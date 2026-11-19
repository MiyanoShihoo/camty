"""审批模式：interactive（终端确认）/ model（LLM 兜底审批）/ auto（自动放行）。

模型兜底审批（ARTEX 思路）：无操作员在场时，由 review LLM 对照交战范围、
台账与动作后果批准或拒绝，审批结论与理由写入审计链。model 模式拒绝≠报错，
等价于操作员按下 N。
"""

from __future__ import annotations

import json

REVIEW_PROMPT = """你是渗透交战的审批员（guard）。操作员不在场，由你代为审批一个即将执行的动作。

交战授权范围: {scope}
当前台账（verified 项才可作为利用依据）:
{ledger}

待审批动作: {adapter}
参数: {args}
动作说明: {description}

判断标准：
1. 目标是否在授权范围内（范围外 → 拒绝）
2. 是否破坏性/不可逆（删数据、改凭据、拒绝服务 → 拒绝）
3. 利用级动作是否引用了台账中已验证的发现（无依据 → 拒绝）
4. 其余侦察/验证类只读动作 → 倾向批准

只输出 JSON：{{"approve": true/false, "reason": "一句话理由"}}"""


def model_review(router, adapter, args: dict, eng) -> tuple[bool, str]:
    """LLM 兜底审批。返回 (approve, reason)。异常时保守拒绝。"""
    from camty.llm.router import ROLE_DECIDE

    scope = eng.cfg.get("scope", {})
    scope_desc = json.dumps(
        {"domains": scope.get("domains", []), "cidrs": scope.get("cidrs", []),
         "ips": scope.get("ips", [])}, ensure_ascii=False)
    prompt = REVIEW_PROMPT.format(
        scope=scope_desc, ledger=eng.ledger.summary()[:2000],
        adapter=adapter.name, args=json.dumps(args, ensure_ascii=False, default=str)[:1500],
        description=adapter.description[:300],
    )
    try:
        resp = router.chat(ROLE_DECIDE, [
            {"role": "system", "content": "你是审批员，只输出 JSON。"},
            {"role": "user", "content": prompt},
        ], None)
        content = resp.get("content", "") or ""
        start, end = content.find("{"), content.rfind("}")
        if start < 0 or end <= start:
            return False, "审批模型输出不可解析，保守拒绝"
        verdict = json.loads(content[start:end + 1])
        return bool(verdict.get("approve")), str(verdict.get("reason", ""))[:200]
    except Exception as exc:  # noqa: BLE001 - 审批失败宁可保守
        return False, f"审批调用失败，保守拒绝: {exc}"


def decide_confirm(eng, adapter, args: dict, router=None) -> tuple[bool, str, str]:
    """统一确认入口。返回 (proceed, mode, note)。

    优先级：预授权规则表 > 显式 approval.mode（interactive/model/auto）> auto_confirm 标志 > 终端交互。
    """
    from camty.guardrail.preauth import check as preauth_check

    if preauth_check(eng, adapter.name, args):
        return True, "preauth", "命中预授权规则（面板/批量放行，审计留痕）"
    mode = (eng.cfg.get("approval", {}) or {}).get("mode", "")
    if mode == "auto":
        return True, "auto", "审批模式 auto"
    if mode == "model":
        if router is None:
            return False, "model", "审批模式 model 但未配置 LLM，保守拒绝"
        approve, reason = model_review(router, adapter, args, eng)
        return approve, "model", reason
    if eng.cfg.get("auto_confirm", False):
        return True, "auto_confirm", "交战配置 auto_confirm"
    answer = input(f"[确认] 执行 {adapter.name}，参数: {args}，继续? [y/N] ").strip().lower()
    return answer == "y", "interactive", "operator " + ("批准" if answer == "y" else "拒绝")
