"""鉴权矩阵适配器（authz-probe）：A/B 双会话平行越权 + 强制浏览验证。

前置：browser-action 以 session_name=a / session_name=b 分别登录两个账号
（save_session: true），各账号的自身资源 ID 经 own_id/other_id 注入。
按 operator 立场：写操作越权（PUT/POST）默认直接测（真实伤害证明），
cfg authz.write_confirm: true 可选回退为确认。
"""

from __future__ import annotations

import json

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.modules import authz_probe


def _session_file(ctx: RunContext, name: str):
    if ctx.eng is None:
        return None
    path = ctx.eng.dir / f"browser-session-{name}.json" if name != "default" \
        else ctx.eng.dir / "browser-session.json"
    return path if path.is_file() else None


class AuthzProbeAdapter(ToolAdapter):
    name = "authz-probe"
    description = (
        "鉴权矩阵验证：A 会话请求 B 的资源（平行越权）+ 无凭据强制浏览。"
        "需先用 browser-action 以 session_name=a/b 登录两个账号并保存会话。"
        "支持 {id} 占位、?id= 参数、路径尾段三种资源定位。"
    )

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "targets": {
                    "oneOf": [{"type": "array", "items": {}}, {"type": "string"}],
                    "description": "资源端点列表（如 https://x.com/api/orders/{id}）",
                },
                "session_a": {"type": "string", "default": "a", "description": "账号 A 会话名"},
                "session_b": {"type": "string", "default": "b", "description": "账号 B 会话名"},
                "own_id": {"type": "string", "description": "A 自身的资源 ID"},
                "other_id": {"type": "string", "description": "B 的资源 ID（越权目标）"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT"], "default": "GET"},
                "forced_browsing": {"type": "boolean", "default": True,
                                    "description": "无凭据访问受保护端点，验证 401/403 真拦截"},
                "token_header": {"type": "string", "default": "Bearer {token}",
                                 "description": "localStorage token 的 Authorization 头模板"},
            },
            "required": ["targets", "own_id", "other_id"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        raw = args.get("targets", [])
        if isinstance(raw, str):
            raw = [t.strip() for t in raw.replace(",", "\n").splitlines() if t.strip()]
        own_id = str(args["own_id"])
        other_id = str(args["other_id"])
        method = str(args.get("method", "GET")).upper()
        session_a_name = str(args.get("session_a", "a"))
        session_b_name = str(args.get("session_b", "b"))
        token_header = str(args.get("token_header", "Bearer {token}"))
        if not raw or not own_id or not other_id:
            return ToolResult(summary="参数不全（targets/own_id/other_id 必填）", data={})
        # 写方法越权：operator 立场默认直接测，cfg 可选回退确认
        write_confirm = (self.eng_cfg(ctx) or {}).get("authz", {}).get("write_confirm", False)
        if method in ("POST", "PUT") and write_confirm:
            proceed, mode, note = self._confirm_gate(ctx, method)
            if not proceed:
                return ToolResult(summary=f"写越权未获确认（{mode}: {note}）", data={})
        session_files = {
            "a": _session_file(ctx, session_a_name),
            "b": _session_file(ctx, session_b_name),
        }
        missing = [k for k, v in session_files.items() if v is None]
        if missing:
            return ToolResult(
                summary=f"缺登录会话 {missing}（先用 browser-action session_name={'/'.join(missing)} 登录并 save_session）",
                data={})
        sess = {k: authz_probe.load_session(v) for k, v in session_files.items()}
        for t in raw:
            ctx.scope.require(t)
        findings: list[dict] = []
        matrix: list[dict] = []
        needs_review: list[dict] = []
        for endpoint in raw:
            pair = authz_probe.build_pair(endpoint, own_id, other_id)
            if pair is None:
                matrix.append({"endpoint": endpoint, "skipped": "未识别资源 ID 位置（支持 {id} 占位 / ?id= / 路径尾段）"})
                continue
            own_url, other_url = pair
            baseline = authz_probe.fetch(own_url, sess["a"], method, token_header)
            self_b = authz_probe.fetch(other_url, sess["b"], method, token_header)
            cross = authz_probe.fetch(other_url, sess["a"], method, token_header)
            verdict = authz_probe.verdict(baseline, cross, other_id)
            forced = {"status": None}
            if args.get("forced_browsing", True):
                forced = authz_probe.fetch(own_url, None, "GET", token_header)
            row = {
                "endpoint": endpoint,
                "baseline_status": baseline["status"],
                "self_b_status": self_b["status"],
                "cross_status": cross["status"],
                "cross_verdict": verdict,
                "forced_status": forced["status"],
            }
            matrix.append(row)
            if verdict["hit"]:
                findings.append({
                    "template": "authz/idor", "severity": "high",
                    "url": other_url, "detail": verdict["detail"][:120],
                    "verified": True,
                })
            elif verdict["needs_review"]:
                needs_review.append({"endpoint": endpoint, "verdict": verdict,
                                     "cross_body": cross["body"][:600],
                                     "baseline_body": baseline["body"][:600]})
            if forced["status"] == 200:
                findings.append({
                    "template": "authz/forced-browse", "severity": "medium",
                    "url": own_url, "detail": "无凭据可访问受保护端点（强制浏览）",
                    "verified": True,
                })
        summary = (
            f"{len(raw)} 端点：越权命中 {sum(1 for f in findings if f['template'] == 'authz/idor')}，"
            f"强制浏览命中 {sum(1 for f in findings if f['template'] == 'authz/forced-browse')}，"
            f"待复核 {len(needs_review)}"
        )
        evidence = ctx.save_evidence(self.name, json.dumps(
            {"matrix": matrix, "needs_review": needs_review, "findings": findings},
            ensure_ascii=False, indent=2))
        ctx.audit.record(self.name, {"n_targets": len(raw), "method": method},
                         ok=True, note=summary)
        return ToolResult(
            summary=summary,
            data={"matrix": matrix, "needs_review": needs_review, "findings": findings},
            evidence=evidence,
        )

    @staticmethod
    def eng_cfg(ctx: RunContext) -> dict | None:
        return ctx.eng.cfg if ctx.eng else None

    def _confirm_gate(self, ctx: RunContext, method: str) -> tuple[bool, str, str]:
        from camty.guardrail.approval import decide_confirm

        eng = ctx.eng
        proceed, mode, note = decide_confirm(
            eng, self, {"method": method, "action": "authz-write-probe"}, None)
        return proceed, mode, note
