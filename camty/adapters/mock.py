"""测试用 mock 适配器：产出确定性结果，不依赖外部工具。仅用于回归测试。"""

from __future__ import annotations

import time

from camty.adapters.base import RunContext, ToolAdapter, ToolResult


class MockSubfinder(ToolAdapter):
    name = "mock-subfinder"
    description = "mock 子域发现（测试用）"

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        ctx.scope.require(args["domain"])
        domain = args["domain"].strip().lower()
        subs = [f"www.{domain}", f"api.{domain}", f"mail.{domain}"]
        ctx.audit.record(self.name, args, ok=True, note=f"{len(subs)} hosts")
        return ToolResult(summary=f"mock 发现 {len(subs)} 子域", data={"subdomains": subs})


class MockHttpx(ToolAdapter):
    name = "mock-httpx"
    description = "mock 存活探测（测试用）"

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {"hosts": {"type": "array", "items": {"type": "string"}}},
            "required": ["hosts"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        hosts = list(args.get("hosts", []))
        for h in hosts:
            ctx.scope.require(h)
        sites = [
            {"url": f"https://{h}", "status": 200, "title": h, "tech": ["WordPress" if h.startswith("www.") else "Nginx"]}
            for h in hosts[:2]
        ]
        return ToolResult(
            summary=f"mock 存活 {len(sites)}/{len(hosts)}",
            data={
                "live_sites": sites,
                "live_hosts": [s["url"] for s in sites],
                "tech_map": {s["url"]: s["tech"] for s in sites},
            },
        )


class MockSleep(ToolAdapter):
    name = "mock-sleep"
    description = "mock 延迟步骤（测试并发调度用）"

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {"type": "object", "properties": {"seconds": {"type": "number"}}, "required": ["seconds"]}

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        seconds = float(args.get("seconds", 0.5))
        time.sleep(seconds)
        return ToolResult(summary=f"slept {seconds}s", data={"slept": seconds})


class MockConfirm(ToolAdapter):
    name = "mock-confirm"
    description = "mock 确认步骤（测试确认流）"
    requires_confirm = True

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {"type": "object", "properties": {}}

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        return ToolResult(summary="confirmed action executed", data={"confirmed_done": True})


class MockGated(ToolAdapter):
    name = "mock-gated"
    description = "mock 利用级步骤（测试 finding 门控）"
    requires_finding = True

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {"type": "object", "properties": {"finding_id": {"type": "string"}}}

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        return ToolResult(
            summary=f"gated done with {args.get('finding_id')}",
            data={"gated": args.get("finding_id")},
        )
