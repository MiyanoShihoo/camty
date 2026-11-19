"""subfinder 子域名发现适配器。"""

from __future__ import annotations

from camty.adapters.base import RunContext, ToolAdapter, ToolResult, run_cmd


class SubfinderAdapter(ToolAdapter):
    name = "subfinder"
    description = "子域名发现。输入根域名，返回发现的子域列表。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "根域名，如 example.com"}},
            "required": ["domain"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        domain = args["domain"].strip().lower()
        ctx.scope.require(domain)
        code, output = run_cmd([self.binary(), "-d", domain, "-silent"])
        subs = sorted({ln.strip() for ln in output.splitlines() if ln.strip()})
        evidence = ctx.save_evidence(self.name, output)
        ctx.audit.record(self.name, args, ok=code == 0, note=f"{len(subs)} hosts")
        return ToolResult(
            summary=f"发现 {len(subs)} 个子域",
            data={"subdomains": subs},
            evidence=evidence,
        )
