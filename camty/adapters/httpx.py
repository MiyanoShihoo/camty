"""httpx 存活探测与指纹适配器。"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from camty.adapters.base import RunContext, ToolAdapter, ToolResult, run_cmd, strip_ansi

LINE_RE = re.compile(
    r"^(?P<url>\S+)\s+\[(?P<status>\d{3})\]"
    r"(?:\s+\[(?P<title>[^\]]*)\])?"
    r"(?:\s+\[(?P<tech>[^\]]*)\])?\s*$"
)


class HttpxAdapter(ToolAdapter):
    name = "httpx"
    description = "HTTP 存活探测与指纹。输入主机/URL 列表，返回存活站点、状态码、标题、技术栈。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "hosts": {
                    "oneOf": [
                        {"type": "array", "items": {"type": "string"}},
                        {"type": "string", "description": "逗号或换行分隔的列表"},
                    ],
                    "description": "待探测的主机或 URL 列表",
                }
            },
            "required": ["hosts"],
        }

    @staticmethod
    def _normalize_hosts(raw) -> list[str]:
        if isinstance(raw, str):
            hosts = [h.strip() for h in re.split(r"[,\n]", raw)]
        else:
            hosts = [str(h).strip() for h in raw]
        return [h for h in hosts if h]

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        hosts = self._normalize_hosts(args.get("hosts", []))
        if not hosts:
            return ToolResult(summary="输入为空", data={"live_sites": [], "live_hosts": []})
        for host in hosts:
            ctx.scope.require(host)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write("\n".join(hosts))
            list_file = tmp.name
        code, output = run_cmd(
            [self.binary(), "-l", list_file, "-status-code", "-title", "-tech-detect",
             "-silent", "-no-color"]
        )
        Path(list_file).unlink(missing_ok=True)
        sites = []
        for line in output.splitlines():
            m = LINE_RE.match(strip_ansi(line).strip())
            if m:
                sites.append(
                    {
                        "url": m.group("url"),
                        "status": int(m.group("status")),
                        "title": m.group("title") or "",
                        "tech": [t for t in (m.group("tech") or "").split(",") if t],
                    }
                )
        evidence = ctx.save_evidence(self.name, output)
        ctx.audit.record(self.name, {"n_hosts": len(hosts)}, ok=code == 0, note=f"{len(sites)} live")
        return ToolResult(
            summary=f"{len(hosts)} 个主机中 {len(sites)} 个存活",
            data={
                "live_sites": sites,
                "live_hosts": [s["url"] for s in sites],
                "tech_map": {s["url"]: s["tech"] for s in sites if s["tech"]},
            },
            evidence=evidence,
        )
