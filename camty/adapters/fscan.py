"""fscan 内网探测适配器（只探测，关闭 poc 与爆破）。"""

from __future__ import annotations

import re

from camty.adapters.base import RunContext, ToolAdapter, ToolResult, run_cmd

PORT_RE = re.compile(r"^(?P<host>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)\s+open", re.M)
TITLE_RE = re.compile(r"^\[\*\]\s+(?P<host>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<info>\S.*)$", re.M)


def parse_fscan(output: str) -> dict:
    from camty.adapters.base import strip_ansi

    output = strip_ansi(output)
    ports = [{"host": m.group("host"), "port": int(m.group("port"))} for m in PORT_RE.finditer(output)]
    host_ports: dict[str, list[int]] = {}
    for p in ports:
        host_ports.setdefault(p["host"], []).append(p["port"])
    return {
        "live_hosts": sorted(host_ports),
        "open_ports": ports,
        "host_ports": host_ports,
        "info": [{"host": m.group("host"), "info": m.group("info").strip()} for m in TITLE_RE.finditer(output)],
    }


class FscanAdapter(ToolAdapter):
    name = "fscan"
    description = "内网存活与服务探测（fscan，-nopoc -nobr 只探测不利用不爆破）。输入授权网段。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {"cidr": {"type": "string", "description": "授权网段，如 192.168.100.0/24"}},
            "required": ["cidr"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        cidr = str(args["cidr"]).strip()
        ctx.scope.require_cidr(cidr)
        code, output = run_cmd([self.binary(), "-h", cidr, "-nopoc", "-nobr"], timeout=3600)
        data = parse_fscan(output)
        evidence = ctx.save_evidence(self.name, output)
        ctx.audit.record(self.name, {"cidr": cidr}, ok=code == 0, note=f"{len(data['live_hosts'])} hosts")
        return ToolResult(
            summary=f"{cidr} 探测到 {len(data['live_hosts'])} 台存活主机",
            data=data,
            evidence=evidence,
        )
