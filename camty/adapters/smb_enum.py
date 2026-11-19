"""NetExec(nxc) SMB 枚举适配器：签名状态、共享、会话（空会话只读枚举）。"""

from __future__ import annotations

import re

from camty.adapters.base import RunContext, ToolAdapter, ToolResult, run_cmd

NXC_STATUS_RE = re.compile(r"^SMB\s+(?P<host>\S+)\s+\d+\s+(?P<hostname>\S+)\s+(?P<rest>.*)$", re.M)
SIGNING_RE = re.compile(r"signing[: ]\s*(?P<v>True|False)", re.I)
PWN_RE = re.compile(r"\[\+\](?P<rest>.*)", re.I)
SHARE_RE = re.compile(r"^(?P<share>[A-Za-z0-9_$#.-]+)\s+(?P<perm>[^\s]*\s*[^\s]*)\s+(?P<remark>.*)$", re.M)


def parse_nxc_enum(output: str) -> dict:
    signing: dict[str, bool] = {}
    hosts: list[str] = []
    shares: list[dict] = []
    in_shares = False
    for line in output.splitlines():
        if "Enumerated shares" in line:
            in_shares = True
            continue
        status = NXC_STATUS_RE.match(line)
        if status:
            host = status.group("host")
            if host not in hosts:
                hosts.append(host)
            m = SIGNING_RE.search(status.group("rest"))
            if m:
                signing[host] = m.group("v").lower() == "true"
            continue
        if in_shares:
            stripped = line.strip()
            if not stripped or stripped.startswith("-") or stripped.startswith("Share"):
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                shares.append({"host": hosts[-1] if hosts else "", "share": parts[0],
                               "permission": " ".join(parts[1:-1]) or "", "remark": parts[-1]})
    return {"hosts": hosts, "signing": signing, "shares": shares}


class SmbEnumAdapter(ToolAdapter):
    name = "smb-enum"
    tool_name = "nxc"
    description = "SMB 只读枚举（NetExec 空会话）：签名状态、共享、会话。输入主机列表。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "hosts": {
                    "oneOf": [
                        {"type": "array", "items": {"type": "string"}},
                        {"type": "string"},
                    ],
                    "description": "主机列表",
                }
            },
            "required": ["hosts"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        hosts = args.get("hosts", [])
        if isinstance(hosts, str):
            hosts = [h.strip() for h in hosts.replace(",", "\n").splitlines() if h.strip()]
        if not hosts:
            return ToolResult(summary="输入为空", data={})
        for h in hosts:
            ctx.scope.require(h)
        code, output = run_cmd(
            [self.binary(), "smb", ",".join(hosts), "-u", "", "-p", "", "--shares", "--sessions"],
            timeout=1800,
        )
        data = parse_nxc_enum(output)
        findings = [
            {"template": "smb/signing-disabled", "severity": "medium", "url": h}
            for h, v in data["signing"].items() if not v
        ]
        evidence = ctx.save_evidence(self.name, output)
        ctx.audit.record(self.name, {"n_hosts": len(hosts)}, ok=code == 0, note=f"{len(data['hosts'])} hosts")
        return ToolResult(
            summary=f"枚举 {len(data['hosts'])} 台主机，签名未开启 {sum(1 for v in data['signing'].values() if not v)} 台",
            data={**data, "findings": findings},
            evidence=evidence,
        )
