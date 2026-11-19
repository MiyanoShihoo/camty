"""凭据测试适配器（NetExec smb 验证已知凭据，--continue-on-success）。"""

from __future__ import annotations

import re

from camty.adapters.base import RunContext, ToolAdapter, ToolResult, run_cmd

SUCCESS_RE = re.compile(r"^SMB\s+(?P<host>\S+)\s+\d+\s+(?P<hostname>\S+)\s+(?P<status>\[\+\]|\[-\])\s*(?P<rest>.*)$", re.M)


def parse_nxc_auth(output: str) -> dict:
    valid, invalid, pwned = [], [], []
    for m in SUCCESS_RE.finditer(output):
        host, status, rest = m.group("host"), m.group("status"), m.group("rest")
        if status == "[+]":
            valid.append({"host": host, "detail": rest.strip()})
            if "pwn" in rest.lower():
                pwned.append({"host": host})
        else:
            invalid.append({"host": host, "detail": rest.strip()})
    return {"valid": valid, "invalid": invalid, "pwned": pwned}


class CredTestAdapter(ToolAdapter):
    name = "cred-test"
    tool_name = "nxc"
    description = "在授权范围内验证已知凭据（NetExec，只验证，不喷洒不爆破）。"
    requires_confirm = True
    requires_finding = True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "hosts": {"oneOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}]},
                "domain_user": {"type": "string"},
                "domain_pass": {"type": "string"},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["hosts", "domain_user", "domain_pass", "finding_id"],
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
            [
                self.binary(), "smb", ",".join(hosts),
                "-u", args["domain_user"], "-p", args["domain_pass"],
                "--continue-on-success",
            ],
            timeout=1800,
        )
        data = parse_nxc_auth(output)
        findings = [
            {"template": "valid-credential", "severity": "high", "url": v["host"]}
            for v in data["valid"]
        ]
        evidence = ctx.save_evidence(self.name, output)
        ctx.audit.record(
            self.name, {"n_hosts": len(hosts), "user": args["domain_user"], "finding_id": args.get("finding_id")},
            ok=code == 0, note=f"{len(data['valid'])} valid",
        )
        return ToolResult(
            summary=f"{len(hosts)} 台主机中 {len(data['valid'])} 台凭据有效",
            data={**data, "findings": findings},
            evidence=evidence,
        )
