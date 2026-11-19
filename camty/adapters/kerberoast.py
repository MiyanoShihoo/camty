"""Kerberoasting 检查适配器（impacket GetUserSPNs.py，只枚举可 roast SPN）。"""

from __future__ import annotations

import re

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.adapters.impacket import run_impacket

SPN_ROW_RE = re.compile(
    r"^(?P<spn>[A-Za-z0-9_.\-]+(?:[:/][A-Za-z0-9_.\-]+)+)\s+(?P<user>[A-Za-z0-9$_.\-]+)\s",
    re.M,
)


def parse_getuserspns(output: str) -> list[dict]:
    """解析表格式输出：ServicePrincipalName ... Name ... 行（跳过表头与分隔线）。"""
    spns = []
    for m in SPN_ROW_RE.finditer(output):
        spn, user = m.group("spn").strip(), m.group("user").strip()
        if "/" not in spn and ":" not in spn:
            continue
        spns.append({"spn": spn, "user": user})
    return spns


class KerberoastAdapter(ToolAdapter):
    name = "kerberoast-check"
    tool_name = "GetUserSPNs.py"
    description = "枚举可 Kerberoast 的 SPN 账户（impacket GetUserSPNs -request，只枚举与取票据，不爆破）。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"},
                "domain_user": {"type": "string", "description": "domain\\user 形式的域账号"},
                "domain_pass": {"type": "string"},
            },
            "required": ["dc_ip", "domain_user", "domain_pass"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        dc_ip = str(args["dc_ip"]).strip()
        ctx.scope.require(dc_ip)
        user = args["domain_user"]
        cmd_args = [
            f"{user}:{args['domain_pass']}",
            "-dc-ip", dc_ip,
            "-request",
        ]
        code, output = run_impacket(self.binary(), cmd_args, timeout=900)
        spns = parse_getuserspns(output)
        findings = [
            {"template": "kerberoastable-spn", "severity": "high", "url": s["user"]}
            for s in spns
        ]
        evidence = ctx.save_evidence(self.name, output)
        ctx.audit.record(self.name, {"dc": dc_ip, "user": user}, ok=code == 0, note=f"{len(spns)} spns")
        return ToolResult(
            summary=f"发现 {len(spns)} 个可 roast 的 SPN 账户",
            data={"spns": spns, "findings": findings},
            evidence=evidence,
        )
