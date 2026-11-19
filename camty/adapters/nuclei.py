"""nuclei 已知漏洞验证适配器（只读验证，不执行利用）。"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from camty.adapters.base import RunContext, ToolAdapter, ToolResult, run_cmd, strip_ansi

LINE_RE = re.compile(r"^\[(?P<template>[^\]]+)\]\s+\[(?P<severity>[a-z]+)\]\s+\[(?P<type>[^\]]+)\]\s+(?P<target>\S+)")


def _normalize_hosts(raw) -> list[str]:
    if isinstance(raw, str):
        return [h.strip() for h in re.split(r"[,\n]", raw) if h.strip()]
    items = []
    for h in raw or []:
        if isinstance(h, dict):
            if h.get("url"):
                items.append(str(h["url"]).strip())
        elif h:
            items.append(str(h).strip())
    return [t for t in items if t]


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    description = "已知漏洞指纹验证（nuclei 模板，只读验证不利用）。输入 URL 列表与可选过滤。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "hosts": {
                    "oneOf": [
                        {"type": "array", "items": {}},
                        {"type": "string"},
                    ],
                    "description": "待验证的 URL 列表",
                },
                "severity": {
                    "type": "string",
                    "description": "最低严重级别过滤（如 medium），多个用逗号",
                    "default": "medium",
                },
                "tags": {"type": "string", "description": "按标签过滤模板，如 cve,sqli"},
                "templates": {"type": "string", "description": "指定模板/目录"},
            },
            "required": ["hosts"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        hosts = _normalize_hosts(args.get("hosts", []))
        if not hosts:
            return ToolResult(summary="输入为空", data={"findings": []})
        for host in hosts:
            ctx.scope.require(host)
        cmd = [self.binary(), "-silent"]
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write("\n".join(hosts))
            list_file = tmp.name
        cmd += ["-l", list_file]
        severity = args.get("severity")
        if severity:
            cmd += ["-severity", str(severity)]
        if args.get("tags"):
            cmd += ["-tags", str(args["tags"])]
        if args.get("templates"):
            cmd += ["-t", str(args["templates"])]
        code, output = run_cmd(cmd)
        Path(list_file).unlink(missing_ok=True)
        findings = []
        for line in output.splitlines():
            m = LINE_RE.match(strip_ansi(line).strip())
            if m:
                findings.append(
                    {
                        "template": m.group("template"),
                        "severity": m.group("severity"),
                        "type": m.group("type"),
                        "url": m.group("target"),
                    }
                )
        evidence = ctx.save_evidence(self.name, output)
        ctx.audit.record(self.name, {"n_hosts": len(hosts), "severity": severity or ""}, ok=code == 0, note=f"{len(findings)} hits")
        return ToolResult(
            summary=f"命中 {len(findings)} 条已知指纹",
            data={"findings": findings},
            evidence=evidence,
        )
