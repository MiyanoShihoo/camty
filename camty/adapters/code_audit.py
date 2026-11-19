"""白盒源码审计适配器（code-audit）：本地源码树静态模式扫描 → 台账。"""

from __future__ import annotations

import json

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.modules import code_audit

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}


class CodeAuditAdapter(ToolAdapter):
    name = "code-audit"
    description = (
        "白盒源码审计：本地源码树（Go/Python/JS/Java/PHP）静态模式扫描，"
        "SQL 拼接/命令执行/硬编码凭据/弱加密/路径穿越/SSRF 面 → 结构化 findings。"
    )

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "源码根目录或单文件（operator 提供的授权源码）"},
                "max_files": {"type": "integer", "default": 4000, "description": "扫描文件数上限"},
            },
            "required": ["path"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        from pathlib import Path

        root = str(args["path"]).strip()
        if not root or not Path(root).exists():
            return ToolResult(summary=f"路径不存在: {root}", data={"findings": []})
        result = code_audit.scan_tree(root, max_files=int(args.get("max_files", 4000)))
        findings = result["findings"]
        # 模式审计天然有误报（占位符、测试代码），verified=False 进台账待 operator 复核
        ledger_findings = [
            {
                "template": f"code/{f['rule']}",
                "severity": f["severity"],
                "url": f"{f['file']}:{f['line']}",
                "detail": f["snippet"][:120],
                "verified": False,
            }
            for f in findings[:200]
        ]
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        evidence = ctx.save_evidence(
            self.name, json.dumps(result, ensure_ascii=False, indent=2)
        )
        ctx.audit.record(
            self.name, {"root": root, "files": result["files"]},
            ok=True,
            note=", ".join(f"{k}:{v}" for k, v in sorted(by_sev.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))) or "无命中",
        )
        return ToolResult(
            summary=(
                f"扫描 {result['files']} 个源文件，命中 {len(findings)} 条"
                f"（high+ {by_sev.get('high', 0) + by_sev.get('critical', 0)}，"
                f"medium {by_sev.get('medium', 0)}）"
            ),
            data={
                "files": result["files"],
                "hits": findings[:400],
                "by_severity": by_sev,
                "findings": ledger_findings,
            },
            evidence=evidence,
        )
