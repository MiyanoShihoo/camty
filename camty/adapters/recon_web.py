"""Web 侦察与内容发现适配器：secret-scan（密钥泄露）+ dir-scan（目录/敏感路径）。"""

from __future__ import annotations

import json

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.modules import dir_scan, secret_scan


class SecretScanAdapter(ToolAdapter):
    name = "secret-scan"
    description = "密钥泄露扫描：入口页与其引用的 JS 资产跑高置信 secret 正则（OpenAI/AWS/JWT/私钥/硬编码凭据）。"

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "targets": {"oneOf": [{"type": "array", "items": {}}, {"type": "string"}]},
            },
            "required": ["targets"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        targets = args.get("targets", [])
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.replace(",", "\n").splitlines() if t.strip()]
        targets = [t for t in targets if t]
        if not targets:
            return ToolResult(summary="输入为空", data={"findings": []})
        for t in targets:
            ctx.scope.require(t)
        hits = []
        for base in targets:
            for h in secret_scan.scan_site(base):
                hits.append({
                    "template": f"secret/{h['kind']}",
                    "severity": "critical",
                    "url": h["source"],
                    "detail": {"match": h["match"], "evidence": h["evidence"]},
                })
        evidence = ctx.save_evidence(self.name, json.dumps(hits, ensure_ascii=False, indent=2))
        ctx.audit.record(self.name, {"n_targets": len(targets)}, ok=True, note=f"{len(hits)} hits")
        return ToolResult(
            summary=f"扫描 {len(targets)} 个入口，命中 {len(hits)} 处疑似密钥",
            data={"findings": hits},
            evidence=evidence,
        )


class DirScanAdapter(ToolAdapter):
    name = "dir-scan"
    description = (
        "内容发现：字典扫描目录/敏感路径，带 SPA fallback 基线判别"
        "（对任意路径回前端 HTML 的站点不误报）。401/403/200/跳转均记为发现。"
    )

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "base": {"type": "string", "description": "目标基址，如 https://a.com/"},
                "wordlists": {
                    "oneOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}],
                    "description": "字典路径（缺省 SecLists common + api-endpoints）",
                },
                "limit": {"type": "integer", "description": "字典条目上限", "default": 6000},
            },
            "required": ["base"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        base = str(args["base"]).strip()
        ctx.scope.require(base)
        wordlists = args.get("wordlists")
        if isinstance(wordlists, str):
            wordlists = [wordlists]
        found = dir_scan.scan(base, wordlists=wordlists, limit=int(args.get("limit", 6000)))
        findings = []
        for f in found:
            severity = "info"
            if f["status"] in (200, 201) and "json" in f["content_type"]:
                severity = "medium"
            elif f["status"] in (401, 403):
                severity = "low"
            findings.append({
                "template": f"content-discovery/{f['status']}",
                "severity": severity,
                "url": f["url"],
                "detail": {"status": f["status"], "length": f["length"],
                           "content_type": f["content_type"]},
            })
        evidence = ctx.save_evidence(self.name, json.dumps(found, ensure_ascii=False, indent=2))
        ctx.audit.record(self.name, {"base": base, "n": len(found)}, ok=True)
        return ToolResult(
            summary=f"发现 {len(found)} 个非 fallback 路径",
            data={"discovered": found, "findings": findings},
            evidence=evidence,
        )
