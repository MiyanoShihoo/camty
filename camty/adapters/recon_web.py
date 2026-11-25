"""Web 侦察与内容发现适配器：secret-scan（密钥泄露）+ dir-scan（目录/敏感路径）。"""

from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.modules import dir_scan, secret_scan


def _normalize_url_key(url: str) -> str:
    """finding 去重键：scheme/host/path 全小写 + query 参数排序归一。

    实验实录：dir-scan 对 Login/login/favicon 等大小写与重复路径重复入账
    （17 条 findings 实际约 6 端点）——按此键折叠，同 URL 变体只记一条。
    """
    try:
        parts = urlsplit(url.strip())
        query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(),
                           parts.path.lower() or "/", query, ""))
    except ValueError:  # 非法 URL（异常端口等）：退化为整体小写
        return url.strip().lower()


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
        # 入账前按归一化 key 去重（同一适配器运行内）：同 URL 大小写/query 顺序
        # 变体与重复条目只记一条，跨状态码保留首个；evidence 保留原始 found 全量。
        seen_keys: set[str] = set()
        unique_found = []
        findings = []
        for f in found:
            key = _normalize_url_key(f["url"])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            unique_found.append(f)
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
        ctx.audit.record(self.name, {"base": base, "n": len(unique_found), "n_raw": len(found)}, ok=True)
        return ToolResult(
            summary=f"发现 {len(unique_found)} 个非 fallback 路径"
                    + (f"（原始 {len(found)} 条，已按 URL 归一化去重）" if len(unique_found) != len(found) else ""),
            data={"discovered": unique_found, "findings": findings},
            evidence=evidence,
        )
