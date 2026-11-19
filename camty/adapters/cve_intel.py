"""CVE 情报适配器（cve-intel）：技术栈指纹 → 已知漏洞匹配 → 可验证 findings。

输入 components（"nginx:1.18, openssh:9.6" 或列表），或缺省自动取
context.tech_map（httpx 指纹）+ 本次扫描的 banner。命中 CVE 输出
findings（按严重度），并给 nuclei 验证建议（命中 CVE 即有对应模板）。
"""

from __future__ import annotations

import json

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.modules import cve_intel


def _parse_components(raw, fallback_tech: dict) -> list[dict]:
    if not raw:
        # 自动：从 context.tech_map 提取（httpx 输出 {url: [tech,...]}）
        out = []
        seen = set()
        for _, techs in (fallback_tech or {}).items():
            for t in techs if isinstance(techs, list) else [techs]:
                t = str(t).strip()
                if t and t.lower() not in seen and not t.startswith(("HSTS",)):
                    seen.add(t.lower())
                    out.append({"name": t, "version": None})
        return out
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]
        items = []
        for p in parts:
            name, _, version = p.partition(":")
            items.append({"name": name.strip(), "version": version.strip() or None})
        return items
    return [dict(x) if isinstance(x, dict) else {"name": str(x), "version": None}
            for x in raw or []]


class CveIntelAdapter(ToolAdapter):
    name = "cve-intel"
    description = (
        "组件指纹 CVE 情报：CIRCL CVE 库匹配已知漏洞（严重度/受影响版本/摘要），"
        "缺省自动取 httpx 指纹（tech_map）。输出 findings + nuclei 验证建议。"
    )

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "components": {
                    "oneOf": [
                        {"type": "string",
                         "description": "组件清单（如 'nginx:1.18, openssh:9.6'）"},
                        {"type": "array", "items": {}},
                    ],
                    "description": "缺省自动取 context.tech_map 指纹",
                },
                "version_filter": {"type": "boolean", "default": True,
                                    "description": "带版本时按版本粗筛受影响条目"},
                "max_per_component": {"type": "integer", "default": 30},
            },
            "required": [],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        tech_map = ctx.eng.context.get("tech_map") or {} if ctx.eng else {}
        components = _parse_components(args.get("components"), tech_map)
        if not components:
            return ToolResult(summary="无组件指纹输入（先跑 httpx 或显式传 components）",
                              data={"cves": []})
        version_filter = bool(args.get("version_filter", True))
        limit = int(args.get("max_per_component", 30))
        results = []
        findings = []
        for comp in components:
            r = cve_intel.query_component(comp["name"], comp["version"] if version_filter else None,
                                           limit=limit)
            results.append(r)
            for cve in r.get("cves", []):
                sev = cve["severity"]
                if sev in ("critical", "high"):
                    findings.append({
                        "template": f"cve/{cve['id'].upper()}",
                        "severity": sev,
                        "url": f"{r['component']}",
                        "detail": f"{cve['id']} {cve['desc'][:100]}",
                        "verified": False,  # 情报命中待 nuclei 验证
                    })
        total = sum(len(r.get("cves", [])) for r in results)
        hi = sum(1 for f in findings if f["severity"] in ("critical", "high"))
        summary = (f"{len(components)} 组件查询完成：{total} 条 CVE 命中，"
                   f"high/critical {hi}（nuclei -t cve/ 或 -tags 验证）")
        evidence = ctx.save_evidence(self.name, json.dumps(
            {"components": components, "results": results}, ensure_ascii=False, indent=1))
        ctx.audit.record(self.name, {"n_components": len(components)}, ok=True,
                         note=f"{total} cves, {hi} high")
        return ToolResult(summary=summary,
                          data={"results": results, "findings": findings},
                          evidence=evidence)
