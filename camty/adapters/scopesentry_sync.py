"""ScopeSentry 资产同步适配器：外部测绘平台资产一键入图。

ScopeSentry（Autumn-27）REST API：Authorization: <token> 头。
端点/字段可配置（asset_types + endpoints + value_fields），
缺省用 ScopeSentry 常见预设；响应 {code:200, data:{items:[...]}} 或裸列表皆可。
同步只做 upsert 进资产图（带 source 标记），不重测。
"""

from __future__ import annotations

import json

from camty.adapters.base import RunContext, ToolAdapter, ToolResult

# ScopeSentry 预设：资产类型 → (API 路径, 资产 kind, 取值字段)
PRESETS = {
    "domain": ("/api/asset/domain/list", "root_domain", "domain"),
    "subdomain": ("/api/asset/subdomain/list", "subdomain", "subdomain"),
    "ip": ("/api/asset/ip/list", "host", "ip"),
    "port": ("/api/asset/port/list", "service", "host"),
    "site": ("/api/asset/site/list", "service", "site"),
    "url": ("/api/asset/url/list", "endpoint", "url"),
}


class ScopeSentrySyncAdapter(ToolAdapter):
    name = "scopesentry-sync"
    description = (
        "从 ScopeSentry 测绘平台同步资产入资产图（域名/子域/IP/端口/站点/URL），"
        "需要平台地址与 API token；同步只入图标 source，不重测。"
    )

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "ScopeSentry 实例地址（如 http://ss.example.com）"},
                "token": {"type": "string", "description": "平台 API token（settings 生成）"},
                "asset_types": {"type": "array", "items": {"type": "string"},
                                 "default": ["subdomain", "ip", "port", "url"],
                                 "description": "同步的资产类型（domain/subdomain/ip/port/site/url）"},
                "page_size": {"type": "integer", "default": 100},
                "max_per_type": {"type": "integer", "default": 500,
                                  "description": "每类资产入图上限"},
            },
            "required": ["url", "token"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        from camty.modules import http_fp

        base = str(args["url"]).rstrip("/")
        token = str(args["token"])
        page_size = int(args.get("page_size", 100))
        max_per = int(args.get("max_per_type", 500))
        types = args.get("asset_types") or ["subdomain", "ip", "port", "url"]
        stats: list[dict] = []
        total = 0
        for atype in types:
            path, kind, field = PRESETS.get(str(atype), (None, None, None))
            if not kind:
                stats.append({"type": atype, "error": f"未知资产类型（可选: {list(PRESETS)}）"})
                continue
            fetched = 0
            page = 1
            while fetched < max_per:
                out = http_fp.fetch(f"{base}{path}?page={page}&size={page_size}", timeout=30,
                                    headers={"Authorization": token,
                                             "Content-Type": "application/json"})
                if out is None:
                    stats.append({"type": atype, "error": "请求失败（地址/token 或网络）"})
                    break
                text, status = out
                if status != 200:
                    stats.append({"type": atype, "error": f"HTTP {status}: {str(text)[:120]}"})
                    break
                data = json.loads(text)
                payload = data.get("data", data) if isinstance(data, dict) else data
                items = payload.get("items") if isinstance(payload, dict) else payload
                if not isinstance(items, list):
                    stats.append({"type": atype, "error": "响应格式非预期列表"})
                    break
                for item in items:
                    if fetched >= max_per:
                        break
                    if isinstance(item, dict):
                        value = str(item.get(field) or item.get("value") or "").strip()
                    else:
                        value = str(item).strip()
                    if value:
                        ctx.eng.assets.upsert(kind, value, source="scopesentry")
                        total += 1
                        fetched += 1
                if len(items) < page_size or fetched >= max_per:
                    break
                page += 1
            stats.append({"type": atype, "fetched": fetched})
        cov = ctx.eng.assets.coverage()
        evidence = ctx.save_evidence(self.name, json.dumps(
            {"stats": stats, "coverage": cov}, ensure_ascii=False, indent=2))
        ctx.audit.record(self.name, {"url": base, "types": types}, ok=True,
                         note=f"sync {total} assets")
        return ToolResult(
            summary=f"同步 {total} 项资产入图（覆盖度 {cov['tested']}/{cov['total']}）",
            data={"synced": total, "by_type": stats, "coverage": cov},
            evidence=evidence,
        )
