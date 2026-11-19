"""JS 路由侦察适配器（js-recon）：入口页与 JS bundle 提取 API 端点/路由表/sourcemap/泄露 secret。"""

from __future__ import annotations

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.modules import js_recon


def _normalize_targets(raw) -> list[str]:
    if isinstance(raw, str):
        return [t.strip() for t in raw.replace(",", "\n").splitlines() if t.strip()]
    items = []
    for t in raw or []:
        if isinstance(t, dict):
            if t.get("url"):
                items.append(str(t["url"]).strip())
        elif t:
            items.append(str(t).strip())
    return [t for t in items if t]


class JsReconAdapter(ToolAdapter):
    name = "js-recon"
    description = "前端 JS 路由侦察：入口页/JS bundle 提取 API 端点、前端路由表、sourcemap 引用与泄露 secret（SPA 资产测绘）。"
    max_assets: int = 20

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "targets": {
                    "oneOf": [{"type": "array", "items": {}}, {"type": "string"}],
                    "description": "入口页 URL 或 .js 直链列表",
                },
                "max_assets": {"type": "integer", "description": "每页最多跟进的 JS 资产数", "default": 20},
                "depth_scripts": {"type": "boolean", "description": "是否跟进页面引用的 JS 资产", "default": True},
            },
            "required": ["targets"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        targets = _normalize_targets(args.get("targets", []))
        if not targets:
            return ToolResult(summary="输入为空", data={"endpoints": []})
        for t in targets:
            ctx.scope.require(t)
        max_assets = int(args.get("max_assets", self.max_assets))
        depth = bool(args.get("depth_scripts", True))
        endpoints, routes, sourcemaps, secrets = [], [], [], []
        failed = []
        for base in targets:
            data = js_recon.analyze_site(base, max_assets=max_assets, depth_scripts=depth)
            if data.get("status") is None:
                failed.append(base)
            endpoints += data["endpoints"]
            routes += data["routes"]
            sourcemaps += data["sourcemaps"]
            secrets += data["secrets"]
        # 跨目标合并去重
        merged, seen = [], set()
        for e in endpoints:
            if e["endpoint"] not in seen:
                seen.add(e["endpoint"])
                merged.append(e)
        merged_routes, seen_r = [], set()
        for r in routes:
            if r["route"] not in seen_r:
                seen_r.add(r["route"])
                merged_routes.append(r)
        merged_maps = list(dict.fromkeys(sourcemaps))
        merged_secrets, seen_s = [], set()
        for s in secrets:
            key = (s["kind"], s["match"])
            if key not in seen_s:
                seen_s.add(key)
                merged_secrets.append(s)
        findings = [
            {"template": f"secret/{s['kind']}", "severity": "high", "url": s["source"],
             "detail": s["match"]}
            for s in merged_secrets
        ]
        findings += [
            {"template": "js/sourcemap-exposed", "severity": "medium", "url": m,
             "detail": "sourcemap 可下载，泄露前端源码"}
            for m in merged_maps
        ]
        evidence = ctx.save_evidence(self.name, "\n".join(
            [
                f"endpoints: {[e['endpoint'] for e in merged]}",
                f"routes: {[r['route'] for r in merged_routes]}",
                f"sourcemaps: {merged_maps}",
                f"secrets: {merged_secrets}",
            ]
        ))
        ctx.audit.record(
            self.name,
            {"n_targets": len(targets), "depth": depth},
            ok=not failed,
            note=f"{len(merged)} endpoints, {len(merged_secrets)} secrets",
        )
        return ToolResult(
            summary=(
                f"提取 {len(merged)} 个端点、{len(merged_routes)} 条路由、"
                f"{len(merged_secrets)} 处泄露 secret"
                + (f"（{len(failed)} 个目标不可达）" if failed else "")
            ),
            data={
                "endpoints": merged,
                "routes": merged_routes,
                "sourcemaps": merged_maps,
                "secrets": merged_secrets,
                "failed": failed,
                "findings": findings,
            },
            evidence=evidence,
        )
