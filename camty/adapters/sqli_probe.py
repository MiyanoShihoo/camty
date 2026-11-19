"""SQL 注入探测适配器（自研模块，纯 Python，无需外部工具）。"""

from __future__ import annotations

import json
import re

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.modules import sqli_probe


def _normalize_targets(raw) -> list[str]:
    items = []
    if isinstance(raw, str):
        items = [t.strip() for t in re.split(r"[,\n]", raw)]
    elif isinstance(raw, list):
        for t in raw:
            if isinstance(t, dict):
                u = t.get("url")
                if u:
                    items.append(str(u).strip())
            elif t:
                items.append(str(t).strip())
    return [t for t in items if t]


class SqliProbeAdapter(ToolAdapter):
    name = "sqli-probe"
    description = (
        "SQL 注入验证探测（自研，错误回显 + 布尔差异，验证为止不取数据）。"
        "输入目标 URL 列表（带查询参数的 URL 才可测）。"
    )
    requires_confirm = True

    def available(self) -> bool:
        return True  # 自研纯 Python 模块，无外部二进制依赖

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "targets": {
                    "oneOf": [
                        {"type": "array", "items": {}},
                        {"type": "string"},
                    ],
                    "description": "目标 URL 列表（字符串或 httpx live_sites 结构均可）",
                },
                "delay": {"type": "number", "description": "请求间隔秒数", "default": 0.2},
                "posts": {
                    "type": "array",
                        "description": "POST JSON probe items: [{url: ..., body: JSON string}]",
                    "items": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "body": {"type": "string", "description": "JSON 字符串"},
                        },
                        "required": ["url", "body"],
                    },
                },
            },
            "required": ["targets"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        targets = _normalize_targets(args.get("targets", []))
        if not targets and not args.get("posts"):
            return ToolResult(summary="输入为空", data={"findings": []})
        for t in targets:
            ctx.scope.require(t)
        hits = []
        tested = 0
        for url in targets:
            if not urlparse_has_query(url):
                continue
            tested += 1
            for hit in sqli_probe.probe_url(url, delay=float(args.get("delay", 0.2))):
                hits.append(
                    {
                        "template": f"sqli/{hit['type']} ({hit['dbms']})",
                        "severity": "high",
                        "url": hit["url"],
                        "param": hit["param"],
                        "detail": {"payload": hit["payload"], "evidence": hit["evidence"]},
                    }
                )
        # POST JSON 注入分支
        posts = args.get("posts") or []
        for item in posts:
            url = str(item.get("url", ""))
            if not url:
                continue
            ctx.scope.require(url)
            try:
                body = json.loads(item.get("body", "{}"))
            except ValueError:
                continue
            for hit in sqli_probe.probe_json_url(url, body, delay=float(args.get("delay", 0.2))):
                hits.append(
                    {
                        "template": f"sqli/{hit['type']} ({hit['dbms']})",
                        "severity": "high",
                        "url": hit["url"],
                        "param": hit["param"],
                        "detail": {"payload": hit["payload"], "evidence": hit["evidence"]},
                    }
                )
        evidence = ctx.save_evidence(self.name, json.dumps(
            [{"url": h["url"], "template": h["template"], "detail": h["detail"]} for h in hits],
            ensure_ascii=False, indent=2))
        ctx.audit.record(self.name, {"n_targets": len(targets), "n_tested": tested}, ok=True, note=f"{len(hits)} hits")
        summary = f"测试 {tested} 个带参 URL，命中 {len(hits)} 处注入"
        return ToolResult(
            summary=summary,
            data={
                "findings": hits,
                "sqli_details": [h["detail"] for h in hits],
                "sqli_targets": [h["url"] for h in hits],  # 供利用阶段接续
            },
            evidence=evidence,
        )


def urlparse_has_query(url: str) -> bool:
    from urllib.parse import urlparse

    return bool(urlparse(url).query)
