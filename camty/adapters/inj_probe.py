"""多载体注入探测适配器（inj-probe）：GET/POST 表单/POST JSON × SQLi/XSS/SSTI/cmd/时间盲。

沿用 sqli-probe 的只读验证边界：命中即停、不取数据、不执行真实命令。
"""

from __future__ import annotations

import json

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.modules import inj_probe
from camty.adapters.sqli_probe import _normalize_targets  # 复用目标归一化

KINDS = ("sqli", "xss", "ssti", "cmd", "time-blind")
SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "info": "info"}


class InjProbeAdapter(ToolAdapter):
    name = "inj-probe"
    description = (
        "多载体注入验证：GET 参数、POST 表单、POST JSON（嵌套叶子）注入探测，"
        "类型 sqli/xss/ssti/cmd/time-blind，错误回显+回显判定，命中即停不利用。"
    )

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "targets": {
                    "oneOf": [{"type": "array", "items": {}}, {"type": "string"}],
                    "description": "目标 URL（GET 带参数探测；无参数跳过）",
                },
                "post_targets": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "body": {"type": "string", "description": "POST body 模板（表单或 JSON）"},
                            "content_type": {"type": "string", "description": "缺省按 body 形态判定"},
                            "kinds": {"type": "array", "items": {"type": "string", "enum": list(KINDS)}},
                        },
                        "required": ["url", "body"],
                    },
                    "description": "POST 载体目标列表",
                },
                "kinds": {"type": "array", "items": {"type": "string", "enum": list(KINDS)},
                          "default": ["sqli", "xss"], "description": "GET 目标探测类型"},
                "evasion": {"type": "boolean", "default": False,
                            "description": "编码混淆（SQL 大小写/内联注释/URL 编码；XSS 大小写变体）。"
                                           "WAF 在场时开启，正常目标保持克制"},
                "delay": {"type": "number", "default": 0.2, "description": "请求间隔（秒）"},
            },
            "required": [],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        hits: list[dict] = []
        all_targets = _normalize_targets(args.get("targets", []))
        post_targets = args.get("post_targets") or []
        for t in all_targets:
            ctx.scope.require(t)
        for pt in post_targets:
            ctx.scope.require(str(pt.get("url", "")))
        default_kinds = list(args.get("kinds") or ["sqli", "xss"])
        delay = float(args.get("delay", 0.2))
        evasion = bool(args.get("evasion", False))
        for url in all_targets:
            hits += inj_probe.probe_get(url, kinds=default_kinds, delay=delay,
                                         evasion=evasion)
        for pt in post_targets:
            body = str(pt.get("body", ""))
            ctype = str(pt.get("content_type") or
                        ("application/json" if body.lstrip().startswith("{") else
                         "application/x-www-form-urlencoded"))
            kinds = list(pt.get("kinds") or default_kinds)
            hits += inj_probe.probe_post(str(pt["url"]), body, ctype, kinds=kinds,
                                         delay=delay, evasion=evasion)
        # 去重（同 param 同 kind 只留一条）
        seen, unique = set(), []
        for h in hits:
            key = (h.get("param"), h.get("kind"), h.get("method"))
            if key not in seen:
                seen.add(key)
                unique.append(h)
        findings = [
            {"template": f"injection/{h['kind']}", "severity": "high",
             "url": h.get("param", ""), "detail": h.get("evidence", "")[:120]}
            for h in unique
        ]
        evidence = ctx.save_evidence(self.name, json.dumps(unique, ensure_ascii=False, indent=2))
        ctx.audit.record(
            self.name,
            {"n_get": len(all_targets), "n_post": len(post_targets), "kinds": default_kinds},
            ok=True,
            note=f"{len(unique)} hits",
        )
        summary = f"{len(all_targets)} 个 GET + {len(post_targets)} 个 POST 目标，命中 {len(unique)} 处"
        return ToolResult(summary=summary, data={"hits": unique, "findings": findings},
                          evidence=evidence)
