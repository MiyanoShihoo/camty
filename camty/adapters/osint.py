"""OSINT 适配器（osint-recon）：交战前目标画像——RDAP 注册信息 + crt.sh 子域历史。

零接触目标（数据源全部是公共情报库，不打目标流量）：
- RDAP（rdap.org → 注册商/时间线/NS）
- crt.sh（证书透明度子域历史 → 直接入资产图）
- 反查 IP（解析 + ASN 提示）
"""

from __future__ import annotations

import json
import re
import socket

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.modules import http_fp


def _rdap(domain: str) -> dict:
    out = http_fp.fetch(f"https://rdap.org/domain/{domain}", timeout=30)
    if not out or out[1] != 200:
        return {"available": False, "note": f"RDAP 不可达（{out[1] if out else 'err'}）"}
    try:
        data = json.loads(out[0])
    except (TypeError, ValueError):
        return {"available": False}
    events = {e.get("eventAction"): e.get("eventDate", "")[:10]
              for e in data.get("events") or []}
    nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers") or []]
    return {
        "available": True,
        "registrar": next((e.get("handle") for e in data.get("entities") or []
                           if e.get("roles") and "registrar" in e["roles"]), ""),
        "registered": events.get("registration", ""),
        "updated": events.get("last changed", events.get("last update of RDAP database", "")),
        "expires": events.get("expiration", ""),
        "nameservers": nameservers,
    }


def _crtsh_subdomains(domain: str, timeout: float = 45.0) -> list[str]:
    out = http_fp.fetch(f"https://crt.sh/?q=%{domain}&output=json", timeout=timeout)
    if not out or out[1] != 200:
        return []
    try:
        rows = json.loads(out[0])
    except (TypeError, ValueError):
        return []
    subs = set()
    base = domain.lower()
    for row in rows:
        for name in (row.get("name_value") or "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name.endswith(base) and name != f"issuer.{base}":
                subs.add(name)
    return sorted(subs)


class OsintAdapter(ToolAdapter):
    name = "osint-recon"
    description = (
        "目标画像 OSINT（零接触）：RDAP 注册时间线/NS + crt.sh 证书历史子域"
        "（直接入资产图）+ IP/ASN。公共情报源，不产生目标流量。"
    )

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "根域名（如 wbssr.com）"},
                "ingest_assets": {"type": "boolean", "default": True,
                                   "description": "子域直接入资产图"},
            },
            "required": ["domain"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        domain = str(args["domain"]).strip().lower().strip(".")
        if "://" in domain:
            domain = domain.split("://", 1)[1].split("/")[0]
        root = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
        rdap = _rdap(root)
        subs = _crtsh_subdomains(root)
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, 443,
                                                           socket.AF_INET)}) or []
        ingested = 0
        if args.get("ingest_assets", True) and ctx.eng is not None:
            ctx.eng.assets.upsert("root_domain", root, source="osint")
            for s in subs:
                ctx.eng.assets.upsert("subdomain", s, source="crt.sh")
                ingested += 1
        data = {
            "domain": domain, "root": root,
            "rdap": rdap, "subdomains": subs, "ips": ips,
        }
        evidence = ctx.save_evidence(self.name, json.dumps(data, ensure_ascii=False, indent=1))
        ctx.audit.record(self.name, {"domain": domain}, ok=True,
                         note=f"{len(subs)} 子域, {len(ips)} IP")
        return ToolResult(
            summary=(f"{root} 画像：{len(subs)} 个历史子域、{len(ips)} 个 A 记录、"
                     f"注册 {rdap.get('registered') or '?'}"
                     + (f"，{ingested} 项已入资产图" if ingested else "")),
            data=data,
            evidence=evidence,
        )
