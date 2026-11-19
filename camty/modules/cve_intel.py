"""CVE 情报环：组件指纹 → CIRCL CVE 库匹配 → 严重度/受影响版本过滤。

CIRCL CVE 搜索（免费无 key）：https://cve.circl.lu/api/search/{vendor}/{product}
响应 cvelistv5 格式：results.cvelistv5 = [[cve_id, {containers:{cna:{affected,
descriptions, metrics}}}]]。在线优先；不可达时空结果并注明（不伪造数据）。
"""

from __future__ import annotations

import re

from camty.modules import http_fp

CIRCL = "https://cve.circl.lu/api/search"

# 常见指纹名 → CIRCL (vendor, product) 映射（大小写不敏感关键词）
PRODUCT_MAP = {
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "tomcat": ("apache", "tomcat"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "sqlite": ("sqlite", "sqlite"),
    "golang": ("golang", "go"),
    "go": ("golang", "go"),
    "gin": (None, None),  # Go 框架无独立 CPE
    "node.js": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    "express": (None, None),
    "struts": ("apache", "struts"),
    "thinkphp": (None, None),
    "spring": ("vmware", "spring_framework"),
    "log4j": ("apache", "log4j"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "wordpress": ("wordpress", "wordpress"),
    "php": ("php", "php"),
    "django": ("djangoproject", "django"),
    "flask": (None, None),
    "fastapi": (None, None),
    "sqlite3": ("sqlite", "sqlite"),
    "curl": ("haxx", "curl"),
    "bash": ("gnu", "bash"),
    "git": ("git", "git"),
    "docker": ("docker", "docker"),
    "grafana": ("grafana", "grafana"),
    "minio": ("minio", "minio"),
    "consul": ("hashicorp", "consul"),
    "etcd": ("etcd", "etcd"),
    "kubernetes": ("kubernetes", "kubernetes"),
}


def _resolve(name: str) -> tuple[str, str] | None:
    key = name.strip().lower()
    if key in PRODUCT_MAP:
        return PRODUCT_MAP[key] if PRODUCT_MAP[key][0] else None
    for keyword, vp in PRODUCT_MAP.items():
        if keyword in key:
            return vp if vp[0] else None
    # 未知组件：vendor 取名字第一段尝试
    parts = key.split()
    return (parts[0], parts[-1]) if parts else None


def _severity_of(entry: dict) -> str:
    """从 cna.metrics 提取 CVSS 分级。"""
    cna = entry.get("containers", {}).get("cna", {})
    metrics = cna.get("metrics") or []
    best = 0.0
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0", "cvssV4_0"):
            score = (m.get(key) or {}).get("baseScore")
            if isinstance(score, (int, float)):
                best = max(best, float(score))
    if best >= 9:
        return "critical"
    if best >= 7:
        return "high"
    if best >= 4:
        return "medium"
    return "low" if best > 0 else "unknown"


def _description_of(entry: dict) -> str:
    cna = entry.get("containers", {}).get("cna", {})
    for desc in cna.get("descriptions") or []:
        value = desc.get("value", "")
        if desc.get("lang") in ("en", "eng") or not desc.get("lang"):
            return re.sub(r"\s+", " ", value)[:160]
    return ""


def _version_scope_of(entry: dict) -> str:
    """受影响版本范围（cna.affected[].versions 简表）。"""
    cna = entry.get("containers", {}).get("cna", {})
    parts = []
    for aff in (cna.get("affected") or [])[:4]:
        versions = aff.get("versions") or []
        if versions:
            parts.append(",".join(str(v) for v in versions[:6]))
    return "; ".join(parts)[:200]


def query_component(name: str, version: str | None = None,
                    limit: int = 40) -> dict:
    """查询单组件 CVE。返回 {component, cves: [{id, severity, desc, versions}], source}。

    version 非空时只保留 affects 中提及该版本前缀的条目（粗筛，不精确判定范围）。
    """
    vp = _resolve(name)
    if vp is None:
        return {"component": name, "cves": [], "source": "unsupported",
                "note": f"{name} 无独立 CPE（框架类），建议按宿主组件查询"}
    vendor, product = vp
    out = http_fp.fetch(f"{CIRCL}/{vendor}/{product}", timeout=30)
    if out is None or out[1] != 200:
        return {"component": name, "cves": [], "source": "unreachable",
                "note": f"CIRCL 不可达（HTTP {out[1] if out else 'err'}），离线无本地库"}
    data = out[0]
    try:
        import json

        body = json.loads(data)
    except (TypeError, ValueError):
        return {"component": name, "cves": [], "source": "parse-error"}
    entries = (body.get("results") or {}).get("cvelistv5") or []
    cves = []
    for cve_id, entry in entries[:limit]:
        sev = _severity_of(entry)
        versions = _version_scope_of(entry)
        if version:
            # 粗筛：条目提及该版本才保留（宽松——CVE affected 不总是列全版本）
            if version not in versions and version.split(".")[0] not in versions:
                continue
        cves.append({"id": cve_id, "severity": sev,
                     "desc": _description_of(entry), "versions": versions})
    return {"component": f"{vendor}/{product}", "cves": cves, "source": "circl"}
