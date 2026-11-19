"""JS 路由侦察：前端资产里的 API 端点与路由表提取（纯 Python，无外部依赖）。

从入口页 HTML 与其引用的 JS bundle 提取：
- API 端点：/api/...、/v1/... 前缀路径、fetch/axios 调用的字符串字面量
- 前端路由表：path: "/xxx/:id"（Vue/React Router 路由定义）
- sourcemap 引用（.map 未部署即泄露源码）
- secret 检测复用 secret_scan 规则
SPA 大包（webpack/vite bundle）里端点常以字符串常量散落，宁可多收再靠调用方去重。
"""

from __future__ import annotations

import re
import urllib.parse

from camty.modules.secret_scan import collect_assets, fetch, scan_text

# 字符串字面量里的 API 风格路径（/api/、/v1-9/、/graphql、/auth 等常见前缀）
API_PATH_RE = re.compile(
    r"[\"'`](/(?:(?:api|api/v\d+|v\d+|auth|admin|internal|graphql|rest|rpc|services?|gateway)"
    r"|[\w.\-]+(?:api|auth|graphql))(?:/[\w\-./:%${}]*)?)[\"'`]"
)
# fetch/axios/$http 调用：请求方法第一参数（字符串或模板字面量开头）
FETCH_CALL_RE = re.compile(
    r"(?:fetch|\$(?:get|post|put|delete|ajax)|axios(?:\.(?:get|post|put|delete|patch|request))?"
    r"|\.request)\(\s*[\"'`]([^\"'`]+)[\"'`]"
)
# 前端路由表 path 定义（Vue Router / React Router）
ROUTER_PATH_RE = re.compile(r"\bpath\s*:\s*[\"'`]([^\"'`]+)[\"'`]")
# 路径模板参数：/api/user/:id、/api/user/{id}
TEMPLATE_PARAM_RE = re.compile(r":([a-zA-Z_][\w]*)")
SOURCEMAP_RE = re.compile(r"sourceMappingURL=([^\s\"']+)")
MAP_FILE_RE = re.compile(r"[\"']([^\"']+\.map)[\"']")


def _normalize(origin: str, path: str) -> str:
    """相对路径补 origin、去 query/hash；绝对路径原样保留。"""
    path = path.strip()
    if not path or path.startswith(("data:", "blob:", "javascript:", "mailto:", "#")):
        return ""
    if not path.startswith("/"):
        if path.startswith(("http://", "https://")):
            return path
        base = origin.rstrip("/") + "/"
        path = urllib.parse.urljoin(base, path)
    else:
        path = urllib.parse.urljoin(origin, path)
    return path.split("#")[0]


def _strip_query(path: str) -> str:
    return path.split("?")[0]


def extract_endpoints(js_text: str, origin: str = "") -> list[dict]:
    """提取 API 端点。返回 [{endpoint, via}]，via 标记来源（api-path/fetch-call）。"""
    out: list[dict] = []
    for path in API_PATH_RE.findall(js_text or ""):
        norm = _strip_query(_normalize(origin, path))
        if norm:
            out.append({"endpoint": norm, "via": "api-path"})
    for path in FETCH_CALL_RE.findall(js_text or ""):
        norm = _strip_query(_normalize(origin, path))
        if norm:
            out.append({"endpoint": norm, "via": "fetch-call"})
    return _dedup(out)


def extract_routes(js_text: str, origin: str = "") -> list[dict]:
    """提取前端路由表。返回 [{route, params}]。"""
    out: list[dict] = []
    for path in ROUTER_PATH_RE.findall(js_text or ""):
        norm = _normalize(origin, path)
        if not norm or len(norm) > 300:
            continue
        params = TEMPLATE_PARAM_RE.findall(norm)
        out.append({"route": norm, "params": params})
    return _dedup(out)


def extract_sourcemaps(js_text: str, origin: str = "") -> list[str]:
    """sourcemap 引用：URL 直接可下载即源码泄露。"""
    out = []
    for m in list(SOURCEMAP_RE.findall(js_text or "")) + list(MAP_FILE_RE.findall(js_text or "")):
        norm = _normalize(origin, m)
        if norm and norm not in out:
            out.append(norm)
    return out


def _dedup(items: list[dict]) -> list[dict]:
    seen, unique = set(), []
    for item in items:
        key = item.get("endpoint") or item.get("route")
        if key and key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def analyze_text(text: str, source: str, origin: str = "") -> dict:
    """单份文本（HTML 或 JS）静态分析。"""
    return {
        "endpoints": extract_endpoints(text, origin),
        "routes": extract_routes(text, origin),
        "sourcemaps": extract_sourcemaps(text, origin),
        "secrets": scan_text(text, source),
    }


def analyze_site(base_url: str, max_assets: int = 20, depth_scripts: bool = True) -> dict:
    """入口页（或 .js 直链）分析：页面本体 + 引用的 JS 资产逐个提取，汇总去重。"""
    origin = f"{urllib.parse.urlsplit(base_url).scheme}://{urllib.parse.urlsplit(base_url).netloc}"
    html, status = fetch(base_url)
    if html is None:
        return {"page": base_url, "status": None, "js_assets": [], "endpoints": [],
                "routes": [], "sourcemaps": [], "secrets": []}
    result = {"page": base_url, "status": status, "js_assets": [], "endpoints": [],
              "routes": [], "sourcemaps": [], "secrets": []}
    page_data = analyze_text(html, base_url, origin)
    if base_url.endswith(".js"):
        assets = []  # JS 直链：自身就是资产
        page_data = analyze_text(html, base_url, origin)
    else:
        assets = collect_assets(base_url, html, limit=max_assets)
    for key in ("endpoints", "routes", "sourcemaps"):
        result[key] += page_data[key]
    result["secrets"] += page_data["secrets"]
    result["js_assets"] = list(assets)
    if depth_scripts:
        for asset in assets:
            text, _ = fetch(asset)
            if not text:
                continue
            data = analyze_text(text, asset, origin)
            for key in ("endpoints", "routes", "sourcemaps"):
                result[key] += data[key]
            result["secrets"] += data["secrets"]
    result["endpoints"] = _dedup(result["endpoints"])
    result["routes"] = _dedup(result["routes"])
    seen, unique_secrets = set(), []
    for s in result["secrets"]:
        key = (s["kind"], s["match"])
        if key not in seen:
            seen.add(key)
            unique_secrets.append(s)
    result["secrets"] = unique_secrets
    result["sourcemaps"] = [s for s in dict.fromkeys(result["sourcemaps"])]
    return result
