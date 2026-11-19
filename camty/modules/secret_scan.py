"""密钥泄露扫描：页面与 JS 资产的 secret 正则库（纯 Python，无外部依赖）。

保守规则集：只收高置信模式（OpenAI/AWS/GCP/GitHub/Slack/JWT/私钥/赋值硬编码），
误报代价高（进台账），宁缺毋滥。
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("openai-api-key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9\-_]{20,}")),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("github-token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("slack-token", re.compile(r"xox[bpars]-[A-Za-z0-9\-]{10,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("hardcoded-secret", re.compile(
        r"(?:api[_-]?key|apisecret|secret|passwd|db[_-]?pass)\s*[:=]\s*[\"'][^\"'{}]{16,}[\"']", re.I)),
    ("deepseek/moonshot-key", re.compile(r"sk-[a-z0-9]{32,}")),
]

# 白名单：开发库自身的合法常量（避免库代码误报）
_FALSE_POSITIVE_HINTS = ("EXAMPLE", "your-api-key", "xxxxxx", "placeholder", "changeme")

_SCRIPT_RE = re.compile(r"<script[^>]*\bsrc=[\"']([^\"']+)[\"']", re.I)


def fetch(url: str, timeout: float = 20.0, max_bytes: int = 4_000_000) -> tuple[str | None, int | None]:
    """Chrome 指纹优先（JA3 伪装），curl_cffi 不可用回退 urllib。"""
    from camty.modules import http_fp

    out = http_fp.fetch(url, timeout=timeout)
    if out is not None:
        text, status = out
        return (text[:max_bytes] if text else None), status
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(max_bytes).decode("utf-8", "replace"), resp.status
    except urllib.error.HTTPError as exc:
        return exc.read(max_bytes).decode("utf-8", "replace"), exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, None


def collect_assets(base_url: str, page_html: str, limit: int = 30) -> list[str]:
    """页面引用的 JS 资产（相对路径补全），外加页面自身内联内容由调用方处理。"""
    from urllib.parse import urljoin

    urls = []
    for src in _SCRIPT_RE.findall(page_html or "")[:limit]:
        if src.startswith(("http://", "https://")):
            urls.append(src)
        else:
            urls.append(urljoin(base_url, src))
    return urls


def scan_text(text: str, source: str) -> list[dict]:
    """对单份文本跑规则。返回 [{kind, match, source, evidence}]。"""
    hits = []
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text or ""):
            matched = m.group(0)
            if any(hint in matched.upper() for hint in _FALSE_POSITIVE_HINTS):
                continue
            start = max(0, m.start() - 40)
            evidence = text[start:m.end() + 40].replace("\n", " ")
            hits.append({
                "kind": kind,
                "match": matched[:80],
                "source": source,
                "evidence": evidence,
            })
    return hits


def scan_site(base_url: str, depth_scripts: bool = True) -> list[dict]:
    """扫描入口页与其引用的 JS 资产。"""
    findings = []
    html, status = fetch(base_url)
    if html is None:
        return findings
    findings += scan_text(html, base_url)
    if depth_scripts:
        for asset in collect_assets(base_url, html):
            text, _ = fetch(asset)
            if text:
                findings += scan_text(text, asset)
    # 去重（同 match 只留第一条）
    seen = set()
    unique = []
    for f in findings:
        key = (f["kind"], f["match"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
