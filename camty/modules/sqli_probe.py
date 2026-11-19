"""纯 Python SQL 注入探测：错误回显 + 布尔差异。验证为止，不取数据。

只测 GET 参数（安全边界），参数级去重：一个参数命中一次即停，不发多余请求。
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

ERROR_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("MySQL", re.compile(r"you have an error in your sql syntax|warning\s*:?mysql|mysql_fetch|maria\db", re.I)),
    ("MSSQL", re.compile(r"unclosed quotation mark|microsoft odbc|odbc driver|native client|sql server.{0,30}error", re.I)),
    ("PostgreSQL", re.compile(r"pg_query|psql:|sqlstate|postgresql.{0,20}error", re.I)),
    ("SQLite", re.compile(r"unrecognized token|sqlite3?_?(error|exception)|sqlite_query", re.I)),
    ("Oracle", re.compile(r"\bora-\d{5}|oracle.{0,30}error", re.I)),
]

PROBES = ["'", '"', "\\)", "')", "';", "') OR ('1'='1"]
BOOLEAN_TRUE = "' AND '1'='1"
BOOLEAN_FALSE = "' AND '1'='2"
BOOLEAN_MIN_DIFF = 40


def _set_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    params = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    params.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(params)))


def _fetch(url: str, timeout: float = 10.0) -> tuple[str | None, int | None]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace"), resp.status
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", "replace"), exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, None


def probe_url(url: str, timeout: float = 10.0, delay: float = 0.2) -> list[dict]:
    """对单个 URL 的 GET 参数做注入验证。返回命中列表（可为空）。"""
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return []
    findings: list[dict] = []
    for pname, pvalue in params:
        hit = False
        for payload in PROBES:
            probe_value = (pvalue or "") + payload
            text, status = _fetch(_set_param(url, pname, probe_value), timeout)
            if delay:
                time.sleep(delay)
            if text is None:
                continue
            for dbms, signature in ERROR_SIGNATURES:
                m = signature.search(text)
                if m:
                    findings.append(
                        {
                            "url": url,
                            "param": pname,
                            "type": "error-based",
                            "dbms": dbms,
                            "payload": payload,
                            "evidence": m.group(0)[:120],
                        }
                    )
                    hit = True
                    break
            if hit:
                break
        if hit:
            continue
        t_true, s_true = _fetch(_set_param(url, pname, (pvalue or "") + BOOLEAN_TRUE), timeout)
        time.sleep(delay)
        t_false, s_false = _fetch(_set_param(url, pname, (pvalue or "") + BOOLEAN_FALSE), timeout)
        time.sleep(delay)
        if (
            t_true is not None
            and t_false is not None
            and s_true == s_false
            and t_true != t_false
            and abs(len(t_true) - len(t_false)) > BOOLEAN_MIN_DIFF
        ):
            findings.append(
                {
                    "url": url,
                    "param": pname,
                    "type": "boolean-based",
                    "dbms": "unknown",
                    "payload": f"{BOOLEAN_TRUE!r} vs {BOOLEAN_FALSE!r}",
                    "evidence": f"响应长度差异 {len(t_true)} vs {len(t_false)}",
                }
            )
    return findings


# ---------- POST JSON 注入路径（v0.3：JSON body 字段错误回显探测） ----------

def _post_json(url: str, body: dict, timeout: float = 10.0) -> tuple[str | None, int | None]:
    try:
        req = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace"), resp.status
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", "replace"), exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, None


def probe_json_url(url: str, body: dict, timeout: float = 10.0, delay: float = 0.2) -> list[dict]:
    """对 JSON body 的每个字符串字段注入探测（验证为止）。返回命中列表。"""
    findings = []
    for pname, pvalue in body.items():
        if not isinstance(pvalue, str):
            continue
        hit = False
        for payload in PROBES:
            probe_body = dict(body)
            probe_body[pname] = pvalue + payload
            text, status = _post_json(url, probe_body, timeout)
            if delay:
                time.sleep(delay)
            if text is None:
                continue
            for dbms, signature in ERROR_SIGNATURES:
                m = signature.search(text)
                if m:
                    findings.append({
                        "url": url, "param": pname, "type": "error-based",
                        "dbms": dbms, "payload": payload, "evidence": m.group(0)[:120],
                    })
                    hit = True
                    break
            if hit:
                break
    return findings
