"""鉴权矩阵探测：A/B 双会话越权判定（平行越权 + 强制浏览）。

设计（用户立场：真实伤害证明是渗透价值）：
- 平行越权：A 的凭据请求 B 的资源（参数替换）→ 响应对比判定
- 强制浏览：无凭据访问受保护端点 → 401/403 是否真拦截
- 判定确定性优先（状态码 + Jaccard 相似度 + ID 特征回显），拿不准标 needs_review
  留给 LLM worker 语义复核（引擎判定层）。
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

TOKEN_FIELDS = ("token", "access_token", "auth_token", "jwt", "authorization")
ID_PARAM_RE = re.compile(r"\{(id|user_id|uid|order_id|\w+_id|uid)\}", re.I)


def load_session(path) -> dict:
    """browser storage_state JSON → {cookie 头, token, raw}。"""
    state = json.loads(path.read_text(encoding="utf-8"))
    cookies = "; ".join(
        f"{c['name']}={c['value']}" for c in state.get("cookies", [])
        if c.get("name") and c.get("value"))
    token = ""
    token_field_hit = ""
    for origin in state.get("origins", []):
        for item in origin.get("localStorage", []):
            name = str(item.get("name", "")).lower()
            if name in TOKEN_FIELDS and not token:
                token = item.get("value", "")
                token_field_hit = name
                break
        if token:
            break
    if not token:
        # 兜底：取第一个看起来像 JWT/长串的 localStorage 值
        for origin in state.get("origins", []):
            for item in origin.get("localStorage", []):
                value = str(item.get("value", ""))
                if len(value) > 40 and (value.startswith("eyJ") or value.count(".") >= 2):
                    token = value
                    token_field_hit = item.get("name", "")
                    break
            if token:
                break
    return {"cookie": cookies, "token": token, "token_field": token_field_hit, "raw": state}


def fetch(url: str, session: dict | None = None, method: str = "GET",
          token_header: str = "Bearer {token}", timeout: float = 15.0,
          body: bytes | None = None) -> dict:
    """带（或不带）会话请求。Chrome 指纹优先（curl_cffi），回退 urllib。

    返回 {status, body, length}。"""
    from camty.modules import http_fp

    headers = {"User-Agent": "Mozilla/5.0"}
    if session:
        if session.get("cookie"):
            headers["Cookie"] = session["cookie"]
        if session.get("token"):
            headers["Authorization"] = token_header.format(token=session["token"])
    out = http_fp.fetch(url, method=method, headers=headers, body=body, timeout=timeout)
    if out is not None:
        text, status = out
        if status == 0:
            return {"status": 0, "body": "__error__ fingerprint layer", "length": 0}
        return {"status": status, "body": text or "", "length": len(text or "")}
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read(2_000_000).decode("utf-8", "replace")
            return {"status": resp.status, "body": text, "length": len(text)}
    except urllib.error.HTTPError as exc:
        text = exc.read(2_000_000).decode("utf-8", "replace")
        return {"status": exc.code, "body": text, "length": len(text)}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": 0, "body": f"__error__ {exc}", "length": 0}


def build_pair(endpoint: str, own_id: str, other_id: str) -> tuple[str, str] | None:
    """端点 → (own 变体, other 变体)。支持 {id} 占位、?id= 尾参、路径尾段。"""
    if ID_PARAM_RE.search(endpoint):
        own = ID_PARAM_RE.sub(re.escape(str(own_id)).replace("\\", ""), endpoint)
        other = ID_PARAM_RE.sub(str(other_id), endpoint)
        return own, other
    # query 参数形式：?xxx_id= / ?id= / ?uid=
    m = re.search(r"([?&](?:\w*_id|id|uid)=)(\S+)$", endpoint)
    if m:
        return (endpoint[:m.start()] + m.group(1) + str(own_id),
                endpoint[:m.start()] + m.group(1) + str(other_id))
    # 尾段数字/UUID：直接替换最后一段
    if re.search(r"/(\d+|[0-9a-fA-F-]{8,})$", endpoint):
        base, _, _ = endpoint.rpartition("/")
        return (f"{base}/{own_id}", f"{base}/{other_id}")
    return None


def similarity(a: str, b: str) -> float:
    """token 集合 Jaccard：响应结构相似度（判定'拿到的是同类数据'）。"""
    ta = {w for w in re.findall(r"[\w.\-]{4,}", a or "")[:800]}
    tb = {w for w in re.findall(r"[\w.\-]{4,}", b or "")[:800]}
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def verdict(baseline: dict, cross: dict, other_id: str) -> dict:
    """越权判定：cross = A 会话请求 B 资源的响应。"""
    if cross["status"] == 0:
        return {"hit": False, "needs_review": False, "detail": "请求失败"}
    if cross["status"] in (401, 403):
        return {"hit": False, "needs_review": False,
                "detail": f"防线正常（{cross['status']}）"}
    if cross["status"] == 200:
        sim = similarity(baseline["body"], cross["body"])
        contains_other = str(other_id) in cross["body"]
        if contains_other or sim >= 0.55:
            return {"hit": True, "needs_review": False,
                    "detail": f"平行越权命中（相似度 {sim:.2f}"
                              f"{'，含对方 ID 回显' if contains_other else ''}）"}
        if cross["length"] > 200 and cross["status"] == 200:
            # 200 但与 baseline 不像：可能是脱敏响应或错误页伪装，留语义复核
            return {"hit": False, "needs_review": True,
                    "detail": f"200 但结构存疑（相似度 {sim:.2f}），待语义复核"}
    return {"hit": False, "needs_review": True,
            "detail": f"状态 {cross['status']}，待复核"}
