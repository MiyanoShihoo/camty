"""HTTP 指纹伪装：curl_cffi chrome impersonation（JA3/HTTP2 指纹与真实浏览器一致）。

vendor 里有 curl_cffi 时所有纯 HTTP 侦察/注入/越权流量走 Chrome 指纹；
未安装或调用异常自动回退 urllib（不阻塞交战）。CAMTY_NO_IMPERSONATE=1 强制关闭。
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

IMPERSONATE = os.environ.get("CAMTY_IMPERSONATE", "chrome")


def available() -> bool:
    if os.environ.get("CAMTY_NO_IMPERSONATE"):
        return False
    try:
        import camty  # noqa: F401 - 触发 vendor 挂载

        from curl_cffi import requests as _cr  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def fetch(url: str, method: str = "GET", headers: dict | None = None,
          body: bytes | None = None, timeout: float = 15.0,
          impersonate: str | None = None) -> tuple[str | None, int | None] | None:
    """Chrome 指纹请求。可用性不足时返回 None（调用方回退 urllib）。

    返回 (text, status)；HTTPError 也归为正常返回（注入判定需要 4xx/5xx body）。
    """
    if not available():
        return None
    try:
        from curl_cffi import requests as cr

        resp = cr.request(
            method, url, data=body, headers=headers or {},
            timeout=timeout, impersonate=impersonate or IMPERSONATE,
            allow_redirects=True)
        return resp.text, resp.status_code
    except Exception:  # noqa: BLE001 - 指纹层故障不阻塞探测
        return None


def fetch_or_urllib(urllib_fetch, url: str, **kwargs):
    """优先指纹层，失败回退原 urllib 取数函数（模块无缝接入）。

    urllib_fetch 签名: (url, timeout=...) -> (text, status)
    """
    out = fetch(url, kwargs.get("method", "GET"),
                headers=kwargs.get("headers"), body=kwargs.get("body"),
                timeout=kwargs.get("timeout", 15.0))
    if out is not None:
        return out
    return urllib_fetch(url, timeout=kwargs.get("timeout", 15.0))
