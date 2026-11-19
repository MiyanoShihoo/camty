"""WAF 指纹识别：响应头特征库（供 browser-visit 等拿到真实响应头的适配器调用）。

检出后：写 eng.context["waf"]（列表）+ 并入 tech_map 触发战术手册提示
（降速/换面/禁高频目录爆破），全程被动特征，不发探测请求。
"""

from __future__ import annotations

WAF_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("cloudflare", ("cf-ray", "cf-cache-status", "__cfduid", "server:cloudflare")),
    ("sucuri", ("x-sucuri", "server: suctech")),
    ("akamai", ("x-akamai", "akamai-transformed", "server: akamaighost")),
    ("imperva", ("x-iinfo", "x-cdn: imperva")),
    ("f5-bigip", ("bigipserver", "x-waf: f5")),
    ("aliyun-waf", ("aliyun-waf", "eos-waf")),
    ("safedog", ("safedog", "waf-2.0")),
    ("baidu-yunjia", ("yunsuoshield", "yunjiasu")),
    ("qianxin-waf", ("qianxin",)),
    ("modsecurity", ("mod_security", "modsecurity")),
    ("aws-waf", ("awswaf", "x-amzn-waf")),
    ("yundun", ("yundun", "scdn")),
    ("binfense", ("binfense",)),
    ("anquanbao", ("anquanbao",)),
]


def detect(headers: dict) -> list[str]:
    """从响应头识别 WAF。返回命中的 WAF 名列表（大小写不敏感子串匹配）。"""
    if not headers:
        return []
    flat = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    joined = {f"{k}: {v}" for k, v in flat.items()} | set(flat.keys()) | set(flat.values())
    hits = []
    for name, signatures in WAF_SIGNATURES:
        for sig in signatures:
            if any(sig in part for part in joined):
                hits.append(name)
                break
    return hits
