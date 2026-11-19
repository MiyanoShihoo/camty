"""内容发现（目录/敏感路径）：字典驱动 + SPA fallback 基线判别。

SPA 站点对任意不存在路径都返回 200 的前端 HTML（fallback 路由），
不做基线判别会全量误报。基线：取一个肯定不存在的路径响应指纹，
dir 响应与基线显著不同（长度差/内容差/JSON/跳转）才算发现。
"""

from __future__ import annotations

import hashlib
import re
import random
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

DEFAULT_WORDLISTS = [
    r"E:\AI tools\wordlists\web\common.txt",
    r"E:\AI tools\wordlists\web\api-endpoints.txt",
]


def _fetch_head(url: str, timeout: float = 12.0):
    """返回 (status, length, sha, content_type)。"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(500_000)
            return resp.status, len(body), hashlib.sha256(body).hexdigest()[:16], resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        return exc.code, 0, "", ""
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, 0, "", ""


def load_words(wordlists: list[str] | None, limit: int = 6000) -> list[str]:
    words = []
    seen = set()
    for path in (wordlists or DEFAULT_WORDLISTS):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    w = line.strip()
                    if w and not w.startswith("#") and w not in seen and not re.search(r"\s", w):
                        seen.add(w)
                        words.append(w)
        except OSError:
            continue
    return words[:limit]


def scan(base_url: str, wordlists: list[str] | None = None,
         workers: int = 12, limit: int = 6000,
         should_stop=None, progress=None) -> list[dict]:
    """返回 [{url, status, length, content_type}] 的发现清单（已过基线判别）。"""
    base_url = base_url.rstrip("/") + "/"
    # 基线：肯定不存在的随机路径 × 2，取稳定指纹
    random.seed()
    probes = [f"camty-nonexistent-{random.randrange(10**9)}", f"camty-nonexistent-{random.randrange(10**9)}"]
    baselines = [_fetch_head(urljoin(base_url, p)) for p in probes]
    statuses = {b[0] for b in baselines}
    if not statuses or statuses == {None}:
        return []
    fallback_status = next(iter(statuses))
    baseline_lens = {b[1] for b in baselines if b[0] == fallback_status}
    baseline_hashes = {b[2] for b in baselines if b[0] == fallback_status}

    words = load_words(wordlists, limit)
    found = []
    done = 0

    def check(word: str):
        url = urljoin(base_url, word)
        status, length, sha, ctype = _fetch_head(url)
        if status is None:
            return None
        is_fallback = (
            status == fallback_status
            and (sha in baseline_hashes
                 or (length in baseline_lens and status == 200 and "html" in ctype))
        )
        if status in (200, 201, 204, 301, 302, 401, 403) and not is_fallback:
            return {"url": url, "status": status, "length": length, "content_type": ctype}
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(check, words):
            done += 1
            if progress and done % 500 == 0:
                progress(done, len(words))
            if result:
                found.append(result)
                if should_stop and should_stop(found):
                    break
    return found
