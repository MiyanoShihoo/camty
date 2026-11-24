"""Repeater：交互式请求重放与向量批测。

实战教训（BSCP 考场首窗口）：每测一条向量要写一个脚本并重建会话，80 分钟只跑完
15 条向量。Repeater 把这个循环压成一次调用——

- 持久会话：cookie 全程携带（无状态请求拿空壳页/CSRF 断连的坑一次治死）
- CSRF 自动跟随：POST 前自动拉表单页提取 csrf 注入 body
- 向量批测：一次打 N 条 payload，按 (状态码, 体量桶, 错误标记, 标题) 聚类，
  只有偏离基线的异类簇需要人眼看——吞吐的倍增器
- 浏览器模式：需要 JS 渲染/真实指纹的页面走持久 stealth 浏览器
- 治理不因提速缺席：每请求过 scope 白名单 + DNS 校验 + 限速 + 审计哈希链

CLI:  python -m camty repeater engagements/psxam.yaml [--port 8895]
API:  POST /req  {method,url,headers,body,mode,auto_csrf}
      POST /vector {url,param,payloads[],method,body,mode,baseline}
      POST /seq   {requests:[{...},...]}
      GET  /log /state ；POST /stop
"""

from __future__ import annotations

import html as html_mod
import json
import os
import queue
import re
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from camty.guardrail.audit import Audit
from camty.guardrail.scope import Scope, ScopeError

ERROR_MARKERS = [
    "internal server", "syntax error", "uncaught exception", "traceback",
    "sqlerror", "unclosed quotation", "you have an error in your sql",
]
_SIZE_BUCKET = 64  # 体量聚类容差（字节）

_tls_warned = False


def _tls_insecure() -> bool:
    """TLS 降级须显式 CAMTY_TLS_INSECURE=1。

    urllib 回退路径默认保留系统证书校验——此前回退无条件 CERT_NONE，
    缺 curl_cffi 的机器会静默变成不验证（携会话 Cookie 的流量可被 MITM）。
    自签靶场确需关闭时用环境变量显式选择，且首次生效时打警告。
    """
    global _tls_warned
    if os.environ.get("CAMTY_TLS_INSECURE", "") != "1":
        return False
    if not _tls_warned:
        _tls_warned = True
        print("[camty] CAMTY_TLS_INSECURE=1：TLS 证书校验已禁用（自签靶场显式选择，勿用于公网）",
              file=sys.stderr)
    return True


def _analyze_html(body: str) -> dict:
    """从 HTML 响应自动提取测试者反复手写的那些东西：标题/表单/CSRF/错误标记。"""
    out: dict = {}
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.DOTALL | re.IGNORECASE)
    out["title"] = html_mod.unescape(m.group(1)).strip()[:120] if m else ""
    h1 = re.findall(r"<h1[^>]*>(.*?)</h1>", body, re.DOTALL | re.IGNORECASE)
    out["h1"] = [html_mod.unescape(x).strip()[:80] for x in h1[:3]]
    # 表单（lab HTML 属性常不带引号——两种都认）
    out["forms"] = [
        {"action": a or "(self)", "method": (m or "GET").upper()}
        for a, m in re.findall(r"<form[^>]*?action=[\"']?([^\"'> ]*)[^>]*?method=[\"']?([^\"'> ]*)", body)
    ] + [
        {"action": a or "(self)", "method": (m or "GET").upper()}
        for m, a in re.findall(r"<form[^>]*?method=[\"']?([^\"'> ]*)[^>]*?action=[\"']?([^\"'> ]*)", body)
    ]
    out["csrf"] = (re.findall(r'name=["\']?csrf["\']?[^>]*value=["\']?([A-Za-z0-9_-]+)', body)
                   or re.findall(r'value=["\']?([A-Za-z0-9_-]+)["\']?[^>]*name=["\']?csrf', body))[:2]
    out["inputs"] = sorted({n for n in re.findall(r"<input[^>]*?name=[\"']?([A-Za-z_][\w.-]*)", body)})[:12]
    low = body.lower()
    out["errors"] = [mk for mk in ERROR_MARKERS if mk in low]
    out["cookies_set"] = re.findall(r"set-cookie:\s*([^;]+)", low)[:6]
    return out


def _fingerprint(status: int, body: str, analysis: dict) -> str:
    """响应指纹：同指纹的响应聚成一簇。体量按桶聚，容忍计数器/时间戳噪声。"""
    return "|".join([
        str(status),
        str(len(body) // _SIZE_BUCKET),
        analysis.get("title", "")[:40],
        ",".join(analysis.get("errors", [])),
        "Y" if analysis.get("csrf") else "-",
    ])


class RepeaterSession:
    """一个交战的持久测试会话：cookie jar + 可选持久浏览器 + 治理三闸。"""

    def __init__(self, eng):
        self.eng = eng
        self.scope: Scope = eng.scope
        self.audit: Audit = eng.audit
        self.name = getattr(eng, "name", "engagement")
        self.log: list[dict] = []          # 请求历史（内存，/log 端点回放）
        self._baselines: dict[str, str] = {}  # "METHOD path" -> 指纹（首响自动锚定）
        self._cookies: dict[str, str] = {}  # host -> "k=v; k2=v2"
        self._ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        self._browser: _BrowserWorker | None = None
        self._lock = threading.Lock()

    # ---------- 底层 HTTP：curl_cffi 优先（Chrome 指纹），urllib 回退 ----------

    def _http(self, method: str, url: str, headers: dict | None, body) -> tuple[int, dict, str]:
        hdrs = {"User-Agent": self._ua, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9"}
        if headers:
            hdrs.update({k: v for k, v in headers.items() if v is not None})
        host = urlsplit(url).hostname or ""
        # 显式 Cookie 头（会话劫持重放）优先；无显式头才用会话 jar
        explicit_cookie = bool(headers and any(k.lower() == "cookie" for k in headers))
        if self._cookies.get(host) and not explicit_cookie:
            hdrs["Cookie"] = self._cookies[host]
        data = None
        if body is not None:
            data = urlencode(body) if isinstance(body, dict) else str(body)
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        try:
            from curl_cffi import requests as cr

            r = cr.request(method, url, headers=hdrs, data=data, timeout=20,
                           impersonate="chrome131", allow_redirects=False,
                           verify=not _tls_insecure())
            status, rh, text = r.status_code, dict(r.headers), r.text
        except ImportError:
            import ssl
            import urllib.request

            req = urllib.request.Request(url, data=data.encode() if data else None,
                                         headers=hdrs, method=method)

            class _NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw):  # noqa: N802
                    return None
            handlers = [_NoRedir]
            # 默认走 urllib 系统证书校验（不带自定义 HTTPSHandler）；显式降级才关闭
            if _tls_insecure():
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                handlers.append(urllib.request.HTTPSHandler(context=ctx))
            opener = urllib.request.build_opener(*handlers)
            try:
                resp = opener.open(req, timeout=20)
                status, rh, text = resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                status, rh, text = e.code, dict(e.headers), e.read().decode("utf-8", "replace")
        # 收 cookie（Set-Cookie 可能多条；curl_cffi 合并为逗号分隔，urllib 单条）
        for sc in [v for k, v in rh.items() if k.lower() == "set-cookie"]:
            for pair in re.split(r",(?=[^;]+=)", sc):
                kv = pair.split(";")[0].strip()
                if "=" in kv:
                    jar = self._cookies.setdefault(host, "")
                    parts = [p for p in jar.split("; ") if p and p.split("=")[0] != kv.split("=")[0]]
                    parts.append(kv)
                    self._cookies[host] = "; ".join(parts)
        return status, rh, text

    # ---------- 浏览器模式（懒启动、持久复用）----------

    def _worker(self) -> "_BrowserWorker":
        if self._browser is None:
            self._browser = _BrowserWorker(self.eng)
            self._browser.start()
        return self._browser

    # ---------- 公共 API ----------

    def send(self, method: str = "GET", url: str = "", headers: dict | None = None,
             body=None, mode: str = "http", auto_csrf: str = "", render: bool = False,
             record: bool = True) -> dict:
        """单发。auto_csrf=表单页 URL 时：先 GET 该页提取 csrf 并入 body（会话绑定坑治死）。
        render=True 时走浏览器完整渲染（执行 JS 后取 DOM）。"""
        method = method.upper()
        self.scope.require(url)
        t0 = time.monotonic()
        if auto_csrf:
            form_resp = self.send("GET", auto_csrf, mode=mode, record=record)
            token = (form_resp.get("analysis", {}).get("csrf") or [""])[0]
            if token:
                body = dict(body or {})
                body.setdefault("csrf", token)
        if mode == "browser":
            res = self._worker().request(method, url, headers, body, render)
            status, rh, text = res
        else:
            status, rh, text = self._http(method, url, headers, body)
        ms = round((time.monotonic() - t0) * 1000)
        ctype = next((v for k, v in rh.items() if k.lower() == "content-type"), "")
        analysis = _analyze_html(text) if "html" in (ctype + text[:300]).lower() else {}
        fp = _fingerprint(status, text, analysis)
        base_key = f"{method} {urlsplit(url).path or '/'}"
        with self._lock:
            if base_key not in self._baselines:
                self._baselines[base_key] = fp
            diff = fp != self._baselines[base_key]
        entry = {
            "n": len(self.log) + 1, "ts": time.strftime("%H:%M:%S"), "method": method,
            "url": url, "status": status, "ms": ms, "size": len(text),
            "fingerprint": fp, "analysis": analysis,
            "diff_baseline": diff,
            "location": rh.get("Location", rh.get("location", "")),
        }
        body_s = None
        if body is not None:
            body_s = urlencode(body) if isinstance(body, dict) else str(body)
        with self._lock:
            self.log.append({**entry, "body": (body_s or "")[:300]})
        if record:
            self.audit.record("repeater", {"method": method, "url": url, "status": status},
                              ok=(status < 400), note=f"{ms}ms size={len(text)}")
        return {**entry, "headers": {k: v for k, v in rh.items() if k.lower() not in ("set-cookie",)},
                "body": text}

    def vector(self, url: str, param: str, payloads: list, method: str = "GET",
               body: dict | None = None, mode: str = "http", baseline: str | None = None,
               gap: str = "url", render: bool | None = None, auto_csrf: str = "",
               headers: dict | None = None) -> dict:
        """批测：N 条 payload 一次打完，按指纹聚类，返回基线簇 + 异类簇。
        gap=url 时 payload 进 query 参数；gap=body 时进表单字段。"""
        results: list[dict] = []
        for p in payloads:
            rrender = (mode == "browser") if render is None else render
            if gap == "body":
                b = dict(body or {}); b[param] = p
                r = self.send(method, url, body=b, mode=mode, record=False,
                              render=rrender, auto_csrf=auto_csrf, headers=headers)
            else:
                sep = "&" if "?" in url else "?"
                q = urlencode({param: p})
                r = self.send(method, f"{url}{sep}{q}", body=body, mode=mode,
                              record=False, render=rrender, auto_csrf=auto_csrf,
                              headers=headers)
            results.append({"payload": p, "status": r["status"], "ms": r["ms"],
                            "size": r["size"], "fingerprint": r["fingerprint"],
                            "errors": r["analysis"].get("errors", []),
                            "title": r["analysis"].get("title", "")})
        if baseline is not None:
            bfp = next((r["fingerprint"] for r in results if r["payload"] == baseline), None)
        else:
            bfp = results[0]["fingerprint"] if results else None
        clusters: dict[str, list] = {}
        for r in results:
            clusters.setdefault(r["fingerprint"], []).append(r["payload"])
        outliers = {fp: ps for fp, ps in clusters.items() if fp != bfp}
        self.audit.record("repeater-vector", {"url": url, "param": param, "n": len(payloads)},
                          note=f"clusters={len(clusters)} outliers={len(outliers)}")
        return {
            "url": url, "param": param, "baseline_fp": bfp, "n": len(payloads),
            "clusters": [{"fingerprint": fp, "payloads": ps, "outlier": fp != bfp}
                         for fp, ps in clusters.items()],
            "results": results,
        }

    def seq(self, requests: list[dict]) -> list[dict]:
        """顺序流：登录→动作→登出这类链，cookie 全程携带。"""
        out = []
        for r in requests:
            out.append(self.send(**r))
        return out

    def state(self) -> dict:
        return {
            "engagement": self.name,
            "requests": len(self.log),
            "baselines": dict(self._baselines),
            "cookies": {h: (v[:60] + "...") for h, v in self._cookies.items()},
            "browser_alive": bool(self._browser and self._browser.alive),
        }

    def close(self) -> None:
        if self._browser:
            self._browser.stop()
            self._browser = None


class _BrowserWorker:
    """独立线程持有 sync playwright（sync API 不能在 uvicorn 事件循环里跑）。"""

    def __init__(self, eng):
        self.eng = eng
        self.alive = False
        self._tasks: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._task(lambda: None).get(timeout=30)  # 等浏览器就绪
        self.alive = True

    def _run(self) -> None:
        from playwright.sync_api import sync_playwright

        session_path = None
        try:
            sd = Path(self.eng.dir) / "sessions"
            session_path = sd / "repeater.json"
            if not session_path.exists():
                session_path = None
        except Exception:  # noqa: BLE001
            session_path = None
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True,
                                        args=["--disable-blink-features=AutomationControlled"])
            kw = {"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}
            if session_path:
                kw["storage_state"] = str(session_path)
            ctx = browser.new_context(**kw)
            ctx.add_init_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
                "window.chrome=window.chrome||{runtime:{}};")
            page = ctx.new_page()
            while True:
                task, rslot = self._tasks.get()
                if task is None:
                    break
                try:
                    rslot.put(task(page, ctx))
                except Exception as e:  # noqa: BLE001
                    rslot.put((0, {}, f"browser-error: {e}"))
            try:
                sd2 = Path(self.eng.dir) / "sessions"
                sd2.mkdir(parents=True, exist_ok=True)
                ctx.storage_state(path=str(sd2 / "repeater.json"))
            except Exception:  # noqa: BLE001
                pass
            browser.close()

    def _task(self, fn):
        rslot: queue.Queue = queue.Queue()
        self._tasks.put((fn, rslot))
        return rslot

    def request(self, method: str, url: str, headers: dict | None, body, render: bool) -> tuple:
        def do(page, ctx):
            if render:
                page.goto(url, timeout=45000, wait_until="domcontentloaded")
                page.wait_for_timeout(600)
                return page.response.status if hasattr(page, "response") else 200, {}, page.content()
            b = None
            if body is not None:
                b = urlencode(body) if isinstance(body, dict) else str(body)
            resp = ctx.request.fetch(
                url, method=method, headers=headers or {}, data=b, timeout=45000,
                fail_on_status_code=False)
            return resp.status, dict(resp.headers), resp.text()
        return self._task(do).get(timeout=60)

    def stop(self) -> None:
        self._tasks.put((None, queue.Queue()))
        self.alive = False


# ---------- FastAPI 守护（可选依赖，与面板一致）----------

def main(engagement_path: str, port: int = 8895) -> None:
    import uvicorn

    from camty.agent.state import Engagement
    from camty.repeater_api import build_app

    eng = Engagement(engagement_path)
    session = RepeaterSession(eng)
    app = build_app(session)
    print(f"Repeater 就绪: http://127.0.0.1:{port} (engagement={eng.name})")
    print(f"用法: POST /req {{\"method\":\"GET\",\"url\":\"...\"}} | /vector | /seq | GET /log")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
