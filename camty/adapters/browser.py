"""浏览器适配器（playwright）：JS 渲染侦察与会话化交互。

browser-visit：无头渲染页面 → 截图 + 可见文本 + 链接/表单/iframe 提取（SPA、
Turnstile 等 JS 强依赖场景的侦察入口）。
browser-action：动作序列执行（goto/fill/click/press/wait/screenshot/extract），
交互式动作，operator 确认后运行。
会话：storage_state 落盘 engagement 目录 browser-session.json，跨步骤复用
登录态（登录一次，后续 visit/action 带 use_session 复用 cookie+localStorage）。
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from camty.adapters.base import RunContext, ToolAdapter, ToolResult

EXTRACT_SUPPORT = "els => els.map(e => e.textContent && e.textContent.trim()).filter(Boolean)"
MAX_TEXT = 6000
MAX_LINKS = 200
MAX_BROWSER_PARALLEL = 2  # 并发 Chromium 实例上限（内存护栏，超出排队）
_BROWSER_SEM = threading.BoundedSemaphore(MAX_BROWSER_PARALLEL)

# 反自动化检测（stealth）：CDP/webdriver 特征覆盖，默认启用
_STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = window.chrome || {
  runtime: {}, loadTimes: function(){}, csi: function(){},
  app: {isInstalled: false, InstallState: {INSTALLED: 'installed', NOT_INSTALLED: 'not_installed'},
        RunningState: {RUNNING: 'running', CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run'}}
};
Object.defineProperty(navigator, 'plugins', {get: () => {
  const arr = [1, 2, 3, 4, 5];
  arr.item = function(i){ return this[i] || null; };
  arr.namedItem = function(){ return null; };
  return arr;
}});
Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh', 'en']});
const _origQuery = window.navigator.permissions && window.navigator.permissions.query;
if (_origQuery) {
  window.navigator.permissions.query = (p) =>
    p && p.name === 'notifications'
      ? Promise.resolve({state: Notification.permission})
      : _origQuery(p);
}
const _getElementById = document.getElementById.bind(document);
document.getElementById = function(id){
  const el = _getElementById(id);
  if (el && el.hasAttribute && el.hasAttribute('g-recaptcha-response') === false) {}
  return el;
};
const _iframeProto = HTMLIFrameElement.prototype;
Object.defineProperty(_iframeProto, 'contentWindow', {
  get: function(){ return this._cw || HTMLIFrameElement.prototype.__lookupGetter__('contentWindow').call(this); }
});
"""


CHALLENGE_HINTS = ("challenges.cloudflare.com", "recaptcha", "hcaptcha.com")


def _stealth_level(value) -> str:
    """三态解析：auto（默认，最保守）| on | off。

    实战结论（onyx-ai）：stealth 注入与 Turnstile 互斥（chrome runtime 伪装破坏 CF
    脚本环境，token 永不签发）。auto = 全关（兼容优先），页面带 Turnstile 时必须
    auto/off；普通 bot 检测场景显式 stealth: true。
    """
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "on", "full"):
            return "on"
        if v in ("auto", ""):
            return "auto"
        return "off"
    return "on" if value else "off"


def _launch_args(stealth) -> tuple[list, list]:
    """stealth 启动参数：剥离 --enable-automation + 屏蔽 AutomationControlled 特征。"""
    if _stealth_level(stealth) != "on":
        return [], []
    args = ["--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process"]
    ignore = ["--enable-automation", "--disable-component-extensions-with-background-pages"]
    return args, ignore


class BrowserUnavailable(RuntimeError):
    pass


def _playwright():
    """返回已启动的 playwright 上下文管理器（with _playwright() as p: ...）。"""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - 环境差异
        raise BrowserUnavailable("playwright 未安装（pip install playwright && playwright install chromium）") from exc
    return sync_playwright()


def chromium_ready() -> bool:
    try:
        with _playwright() as p:
            exe = p.chromium.executable_path
            return bool(exe) and Path(exe).exists()
    except Exception:  # noqa: BLE001 - 缺浏览器/驱动都视为不可用
        return False


def _session_path(ctx: RunContext, name: str = "default") -> Path:
    """会话文件：default 兼容旧单会话路径；具名会话（A/B 账号）分文件存。"""
    eng_dir = ctx.eng.dir
    if name in ("", "default"):
        return eng_dir / "browser-session.json"
    return eng_dir / f"browser-session-{name}.json"


def _session_exists(ctx: RunContext, name: str) -> bool:
    return _session_path(ctx, name).is_file()


def _proxy_arg(args: dict, ctx: RunContext) -> str | None:
    proxy = args.get("proxy") or (ctx.eng.context.get("proxy") if ctx.eng else None)
    return str(proxy) if proxy else None


def _new_context(browser, args: dict, ctx: RunContext):
    """按参数建浏览器上下文：UA/代理/会话复用（session_name 支持多账号）+ stealth 注入。"""
    kwargs: dict = {"viewport": {"width": 1366, "height": 900}}
    if args.get("ua"):
        kwargs["user_agent"] = str(args["ua"])
    proxy = _proxy_arg(args, ctx)
    if proxy:
        kwargs["proxy"] = {"server": proxy}
    session_name = str(args.get("session_name", "default") or "default")
    session = _session_path(ctx, session_name)
    if args.get("use_session") and session.is_file():
        kwargs["storage_state"] = str(session)
    context = browser.new_context(**kwargs)
    if _stealth_level(args.get("stealth", "auto")) == "on":
        context.add_init_script(_STEALTH_JS)
    return context


def _save_screenshot(ctx: RunContext, adapter_name: str, page, full: bool = True) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = ctx.evidence_dir / f"{stamp}-{adapter_name}.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(out), full_page=full)
    return str(out)


def _extract_page(page) -> dict:
    """页面测绘：标题/链接/表单/输入框/iframe/脚本。"""
    links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
    links = sorted(dict.fromkeys(links))[:MAX_LINKS]
    forms = page.eval_on_selector_all(
        "form",
        """els => els.map(f => ({
            action: f.action || '',
            method: (f.method || 'get').toLowerCase(),
            fields: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                name: i.name || i.id || '', type: i.type || i.tagName.toLowerCase()
            }))
        }))""",
    )
    inputs = page.eval_on_selector_all(
        "input,textarea",
        """els => els.map(i => ({name: i.name || i.id || '', type: i.type || i.tagName.toLowerCase()}))
        .filter(i => i.name)""",
    )[:60]
    frames = [{"name": f.name, "url": f.url} for f in page.frames[1:]]
    scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
    return {
        "links": links,
        "forms": forms,
        "inputs": inputs,
        "frames": frames,
        "scripts": sorted(dict.fromkeys(scripts)),
    }


def _page_digest(page) -> dict:
    try:
        text = page.inner_text("body")
    except Exception:  # noqa: BLE001 - 无 body（纯资源页）
        text = ""
    return {"title": page.title(), "url": page.url, "text": text[:MAX_TEXT]}


def _finish(result: ToolResult, page, ctx: RunContext, name: str,
            screenshots: list[str], extra_evidence: dict, save_session: bool,
            session_name: str = "default") -> ToolResult:
    if save_session:
        try:
            page.context.storage_state(path=str(_session_path(ctx, session_name)))
            extra_evidence["session_saved"] = str(_session_path(ctx, session_name))
        except Exception as exc:  # noqa: BLE001 - 会话保存失败不否定整步
            extra_evidence["session_save_error"] = str(exc)
    evidence = ctx.save_evidence(
        name, json.dumps({"result": result.data, **extra_evidence}, ensure_ascii=False, indent=2)
    )
    result.evidence = evidence
    return result


class BrowserVisitAdapter(ToolAdapter):
    name = "browser-visit"
    description = "JS 渲染侦察（playwright 无头）：截图 + 可见文本 + 链接/表单/输入框/iframe 测绘，支持代理与会话复用。"

    def available(self) -> bool:
        return chromium_ready()

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
                "wait_selector": {"type": "string", "description": "等待元素出现（SPA 渲染完成标志）"},
                "wait_ms": {"type": "integer", "description": "额外等待毫秒（动画/懒加载）", "default": 0},
                "use_session": {"type": "boolean", "description": "复用已保存的登录会话", "default": False},
                "save_session": {"type": "boolean", "description": "保存会话（cookie+localStorage）供后续复用", "default": False},
                "session_name": {"type": "string", "default": "default",
                                  "description": "具名会话（A/B 双账号鉴权矩阵时各存各的）"},
                "headless": {"type": "boolean", "default": True},
                "proxy": {"type": "string", "description": "代理地址，缺省读上下文 proxy 变量"},
                "ua": {"type": "string", "description": "自定义 User-Agent"},
                "stealth": {"oneOf": [{"type": "string", "enum": ["auto", "true", "false"]}, {"type": "boolean"}], "default": "auto", "description": "反自动化检测。auto=最保守（全关，兼容 Turnstile）；true=全开（普通 bot 检测场景）；false=显式关。实战：stealth 注入与 Turnstile 互斥，注册/验证码页面必须 auto 或 false"},
                "screenshot": {"type": "boolean", "default": True},
            },
            "required": ["url"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        url = str(args["url"]).strip()
        ctx.scope.require(url)
        session_name = str(args.get("session_name", "default") or "default")
        with _BROWSER_SEM:  # 并发内存护栏：超出上限排队
            with _playwright() as p:
                extra_args, ignore_args = _launch_args(args.get("stealth", "auto"))
                browser = p.chromium.launch(
                    headless=bool(args.get("headless", True)),
                    args=extra_args, ignore_default_args=ignore_args)
                try:
                    context = _new_context(browser, args, ctx)
                    page = context.new_page()
                    resp = page.goto(url, wait_until="domcontentloaded",
                                     timeout=int(args.get("timeout_ms", 30000)))
                    if args.get("wait_selector"):
                        page.wait_for_selector(str(args["wait_selector"]), timeout=15000)
                    if int(args.get("wait_ms", 0)) > 0:
                        page.wait_for_timeout(int(args["wait_ms"]))
                    digest = _page_digest(page)
                    data = {
                        **digest,
                        **_extract_page(page),
                        "status": resp.status if resp else None,
                        "headers": dict(resp.headers) if resp else {},
                    }
                    # Turnstile/验证码检测：提示下一步 stealth 策略（实战互斥结论）
                    challenge = any(
                        any(hint in (f.get("url") or "") for hint in CHALLENGE_HINTS)
                        for f in data.get("frames", []))
                    if challenge:
                        data["challenge_widget"] = "turnstile/recaptcha"
                        data["stealth_advice"] = "检测到验证码组件：注册/提交页面保持 stealth=auto/off（注入互斥）"
                    # WAF 指纹：被动响应头特征 → context + tech_map（触发战术手册提示）
                    from camty.modules.waf import detect as waf_detect

                    wafs = waf_detect(data["headers"])
                    if wafs:
                        data["waf"] = wafs
                        existing_waf = ctx.eng.context.get("waf") or [] if ctx.eng else []
                        for w in wafs:
                            if w not in existing_waf:
                                existing_waf.append(w)
                        if ctx.eng:
                            ctx.eng.context["waf"] = existing_waf
                            tech_map = ctx.eng.context.setdefault("tech_map", {})
                            page_techs = tech_map.setdefault(url, [])
                            for w in wafs:
                                if w not in page_techs:
                                    page_techs.append(w)
                    shots = []
                    if args.get("screenshot", True):
                        shots.append(_save_screenshot(ctx, self.name, page))
                    result = ToolResult(
                        summary=f"渲染 {digest['title'][:60]}（{len(data['links'])} 链接，"
                                f"{len(data['forms'])} 表单，状态 {data['status']}）",
                        data={"page": data, "screenshots": shots},
                    )
                    result = _finish(result, page, ctx, self.name, shots,
                                     {"url": url}, bool(args.get("save_session")), session_name)
                    ctx.audit.record(self.name, {"url": url}, ok=True,
                                     note=f"{digest['title'][:40]}")
                    return result
                finally:
                    browser.close()


class BrowserActionAdapter(ToolAdapter):
    name = "browser-action"
    description = (
        "浏览器交互序列（playwright）：goto/fill/click/press/wait_selector/wait/screenshot/extract_text。"
        "适用于登录表单、动态按钮等场景；会改变站点状态，需 operator 确认。"
    )
    requires_confirm = True

    def available(self) -> bool:
        return chromium_ready()

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "actions": {
                    "type": "array",
                    "description": "动作序列，如 [{type:'goto',url:...},{type:'fill',selector,value},"
                                   "{type:'click',selector},{type:'extract_text'}]",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string",
                                     "enum": ["goto", "fill", "click", "press", "wait_selector",
                                              "wait", "screenshot", "extract_text", "extract_attr"]},
                            "url": {"type": "string"},
                            "selector": {"type": "string"},
                            "value": {"type": "string"},
                            "key": {"type": "string"},
                            "ms": {"type": "integer"},
                            "attr": {"type": "string"},
                        },
                        "required": ["type"],
                    },
                },
                "start_url": {"type": "string", "description": "初始 URL（省略则从 goto 动作开始）"},
                "use_session": {"type": "boolean", "description": "复用已保存的登录会话", "default": False},
                "save_session": {"type": "boolean", "description": "动作完成后保存会话（登录成功后置 true）", "default": False},
                "session_name": {"type": "string", "default": "default",
                                 "description": "具名会话（A/B 双账号鉴权矩阵用）"},
                "headless": {"type": "boolean", "default": True},
                "proxy": {"type": "string"},
                "ua": {"type": "string"},
                "stealth": {"oneOf": [{"type": "string", "enum": ["auto", "true", "false"]}, {"type": "boolean"}], "default": "auto", "description": "反自动化检测。auto=最保守（全关，兼容 Turnstile）；true=全开（普通 bot 检测场景）；false=显式关。实战：stealth 注入与 Turnstile 互斥，注册/验证码页面必须 auto 或 false"},
                "timeout_ms": {"type": "integer", "default": 30000},
            },
            "required": ["actions"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        actions = args.get("actions", [])
        if not actions:
            return ToolResult(summary="动作序列为空", data={})
        for act in actions:
            if act.get("type") == "goto" and act.get("url"):
                ctx.scope.require(str(act["url"]))
        if args.get("start_url"):
            ctx.scope.require(str(args["start_url"]))
        session_name = str(args.get("session_name", "default") or "default")
        with _BROWSER_SEM:  # 并发内存护栏：超出上限排队
            with _playwright() as p:
                extra_args, ignore_args = _launch_args(args.get("stealth", "auto"))
                browser = p.chromium.launch(
                    headless=bool(args.get("headless", True)),
                    args=extra_args, ignore_default_args=ignore_args)
                try:
                    context = _new_context(browser, args, ctx)
                    page = context.new_page()
                    timeout = int(args.get("timeout_ms", 30000))
                    if args.get("start_url"):
                        page.goto(str(args["start_url"]), wait_until="domcontentloaded", timeout=timeout)
                    log: list[dict] = []
                    shots: list[str] = []
                    extracted: dict = {}
                    for act in actions:
                        kind = act.get("type", "")
                        if kind == "goto":
                            page.goto(str(act["url"]), wait_until="domcontentloaded", timeout=timeout)
                            log.append({"type": "goto", "url": page.url})
                        elif kind == "fill":
                            page.fill(str(act["selector"]), str(act.get("value", "")), timeout=timeout)
                            log.append({"type": "fill", "selector": act["selector"]})
                        elif kind == "click":
                            page.click(str(act["selector"]), timeout=timeout)
                            log.append({"type": "click", "selector": act["selector"]})
                        elif kind == "press":
                            target = act.get("selector")
                            if target:
                                page.press(str(target), str(act.get("key", "Enter")), timeout=timeout)
                            else:
                                page.keyboard.press(str(act.get("key", "Enter")))
                            log.append({"type": "press", "key": act.get("key", "Enter")})
                        elif kind == "wait_selector":
                            page.wait_for_selector(str(act["selector"]), timeout=timeout)
                            log.append({"type": "wait_selector", "selector": act["selector"]})
                        elif kind == "wait":
                            page.wait_for_timeout(int(act.get("ms", 1000)))
                            log.append({"type": "wait", "ms": act.get("ms", 1000)})
                        elif kind == "screenshot":
                            shots.append(_save_screenshot(ctx, self.name, page))
                            log.append({"type": "screenshot"})
                        elif kind == "extract_text":
                            selector = act.get("selector", "body")
                            text = page.inner_text(str(selector)) if selector else ""
                            extracted[f"text:{selector}"] = text[:MAX_TEXT]
                            log.append({"type": "extract_text", "selector": selector, "chars": len(text)})
                        elif kind == "extract_attr":
                            val = page.get_attribute(str(act["selector"]), str(act.get("attr", "href")))
                            extracted[f"attr:{act['selector']}@{act.get('attr', 'href')}"] = val
                            log.append({"type": "extract_attr", "selector": act["selector"]})
                    digest = _page_digest(page)
                    result = ToolResult(
                        summary=f"执行 {len(actions)} 个动作，最终页 {digest['title'][:50]}（{digest['url']}）",
                        data={
                            "page": {**digest, **_extract_page(page)},
                            "actions_log": log,
                            "extracted": extracted,
                            "screenshots": shots,
                        },
                    )
                    result = _finish(result, page, ctx, self.name, shots,
                                     {"actions": actions}, bool(args.get("save_session")),
                                     session_name)
                    ctx.audit.record(self.name, {"n_actions": len(actions), "final_url": digest["url"]},
                                     ok=True, note=digest["title"][:40])
                    return result
                finally:
                    browser.close()
