"""browser/impacket 升级冒烟：本地靶机 + 真实 playwright 全链。

布局：<tmp>/engagements/smoke.yaml + <tmp>/packs/browser-smoke/pack.yaml
靶机：127.0.0.1:8765 SPA 页（登录表单 + fetch 调用 + localStorage 会话）
链路：browser-visit(测绘) → browser-action(登录+存会话) → browser-visit(use_session 复用)
     → js-recon(真实 HTTP 端点提取) → secretsdump available=False（AV 隔离优雅降级）
"""

import json
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from camty.adapters.base import RunContext
from camty.adapters.registry import REGISTRY
from camty.guardrail.audit import Audit
from camty.guardrail.scope import Scope

PAGE = """<!DOCTYPE html><html><head><title>CamtySmoke</title>
<script src="/app.js"></script></head>
<body>
<h1>Smoke Target</h1>
<a href="/docs">Docs</a><a href="https://example.com/leave">Leave</a>
<form id="login" action="/api/auth/login" method="post">
<input name="username" type="text"><input name="password" type="password">
<button type="submit" id="go">Sign in</button></form>
<div id="status">anonymous</div>
<iframe src="/frame"></iframe>
<script>
document.getElementById('login').addEventListener('submit', e => {
  e.preventDefault();
  localStorage.setItem('token', 'camty-session-token');
  document.getElementById('status').textContent = 'logged-in';
});
</script>
</body></html>"""

APP_JS = """
fetch("/api/users").then(r => r.json());
const cfg = {admin: "/api/admin/settings"};
//# sourceMappingURL=app.js.map
const API_KEY = "sk-proj-smoke1234567890abcdefghij";
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/":
            body = PAGE
        elif self.path == "/app.js":
            body = APP_JS
        elif self.path == "/frame":
            body = "<html><body>inner</body></html>"
        else:
            body = "ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if self.path != "/app.js" else "application/javascript")
        self.end_headers()
        self.wfile.write(body.encode())


def serve():
    srv = HTTPServer(("127.0.0.1", 8765), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    tmp = Path(tempfile.mkdtemp(prefix="camty-smoke-"))
    (tmp / "packs" / "browser-smoke").mkdir(parents=True)
    (tmp / "packs" / "browser-smoke" / "pack.yaml").write_text(
        "name: browser-smoke\nphases:\n  - id: smoke\n    title: 冒烟\n    steps: []\n",
        encoding="utf-8",
    )
    eng_dir = tmp / "engagements" / "smoke"
    eng_dir.mkdir(parents=True)
    (eng_dir / "smoke").mkdir(exist_ok=True)
    scope = Scope({"domains": [], "ips": ["127.0.0.1"], "min_interval_seconds": 0})
    audit = Audit(eng_dir / "smoke" / "audit.jsonl")

    class Eng:
        dir = eng_dir / "smoke"
        context = {"proxy": ""}

    ctx = RunContext(scope, audit, Eng.dir / "evidence", ledger=None, eng=Eng)
    url = "http://127.0.0.1:8765/"
    results = []

    # 1) browser-visit 测绘
    r = REGISTRY["browser-visit"].run({"url": url, "save_session": True, "wait_ms": 500}, ctx)
    page = r.data["page"]
    results.append(("visit 测绘", r.summary))
    assert "CamtySmoke" in page["title"], page
    assert "/docs" in page["links"][0] or any("/docs" in l for l in page["links"]), page["links"]
    assert page["forms"] and page["forms"][0]["action"].endswith("/api/auth/login"), page["forms"]
    assert {"name": "username", "type": "text"} in page["inputs"], page["inputs"]
    assert page["frames"] and page["frames"][0]["url"].endswith("/frame"), page["frames"]
    assert Path(r.data["screenshots"][0]).exists()

    # 2) browser-action 登录交互（fill + click JS 写 localStorage）+ 存会话
    actions = [
        {"type": "fill", "selector": "input[name=username]", "value": "camty"},
        {"type": "fill", "selector": "input[name=password]", "value": "hunter2"},
        {"type": "click", "selector": "#go"},
        {"type": "wait", "ms": 400},
        {"type": "extract_text", "selector": "#status"},
    ]
    r2 = REGISTRY["browser-action"].run(
        {"actions": actions, "start_url": url, "save_session": True}, ctx)
    results.append(("action 登录", r2.summary))
    # 页面 JS 在 click 后写 localStorage + 改状态文本
    session_file = Eng.dir / "browser-session.json"
    assert session_file.exists(), "会话未落盘"
    state = json.loads(session_file.read_text(encoding="utf-8"))
    assert state.get("origins"), state  # storage_state 带 localStorage

    # 3) use_session 复用：新上下文带 cookie/localStorage
    r3 = REGISTRY["browser-visit"].run({"url": url, "use_session": True, "wait_ms": 300}, ctx)
    results.append(("会话复用", r3.summary))
    assert r3.data["page"]["title"] == "CamtySmoke"

    # 4) js-recon 真实 HTTP 提取
    r4 = REGISTRY["js-recon"].run({"targets": url}, ctx)
    endpoints = [e["endpoint"] for e in r4.data["endpoints"]]
    results.append(("js-recon", r4.summary))
    assert any(e.endswith("/api/users") for e in endpoints), endpoints
    assert any(e.endswith("/api/admin/settings") for e in endpoints), endpoints
    assert any(m.endswith("app.js.map") for m in r4.data["sourcemaps"]), r4.data["sourcemaps"]
    assert r4.data["secrets"], "secret 未提取"

    # 5) AV 隔离工具优雅降级
    results.append(("secretsdump available", str(REGISTRY["secretsdump"].available())))

    for name, summary in results:
        print(f"[{name}] {summary}")
    print("SMOKE OK")
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    srv = serve()
    try:
        main()
    finally:
        srv.shutdown()
