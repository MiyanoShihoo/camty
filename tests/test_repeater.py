"""Repeater 测试：持久会话 / scope 三闸 / CSRF 自动跟随 / 向量聚类 / 审计链 / 顺序流。"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from camty.agent.state import Engagement
from camty.repeater import RepeaterSession


def _write_eng(base: Path, host: str) -> Path:
    """最小交战配置：single-web pack + 指向本地靶机的 scope。"""
    packs = base / "packs" / "single-web"
    packs.mkdir(parents=True, exist_ok=True)
    (packs / "pack.yaml").write_text(
        "name: single-web\nphases:\n  - id: probe\n    steps: []\n", encoding="utf-8")
    cfg = base / "eng.yaml"
    cfg.write_text(f"""
name: rpt-test
pack: single-web
scope:
  domains: ["{host}"]
  min_interval_seconds: 0
auto_confirm: true
""", encoding="utf-8")
    return cfg


class _Target(BaseHTTPRequestHandler):
    """靶机：cookie 回显 / csrf 表单 / 参数分叉响应 / 顺序状态。"""

    def _send(self, status: int, body: str, ctype: str = "text/html; charset=utf-8",
              cookies: list[str] | None = None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for c in cookies or []:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/set":
            self._send(200, "cookie set page", cookies=["session=abc123; Path=/"])
        elif u.path == "/echo":
            ck = self.headers.get("Cookie", "")
            self._send(200, f"COOKIE[{ck}] Q[{q.get('q','')}]")
        elif u.path == "/form":
            self._send(200, '<form method=POST action=/post>'
                            '<input type=hidden name=csrf value=tok-XYZ>'
                            '<input name=textfield></form>')
        elif u.path == "/fork":
            v = q.get("p", "")
            if v == "boom":
                self._send(500, "Internal Server Error boom")
            elif v == "big":
                self._send(200, "x" * 400)
            elif v == "sqlerr":
                self._send(200, "You have an error in your SQL syntax near")
            else:
                self._send(200, "normal response page")
        elif u.path == "/login":
            self._send(200, "logged-in-ok", cookies=["auth=1; Path=/"])
        elif u.path == "/whoami":
            ck = self.headers.get("Cookie", "")
            self._send(200, f"AUTH[{ 'yes' if 'auth=1' in ck else 'no' }]")
        else:
            self._send(404, "Not Found")

    def do_POST(self):
        u = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        if u.path == "/post":
            self._send(200, f"CSRF[{form.get('csrf','')}] FIELD[{form.get('textfield','')}]")
        else:
            self._send(404, "Not Found")

    def log_message(self, *a):  # noqa: N802 - 静默
        pass


class TestRepeater(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = Path(tempfile.mkdtemp())
        cls.cfg = _write_eng(cls.base, "127.0.0.1")
        cls.eng = Engagement(cls.cfg)
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    def setUp(self):
        self.sess = RepeaterSession(self.eng)

    def tearDown(self):
        self.sess.close()

    def test_cookie_persistence(self):
        """会话 cookie 全程携带——治无状态请求断连。"""
        self.sess.send("GET", f"{self.base_url}/set")
        r = self.sess.send("GET", f"{self.base_url}/echo")
        self.assertIn("session=abc123", r["body"])

    def test_scope_deny(self):
        """范围外目标拒绝（deny-by-default 不因提速缺席）。"""
        from camty.guardrail.scope import ScopeError
        with self.assertRaises(ScopeError):
            self.sess.send("GET", "http://192.0.2.55:81/x")  # TEST-NET 范围外
        with self.assertRaises(ScopeError):
            self.sess.send("GET", "http://example.com/")

    def test_auto_csrf(self):
        """auto_csrf：POST 前自动拉表单页提取 token 注入 body。"""
        r = self.sess.send("POST", f"{self.base_url}/post",
                           body={"textfield": "hi"}, auto_csrf=f"{self.base_url}/form")
        self.assertIn("CSRF[tok-XYZ]", r["body"])

    def test_vector_clustering(self):
        """批测：同指纹聚簇、异类标出（500/大响应/SQL 错误三类异端全被抓）。"""
        v = self.sess.vector(f"{self.base_url}/fork", "p",
                              ["normal", "other", "boom", "big", "sqlerr"])
        outliers = [c for c in v["clusters"] if c["outlier"]]
        self.assertEqual(len(v["clusters"]), 4)  # normal/other 同簇 + boom + big + sqlerr
        self.assertEqual(len(outliers), 3)
        fps = {c["fingerprint"].split("|")[0] for c in outliers}
        self.assertIn("500", fps)
        # 错误标记进指纹
        sqlr = next(r for r in v["results"] if r["payload"] == "sqlerr")
        self.assertTrue(sqlr["errors"])

    def test_vector_body_gap(self):
        """gap=body：payload 进表单字段。"""
        v = self.sess.vector(f"{self.base_url}/post", "textfield",
                             ["a", "b"], method="POST", gap="body")
        self.assertEqual(v["n"], 2)

    def test_vector_auto_csrf(self):
        """vector 的 auto_csrf 透传：批测 POST 每条都带新提取的 token。"""
        v = self.sess.vector(f"{self.base_url}/post", "textfield",
                             ["a", "b", "c"], method="POST", gap="body",
                             auto_csrf=f"{self.base_url}/form")
        for r in v["results"]:
            self.assertEqual(r["status"], 200)

    def test_seq_flow(self):
        """顺序流：登录设 cookie → 后续请求携带（登录链语义）。"""
        out = self.sess.seq([
            {"method": "GET", "url": f"{self.base_url}/login"},
            {"method": "GET", "url": f"{self.base_url}/whoami"},
        ])
        self.assertIn("AUTH[yes]", out[1]["body"])

    def test_baseline_diff(self):
        """指纹与基线对比进响应：首响自动锚定基线，异响 diff=True。"""
        r1 = self.sess.send("GET", f"{self.base_url}/fork?p=normal")
        r2 = self.sess.send("GET", f"{self.base_url}/fork?p=boom")
        self.assertFalse(r1["diff_baseline"])   # 首响即基线
        self.assertTrue(r2["diff_baseline"])     # 500 偏离基线

    def test_audit_chain(self):
        """每个请求都进审计哈希链。"""
        n0 = len(self.eng.audit.entries())
        self.sess.send("GET", f"{self.base_url}/echo")
        self.sess.vector(f"{self.base_url}/fork", "p", ["x", "y"])
        entries = self.eng.audit.entries()
        self.assertEqual(len(entries), n0 + 2)
        ok, _ = self.eng.audit.verify()
        self.assertTrue(ok)

    def test_log_and_state(self):
        self.sess.send("GET", f"{self.base_url}/set")
        self.sess.send("GET", f"{self.base_url}/echo")
        st = self.sess.state()
        self.assertEqual(st["requests"], 2)
        self.assertIn("session=abc123", st["cookies"]["127.0.0.1"])
        self.assertTrue(any("/echo" in e["url"] for e in self.sess.log))

    def test_redirect_not_followed(self):
        """重定向不自动跟随（3xx 是测试者要看的信号）。"""
        r = self.sess.send("GET", f"{self.base_url}/login")
        self.assertEqual(r["status"], 200)


class TestRepeaterApiAuth(unittest.TestCase):
    """/req /vector /seq /log /state /stop 全端点 fail-secure 鉴权。"""

    @classmethod
    def setUpClass(cls):
        import tempfile
        from camty.agent.state import Engagement
        from camty.repeater_api import build_app
        from fastapi.testclient import TestClient

        cls.build_app = staticmethod(build_app)
        cls.TestClient = TestClient
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cfg = _write_eng(Path(cls.tmp.name), "127.0.0.1")
        cls.eng = Engagement(cls.cfg)

    @classmethod
    def tearDownClass(cls):
        cls.eng.close()
        cls.tmp.cleanup()

    def setUp(self):
        from camty import repeater as rep_mod
        from camty import repeater_api

        self._rep_mod = rep_mod
        repeater_api._reset_repeater_token_for_tests()
        self._saved_env = repeater_api.os.environ.get("CAMTY_REPEATER_TOKEN")
        repeater_api.os.environ.pop("CAMTY_REPEATER_TOKEN", None)
        self.sess = RepeaterSession(self.eng)
        self.client = self.TestClient(self.build_app(self.sess))

    def tearDown(self):
        self.sess.close()
        if self._saved_env is not None:
            repeater_api.os.environ["CAMTY_REPEATER_TOKEN"] = self._saved_env

    def test_no_token_401(self):
        r = self.client.get("/state")
        self.assertEqual(r.status_code, 401)

    def test_generated_token_200(self):
        from camty import repeater_api

        token = repeater_api._repeater_token()
        r = self.client.get("/state", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(r.status_code, 200)
        r2 = self.client.get(f"/state?token={token}")
        self.assertEqual(r2.status_code, 200)  # ?token= 通道（脚本便利）

    def test_wrong_token_401(self):
        r = self.client.get("/state", headers={"Authorization": "Bearer deadbeef"})
        self.assertEqual(r.status_code, 401)

    def test_explicit_env_token(self):
        from camty import repeater_api

        repeater_api.os.environ["CAMTY_REPEATER_TOKEN"] = "explicit-token-1"
        try:
            r = self.client.get("/state", headers={"Authorization": "Bearer explicit-token-1"})
            self.assertEqual(r.status_code, 200)
            r2 = self.client.get("/state", headers={"Authorization": "Bearer other"})
            self.assertEqual(r2.status_code, 401)
        finally:
            repeater_api.os.environ.pop("CAMTY_REPEATER_TOKEN", None)


class TestTlsInsecureSwitch(unittest.TestCase):
    """TLS 降级开关：默认关（保留证书校验），显式 CAMTY_TLS_INSECURE=1 才开。"""

    def setUp(self):
        from camty import repeater as rep_mod

        self._saved = rep_mod.os.environ.get("CAMTY_TLS_INSECURE")
        rep_mod.os.environ.pop("CAMTY_TLS_INSECURE", None)
        rep_mod._tls_warned = False
        self._mod = rep_mod

    def tearDown(self):
        if self._saved is not None:
            self._mod.os.environ["CAMTY_TLS_INSECURE"] = self._saved
        else:
            self._mod.os.environ.pop("CAMTY_TLS_INSECURE", None)

    def test_default_secure(self):
        self.assertFalse(self._mod._tls_insecure())

    def test_explicit_opt_in(self):
        import contextlib
        import io

        self._mod.os.environ["CAMTY_TLS_INSECURE"] = "1"
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            self.assertTrue(self._mod._tls_insecure())  # 首次触发打警告
            self.assertTrue(self._mod._tls_insecure())  # 二次不再重复
        self.assertIn("TLS 证书校验已禁用", buf.getvalue())
        self.assertEqual(buf.getvalue().count("TLS 证书校验已禁用"), 1)


if __name__ == "__main__":
    unittest.main()
