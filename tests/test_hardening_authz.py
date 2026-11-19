"""加固批次 + authz-probe 测试：预授权/WAF/evasion/引擎降级/鉴权矩阵靶机。"""

from __future__ import annotations

import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import yaml

from camty.adapters.authz_probe import AuthzProbeAdapter
from camty.adapters.base import RunContext
from camty.agent.engine import Engine
from camty.adapters.mock import MockSubfinder
from camty.agent.state import Engagement
from camty.guardrail.approval import decide_confirm
from camty.guardrail.preauth import add_rule, check, clear_rules
from camty.llm.router import LLMError
from camty.modules import authz_probe
from camty.modules.inj_probe import _iter_payloads, evasion_variants
from camty.modules.waf import detect

from tests.test_auto import MockFindings
from tests.test_planner import make_project


def make_eng(tmp: str, plan: list | None = None, cfg_extra: dict | None = None) -> Engagement:
    pack = {"name": "hard-pack", "title": "加固测试", "phases": [], "plan": plan or []}
    root = Path(tmp)
    (root / "packs" / "hard-pack").mkdir(parents=True, exist_ok=True)
    (root / "packs" / "hard-pack" / "pack.yaml").write_text(
        yaml.safe_dump(pack), encoding="utf-8")
    (root / "engagements").mkdir(exist_ok=True)
    cfg = {
        "name": "hard-eng", "pack": "hard-pack", "root_domain": "example.com",
        "scope": {"domains": ["example.com"], "ips": ["127.0.0.1"],
                  "min_interval_seconds": 0},
        "auto_confirm": True,
    }
    cfg.update(cfg_extra or {})
    path = root / "engagements" / "hard-eng.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return Engagement(path)


def build_registry():
    return {"mock-subfinder": MockSubfinder(),
            "mock-findings": MockFindings()}


class TestPreauth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)

    def test_add_check_clear(self):
        add_rule(self.eng, "c2-task", ".*", note="比赛放行")
        self.assertTrue(check(self.eng, "c2-task", {"command": "whoami"}))
        self.assertFalse(check(self.eng, "secretsdump", {"host": "1.2.3.4"}))
        # 审计留痕
        notes = [e.get("adapter") for e in self.eng.audit.entries()]
        self.assertIn("preauth-add", notes)
        self.assertEqual(clear_rules(self.eng), 1)
        self.assertFalse(check(self.eng, "c2-task", {}))

    def test_pattern_matching(self):
        add_rule(self.eng, "lateral-move", r"ping|whoami")
        self.assertTrue(check(self.eng, "lateral-move", {"command": "whoami"}))
        self.assertFalse(check(self.eng, "lateral-move", {"command": "rm -rf /"}))

    def test_decide_confirm_preauth_wins(self):
        self.eng.cfg["approval"] = {"mode": "interactive"}  # 预授权必须压过交互
        add_rule(self.eng, "mock-findings", ".*")
        adapter = build_registry()["mock-findings"]
        proceed, mode, note = decide_confirm(self.eng, adapter, {})
        self.assertTrue(proceed)
        self.assertEqual(mode, "preauth")
        self.assertIn("预授权", note)


class TestWafDetect(unittest.TestCase):
    def test_cloudflare(self):
        self.assertEqual(detect({"cf-ray": "abc123", "server": "cloudflare"}), ["cloudflare"])

    def test_safedog(self):
        self.assertIn("safedog", detect({"x-waf": "safedog 5.0"}))

    def test_clean(self):
        self.assertEqual(detect({"content-type": "text/html", "server": "nginx"}), [])

    def test_case_insensitive(self):
        self.assertIn("aliyun-waf", detect({"Server": "AliYun-WAF"}))


class TestEvasion(unittest.TestCase):
    def test_sql_case_mixed(self):
        out = evasion_variants("') OR ('1'='1", "sqli")
        self.assertIn("') Or ('1'='1", out)

    def test_sql_inline_comment(self):
        out = evasion_variants("' AND SLEEP(3)-- -", "time-blind")
        self.assertTrue(any("/*!50000SLEEP*/" in p or "/*!50000sleep*/" in p for p in out))

    def test_url_encode(self):
        out = evasion_variants("' AND '1'='1", "sqli")
        self.assertTrue(any("%27" in p for p in out))

    def test_xss_and_untouched(self):
        out = evasion_variants("camtyxss<script>", "xss")
        self.assertTrue(any("<ScRiPt>" in p for p in out))
        self.assertEqual(evasion_variants("; echo x", "cmd"), ["; echo x"])

    def test_iter_payloads_off_on(self):
        off = _iter_payloads("sqli", False)
        on = _iter_payloads("sqli", True)
        self.assertEqual(len(on), 7 * len(off))  # 6 变体 + 原始


class TestEngineDegrade(unittest.TestCase):
    """LLM 规划失败 → 引擎降级 pack 确定性模式并跑完。"""

    class BadRouter:
        def chat(self, role, messages, tools=None, timeout=None):
            raise LLMError("provider down")

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_llm_fail_degrades_to_pack(self):
        from unittest import mock as _mock

        import camty.agent.engine as _eng_mod
        plan = [
            {"adapter": "mock-subfinder", "args": {"domain": "{root_domain}"},
             "provides": ["subdomains"]},
            {"adapter": "mock-findings", "requires": ["subdomains"]},
        ]
        eng = make_eng(self.tmp, plan=plan)
        engine = Engine(eng, router=self.BadRouter(), registry=build_registry(),
                        n_workers=2, max_total_steps=10)
        with _mock.patch.object(_eng_mod.time, "sleep", lambda x: None):
            self.assertTrue(engine.run())
        self.assertIsNone(engine.router, "LLM 持续失败后引擎应降级 router=None")
        todo_items = eng.db.load_todolist()
        self.assertTrue(all(i["status"] == "done" for i in todo_items), todo_items)
        self.assertTrue(eng.ledger.findings)
        self.assertIn("subdomains", eng.context)


class TestAuthzProbe(unittest.TestCase):
    """本地靶机：/api/orders/{id} 平行越权（不校验属主）+ 强制浏览 401。"""

    @staticmethod
    def _make_server(port: int):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _session_user(self):
                cookie = self.headers.get("Cookie", "")
                if "session_a" in cookie:
                    return "alice"
                if "session_b" in cookie:
                    return "bob"
                return None

            def do_GET(self):
                # /api/orders/<id>
                if self.path.startswith("/api/orders/"):
                    user = self._session_user()
                    if user is None:
                        self._reply(401, '{"error": "unauthorized"}')
                        return
                    order_id = self.path.rsplit("/", 1)[-1]
                    # 越权靶机：任何登录会话可读任何订单（不校验属主）
                    owner = {"101": "alice", "202": "bob"}.get(order_id, "unknown")
                    self._reply(200, json.dumps({
                        "id": order_id, "owner": owner,
                        "email": f"{owner}@example.com", "status": "paid"}))
                    return
                self._reply(404, '{"error": "not found"}')

            def _reply(self, status, body):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())

        srv = http.server.HTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)
        self.port = 18521
        self.srv = self._make_server(self.port)
        # 两个具名会话（browser storage_state 格式）
        for name, marker in (("a", "session_a"), ("b", "session_b")):
            state = {"cookies": [
                {"name": marker, "value": "x", "domain": "127.0.0.1", "path": "/"}],
                "origins": []}
            (self.eng.dir / f"browser-session-{name}.json").write_text(
                json.dumps(state), encoding="utf-8")

    def tearDown(self):
        self.srv.shutdown()

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_build_pair(self):
        self.assertEqual(
            authz_probe.build_pair("https://x.com/api/o/{id}", "101", "202"),
            ("https://x.com/api/o/101", "https://x.com/api/o/202"))
        self.assertEqual(
            authz_probe.build_pair("https://x.com/api/o?id=101", "1", "2"),
            ("https://x.com/api/o?id=1", "https://x.com/api/o?id=2"))
        self.assertEqual(
            authz_probe.build_pair("https://x.com/api/o/101", "7", "9"),
            ("https://x.com/api/o/7", "https://x.com/api/o/9"))
        self.assertIsNone(authz_probe.build_pair("https://x.com/api/health", "1", "2"))

    def test_verdict_branches(self):
        denied = authz_probe.verdict({"status": 200, "body": "x"},
                                     {"status": 403, "body": "forbidden", "length": 9}, "202")
        self.assertFalse(denied["hit"])
        self.assertIn("防线正常", denied["detail"])
        hit = authz_probe.verdict(
            {"status": 200, "body": '{"id":101,"owner":"alice","email":"alice@example.com"}'},
            {"status": 200, "body": '{"id":202,"owner":"bob","email":"bob@example.com"}'}, "202")
        self.assertTrue(hit["hit"])

    def test_adapter_full_matrix(self):
        adapter = AuthzProbeAdapter()
        result = adapter.run({
            "targets": [self._url("/api/orders/{id}")],
            "own_id": "101", "other_id": "202",
            "session_a": "a", "session_b": "b",
        }, self.eng.ctx)
        findings = result.data["findings"]
        templates = {f["template"] for f in findings}
        self.assertIn("authz/idor", templates, result.data["matrix"])
        self.assertNotIn("authz/forced-browse", templates, "靶机无凭据应 401")
        row = result.data["matrix"][0]
        self.assertEqual(row["baseline_status"], 200)
        self.assertEqual(row["cross_status"], 200)
        self.assertEqual(row["forced_status"], 401)
        # 越权 finding 标记 verified（经 runner 合并即进台账）
        idor = next(f for f in findings if f["template"] == "authz/idor")
        self.assertEqual(idor["severity"], "high")
        self.assertTrue(idor["verified"])
        self.assertEqual(idor["url"], self._url("/api/orders/202"))

    def test_adapter_requires_sessions(self):
        adapter = AuthzProbeAdapter()
        result = adapter.run({
            "targets": [self._url("/api/orders/{id}")],
            "own_id": "1", "other_id": "2", "session_a": "nope", "session_b": "b",
        }, self.eng.ctx)
        self.assertIn("缺登录会话", result.summary)

    def test_scope_rejects(self):
        adapter = AuthzProbeAdapter()
        with self.assertRaises(Exception):
            adapter.run({"targets": ["http://203.0.113.9/api/o/{id}"],
                         "own_id": "1", "other_id": "2"}, self.eng.ctx)


if __name__ == "__main__":
    unittest.main()
