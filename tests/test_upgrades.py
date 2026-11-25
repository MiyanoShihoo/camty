"""框架升级测试：js_recon 提取、browser/impacket 适配器门控、impacket 参数构造。

js_recon 测纯提取函数（无网络）；适配器测 schema/门控标志/参数构造（mock subprocess）；
js-recon 适配器跑一次带 mock analyze_site 的完整 run()（真实 Scope/Audit/证据落盘）。
"""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from camty.adapters.base import RunContext
from camty.adapters.browser import BrowserActionAdapter, BrowserVisitAdapter, chromium_ready
from camty.adapters.impacket import (
    ASREP_HASH_RE,
    NTLM_HASH_LINE_RE,
    AsRepRoastAdapter,
    SecretsDumpAdapter,
    _vendor_root,
    run_impacket,
)
from camty.adapters.js_recon import JsReconAdapter, _normalize_targets
from camty.adapters.lateral import ENGINES, LateralMoveAdapter
from camty.adapters.registry import REGISTRY
from camty.guardrail.audit import Audit
from camty.guardrail.scope import Scope, ScopeError
from camty.modules import code_audit, inj_probe, js_recon

BUNDLE = """
const api = {
  login: () => fetch("/api/auth/login", {method: "POST"}),
  users: (id) => axios.get(`/api/v1/users/${id}`),
  boards: () => $get("/api/leaderboard"),
};
const routes = [{path: "/", name: "home"}, {path: "/profile/:uid", name: "profile"},
                {path: "/admin", name: "admin"}];
const SECRET = "sk-proj-abcdef0123456789abcdef0123456789";
//# sourceMappingURL=index.map
"""


def make_ctx(tmp: str, domains=("example.com",), cidrs=("10.10.10.0/24",)) -> RunContext:
    scope = Scope({"domains": list(domains), "cidrs": list(cidrs), "min_interval_seconds": 0})
    audit = Audit(Path(tmp) / "audit.jsonl")
    eng = mock.MagicMock()
    eng.dir = Path(tmp)
    eng.context = {"proxy": ""}
    return RunContext(scope, audit, Path(tmp) / "evidence", ledger=mock.MagicMock(), eng=eng)


class TestJsReconModule(unittest.TestCase):
    def test_extract_endpoints(self):
        eps = js_recon.extract_endpoints(BUNDLE, "https://example.com")
        paths = {e["endpoint"] for e in eps}
        self.assertIn("https://example.com/api/auth/login", paths)
        self.assertIn("https://example.com/api/v1/users/${id}", paths)
        self.assertIn("https://example.com/api/leaderboard", paths)

    def test_extract_routes(self):
        routes = js_recon.extract_routes(BUNDLE, "https://example.com")
        by_route = {r["route"]: r for r in routes}
        self.assertIn("https://example.com/profile/:uid", by_route)
        self.assertEqual(by_route["https://example.com/profile/:uid"]["params"], ["uid"])

    def test_extract_sourcemaps(self):
        maps = js_recon.extract_sourcemaps(BUNDLE, "https://example.com")
        self.assertIn("https://example.com/index.map", maps)

    def test_analyze_text_secrets(self):
        data = js_recon.analyze_text(BUNDLE, "test.js", "https://example.com")
        kinds = {s["kind"] for s in data["secrets"]}
        self.assertIn("openai-api-key", kinds)
        self.assertIn("hardcoded-secret", kinds)

    def test_normalize_drops_nonhttp(self):
        self.assertEqual(js_recon._normalize("https://a.com", "javascript:void(0)"), "")
        # query 在 _normalize 保留、提取层 _strip_query 剥离
        eps = js_recon.extract_endpoints('fetch("/x?q=1&z=2")', "https://a.com")
        self.assertEqual(eps, [{"endpoint": "https://a.com/x", "via": "fetch-call"}])


class TestJsReconAdapter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ctx = make_ctx(self.tmp)

    def test_normalize_targets(self):
        self.assertEqual(_normalize_targets("a.com, b.com\nc.com"), ["a.com", "b.com", "c.com"])
        self.assertEqual(_normalize_targets([{"url": "x.com"}, "y.com"]), ["x.com", "y.com"])

    def test_run_mocked_analyze(self):
        adapter = JsReconAdapter()
        fake = {
            "page": "https://example.com", "status": 200, "js_assets": ["https://example.com/app.js"],
            "endpoints": [{"endpoint": "https://example.com/api/users", "via": "api-path"}],
            "routes": [], "sourcemaps": ["https://example.com/app.js.map"],
            "secrets": [{"kind": "jwt", "match": "eyJabc.def.ghi", "source": "app.js", "evidence": ""}],
        }
        with mock.patch.object(js_recon, "analyze_site", return_value=fake):
            result = adapter.run({"targets": "https://example.com"}, self.ctx)
        self.assertIn("1 处泄露 secret", result.summary)
        templates = {f["template"] for f in result.data["findings"]}
        self.assertIn("secret/jwt", templates)
        self.assertIn("js/sourcemap-exposed", templates)
        self.assertTrue(Path(result.evidence).exists())

    def test_scope_rejects_out_of_scope(self):
        adapter = JsReconAdapter()
        with self.assertRaises(ScopeError):
            adapter.run({"targets": "https://evil.com"}, self.ctx)


class TestBrowserAdapters(unittest.TestCase):
    def test_registered_and_gates(self):
        visit = REGISTRY["browser-visit"]
        action = REGISTRY["browser-action"]
        self.assertIsInstance(visit, BrowserVisitAdapter)
        self.assertIsInstance(action, BrowserActionAdapter)
        self.assertFalse(action.requires_finding)
        self.assertTrue(action.requires_confirm)

    def test_chromium_ready_returns_bool(self):
        self.assertIsInstance(chromium_ready(), bool)

    def test_visit_schema(self):
        schema = REGISTRY["browser-visit"].tool_schema()
        self.assertIn("url", schema["required"])
        self.assertIn("use_session", schema["properties"])

    def test_action_scope_checks_every_goto(self):
        adapter = REGISTRY["browser-action"]
        ctx = make_ctx(tempfile.mkdtemp())
        actions = [{"type": "goto", "url": "https://evil.com"}]
        with self.assertRaises(ScopeError):
            adapter.run({"actions": actions}, ctx)


class TestImpacketAdapters(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ctx = make_ctx(self.tmp)

    def test_registry_gate_flags(self):
        read_only = ["asreproast-check", "ad-users", "ad-computers", "samr-enum", "delegation-find"]
        privileged = ["secretsdump", "laps-read", "gpp-password", "keylist",
                      "machine-account", "rbcd-set", "ntlmrelay", "ticket-forgery"]
        for name in read_only:
            self.assertFalse(REGISTRY[name].requires_confirm, name)
            self.assertFalse(REGISTRY[name].requires_finding, name)
        for name in privileged:
            self.assertTrue(REGISTRY[name].requires_confirm, name)
            self.assertTrue(REGISTRY[name].requires_finding, name)

    def test_vendor_root(self):
        # 用平台原生分隔符构造路径断言——Path.resolve 解析不了跨平台字面量
        # （Windows 反斜杠路径在 Linux 上被当作单个文件名，历史版本因此误报）。
        import os
        import tempfile
        from pathlib import Path

        base = Path(tempfile.mkdtemp()).resolve()
        script = str(base / "vendor" / "bin" / "GetNPUsers.py")
        self.assertEqual(_vendor_root(script), str(base / "vendor"))

    def test_run_impacket_env(self):
        # 平台原生路径构造（同 test_vendor_root 修法）：Windows 字面量在 Linux
        # 上被当作单个文件名，PYTHONPATH 解析成无关目录导致断言失败。
        import tempfile
        from pathlib import Path

        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            captured["env"] = kw["env"]
            return mock.MagicMock(returncode=0, stdout="ok", stderr="")

        base = Path(tempfile.mkdtemp()).resolve()
        script = str(base / "vendor" / "bin" / "GetNPUsers.py")
        with mock.patch("camty.adapters.impacket.subprocess.run", side_effect=fake_run):
            code, output = run_impacket(script, ["-h"])
        self.assertEqual(code, 0)
        self.assertIn(str(base / "vendor"), captured["env"]["PYTHONPATH"])
        self.assertTrue(captured["cmd"][0] == "python")

    def test_asreproast_parse_and_run(self):
        adapter = REGISTRY["asreproast-check"]
        self.assertIsInstance(adapter, AsRepRoastAdapter)
        out = "$krb5asrep$bob@CORP.LOCAL:8f2a...hash"
        self.assertTrue(ASREP_HASH_RE.search(out))
        fake_output = "$krb5asrep$alice@CORP.LOCAL:abcdef0123\n"
        # 可用性边界：run 前置 binary() → find_tool，无 impacket 的环境会以
        # ToolUnavailable 短路，走不到被 mock 的执行段（Linux/CI 红、Windows
        # 因工具发现路径不同而绿的平台差异）。一并 mock find_tool 让执行段
        # 可达；patch 目标是 base 命名空间（find_tool 由 camty.adapters.base
        # 导入并调用，impacket.py 自身无该符号）。返回值内容无所谓——
        # run_impacket 已被 mock，不会真实执行；用无盘符路径以符合
        # test_hygiene 的盘符守卫。
        with mock.patch("camty.adapters.base.find_tool",
                        return_value="/fake/vendor/bin/GetNPUsers.py"), \
             mock.patch("camty.adapters.impacket.run_impacket",
                        return_value=(0, fake_output)):
            result = adapter.run(
                {"dc_ip": "10.10.10.1", "domain": "corp.local",
                 "domain_user": "u", "domain_pass": "p"},
                self.ctx,
            )
        self.assertIn("1 个可 AS-REP roast", result.summary)
        self.assertEqual(len(result.data["findings"]), 1)

    def test_asreproast_no_creds_no_users_rejected(self):
        adapter = REGISTRY["asreproast-check"]
        result = adapter.run({"dc_ip": "10.10.10.1", "domain": "corp.local"}, self.ctx)
        self.assertIn("拒绝", result.summary)

    def test_secretsdump_parse(self):
        line = "alice:500:01fc5a6be7bc6929aad3b435b51404ee:209c6174da490caeb422f3b5173d4bef:::"
        m = NTLM_HASH_LINE_RE.search(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group("nt"), "209c6174da490caeb422f3b5173d4bef")

    def test_secretsdump_scope_and_audit(self):
        adapter = REGISTRY["secretsdump"]
        self.assertIsInstance(adapter, SecretsDumpAdapter)
        with self.assertRaises(ScopeError):
            adapter.run({"host": "10.9.9.9", "domain_user": "u", "domain_pass": "p",
                         "finding_id": "F-001"}, self.ctx)

    def test_lateral_engines(self):
        self.assertEqual(len(ENGINES), 5)
        schema = REGISTRY["lateral-move"].tool_schema()
        self.assertEqual(schema["properties"]["engine"]["enum"], list(ENGINES))
        adapter = LateralMoveAdapter()
        self.assertIn("wmiexec", LateralMoveAdapter.description)
        with self.assertRaises(RuntimeError):
            adapter.run({"host": "10.10.10.5", "domain_user": "u", "domain_pass": "p",
                         "command": "whoami", "engine": "evilgen", "finding_id": "F-001"}, self.ctx)


class TestInjProbe(unittest.TestCase):
    """本地靶机验证多载体注入探测（错误回显/反射/POST JSON）。"""

    @staticmethod
    def _handler():
        from http.server import BaseHTTPRequestHandler
        from urllib.parse import parse_qsl, urlparse

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                parsed = urlparse(self.path)
                qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
                if parsed.path == "/vuln":
                    if "'" in qs.get("q", ""):
                        self._reply("You have an error in your SQL syntax near '' at line 1", 500)
                    else:
                        self._reply("normal page", 200)
                elif parsed.path == "/reflect":
                    self._reply(f"<html>hi {qs.get('x', '')}</html>", 200)
                elif parsed.path == "/tpl":
                    value = qs.get("x", "")
                    self._reply(f"rendered: {value.replace('{{7*7}}', '49')}", 200)
                else:
                    self._reply("ok", 200)

            def do_POST(self):
                if self.path == "/api/login":
                    body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                    if "' OR" in body or "' AND" in body or "'" in body:
                        self._reply("mysql_fetch failed: syntax error", 500)
                    else:
                        self._reply('{"status":"ok"}', 200)
                else:
                    self._reply("ok", 200)

            def _reply(self, text, status):
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(text.encode())

        return H

    @classmethod
    def setUpClass(cls):
        import http.server
        import socket

        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), cls._handler())
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ctx = make_ctx(self.tmp, domains=(), cidrs=("127.0.0.1/32",))

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_probe_get_sqli_error(self):
        hits = inj_probe.probe_get(self._url("/vuln?q=abc"), kinds=["sqli"], delay=0)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["kind"], "error-based(MySQL)")
        self.assertEqual(hits[0]["param"], "q")

    def test_probe_get_xss_reflect(self):
        hits = inj_probe.probe_get(self._url("/reflect?x=hi"), kinds=["xss"], delay=0)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["kind"], "reflected-xss")

    def test_probe_get_ssti(self):
        hits = inj_probe.probe_get(self._url("/tpl?x=hi"), kinds=["ssti"], delay=0)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["kind"], "ssti-eval")

    def test_probe_get_clean_no_hits(self):
        hits = inj_probe.probe_get(self._url("/vuln?q=abc"), kinds=["xss"], delay=0)
        self.assertEqual(hits, [])

    def test_probe_post_json(self):
        hits = inj_probe.probe_post(
            self._url("/api/login"), '{"user": "a", "pass": "b"}',
            "application/json", kinds=["sqli"], delay=0,
        )
        # 靶机对任意单引号报 SQL 错误 → 两个叶子字段各命中一次
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0]["method"], "POST-JSON")
        self.assertTrue(hits[0]["param"].startswith("$."))
        self.assertEqual(hits[0]["kind"], "error-based(MySQL)")

    def test_adapter_run_multi(self):
        adapter = REGISTRY["inj-probe"]
        result = adapter.run(
            {"targets": [self._url("/vuln?q=abc")],
             "post_targets": [{"url": self._url("/api/login"),
                               "body": '{"user": "a", "pass": "b"}',
                               "content_type": "application/json",
                               "kinds": ["sqli"]}],
             "kinds": ["sqli"], "delay": 0},
            self.ctx,
        )
        self.assertIn("命中 3 处", result.summary)
        self.assertTrue(all(f["severity"] == "high" for f in result.data["findings"]))

    def test_adapter_scope_rejects(self):
        adapter = REGISTRY["inj-probe"]
        with self.assertRaises(ScopeError):
            adapter.run({"targets": "http://203.0.113.9/vuln?q=1"}, self.ctx)


class TestCodeAudit(unittest.TestCase):
    GO_VULN = """
package api
import ("database/sql"; "fmt")
func listUsers(db *sql.DB, name string) {
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
    db.Query(query)
}
"""
    PY_VULN = """
import subprocess
def backup(arg):
    subprocess.run("tar cf " + arg, shell=True)
    result = eval(arg)
"""
    JS_VULN = """
const { exec } = require('child_process');
function run(cmd) { exec(cmd); }
"""
    PHP_VULN = """<?php
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
system($_GET['c']);
"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        src = Path(self.tmp) / "src"
        src.mkdir()
        (src / "api.go").write_text(self.GO_VULN, encoding="utf-8")
        (src / "backup.py").write_text(self.PY_VULN, encoding="utf-8")
        (src / "runner.js").write_text(self.JS_VULN, encoding="utf-8")
        (src / "legacy.php").write_text(self.PHP_VULN, encoding="utf-8")
        (src / "node_modules").mkdir()
        (src / "node_modules" / "evil.js").write_text("exec(require('x'))", encoding="utf-8")
        self.ctx = make_ctx(self.tmp)

    def test_scan_tree_rules(self):
        result = code_audit.scan_tree(Path(self.tmp) / "src")
        rules = {f["rule"] for f in result["findings"]}
        self.assertIn("sql-concat", rules)
        self.assertIn("cmd-exec", rules)
        self.assertIn("py-eval", rules)
        # node_modules 被跳过
        files = {Path(f["file"]).name for f in result["findings"]}
        self.assertNotIn("evil.js", files)
        # 命中带 file:line:snippet
        f0 = next(f for f in result["findings"] if f["rule"] == "sql-concat")
        self.assertEqual(Path(f0["file"]).name, "api.go")
        self.assertGreater(f0["line"], 0)
        self.assertIn("Sprintf", f0["snippet"])

    def test_scan_severity_sort(self):
        result = code_audit.scan_tree(Path(self.tmp) / "src")
        sev = [f["severity"] for f in result["findings"]]
        self.assertEqual(sev, sorted(sev, key=lambda s: {"critical": 0, "high": 1, "medium": 2}.get(s, 9)))

    def test_adapter_marks_unverified(self):
        adapter = REGISTRY["code-audit"]
        result = adapter.run({"path": str(Path(self.tmp) / "src")}, self.ctx)
        self.assertIn("命中", result.summary)
        self.assertTrue(result.data["findings"])
        self.assertTrue(all(f.get("verified") is False for f in result.data["findings"]))
        self.assertTrue(Path(result.evidence).exists())

    def test_adapter_missing_path(self):
        adapter = REGISTRY["code-audit"]
        result = adapter.run({"path": str(Path(self.tmp) / "nope")}, self.ctx)
        self.assertIn("路径不存在", result.summary)

    def test_merge_result_respects_verified_flag(self):
        from camty.agent.runner import _merge_result
        from camty.adapters.base import ToolResult

        eng = mock.MagicMock()  # 不用 spec：context/ledger 是实例属性
        added = []
        eng.ledger.add.side_effect = lambda **kw: added.append(kw)
        result = ToolResult(summary="s", data={"findings": [
            {"template": "code/x", "severity": "medium", "url": "a.go:1", "verified": False},
            {"template": "inj/y", "severity": "high", "url": "u.com"},
        ]})
        _merge_result(eng, result)
        self.assertFalse(added[0]["verified"])
        self.assertTrue(added[1]["verified"])


class TestRegistryIntegrity(unittest.TestCase):
    def test_registry_size_and_uniqueness(self):
        from camty.adapters.registry import _ADAPTERS
        names = [a.name for a in _ADAPTERS]
        self.assertEqual(len(names), len(set(names)), "适配器重名")
        self.assertGreaterEqual(len(names), 34)

    def test_all_tool_defs_valid(self):
        for name, adapter in REGISTRY.items():
            spec = adapter.tool_def()
            self.assertEqual(spec["function"]["name"], name)
            self.assertTrue(spec["function"]["description"], name)
            self.assertIn("properties", adapter.tool_schema(), name)


if __name__ == "__main__":
    unittest.main()
