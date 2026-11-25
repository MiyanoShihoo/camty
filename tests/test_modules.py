"""模块级测试：sqli-probe（本地靶机）与 int-ad 适配器解析器（fixture）。

适配器透明度批次：browser 动作摘要透出（fake playwright 页对象）、
skill-lookup 中英别名展开（夹具技能目录）、dir-scan findings 归一化去重（mock scan）。
"""

from __future__ import annotations

import http.server
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import parse_qsl, urlparse
from unittest import mock

from camty.adapters.cred_test import parse_nxc_auth
from camty.adapters.fscan import parse_fscan
from camty.adapters.httpx import LINE_RE as HTTPX_LINE_RE
from camty.adapters.kerberoast import parse_getuserspns
from camty.adapters.nuclei import LINE_RE as NUCLEI_LINE_RE, _normalize_hosts
from camty.adapters.smb_enum import parse_nxc_enum
from camty.guardrail.audit import Audit
from camty.adapters.base import RunContext
from camty.guardrail.scope import Scope
from camty.modules import sqli_probe


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if parsed.path == "/vuln":
            if "'" in qs.get("q", ""):
                body, status = "You have an error in your SQL syntax near '' at line 1", 500
            else:
                body, status = "normal results page", 200
        elif parsed.path == "/bool":
            value = qs.get("v", "")
            if "'1'='1" in value:
                body, status = "A" * 600, 200
            elif "'1'='2" in value:
                body, status = "B", 200
            else:
                body, status = "normal", 200
        else:
            body, status = "safe", 200
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class TestSqliProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_error_based(self):
        hits = sqli_probe.probe_url(f"http://127.0.0.1:{self.port}/vuln?q=test", delay=0)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["type"], "error-based")
        self.assertEqual(hits[0]["dbms"], "MySQL")
        self.assertEqual(hits[0]["param"], "q")

    def test_boolean_based(self):
        hits = sqli_probe.probe_url(f"http://127.0.0.1:{self.port}/bool?v=test", delay=0)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["type"], "boolean-based")

    def test_safe_target_no_finding(self):
        hits = sqli_probe.probe_url(f"http://127.0.0.1:{self.port}/safe?q=test", delay=0)
        self.assertEqual(hits, [])

    def test_no_params_skipped(self):
        self.assertEqual(sqli_probe.probe_url(f"http://127.0.0.1:{self.port}/vuln", delay=0), [])


FSCAN_FIXTURE = """[*] 192.168.100.10:445 open
192.168.100.10:445 open
192.168.100.10:139 open
192.168.100.11:22 open
[*] 192.168.100.10  WORKGROUP\\PC01  Windows 10 Professional
"""

NXC_ENUM_FIXTURE = """SMB         192.168.100.10   445    DC01            [+] DC01.corp.local  (signing:True)
SMB         192.168.100.11   445    PC01            [+] PC01.corp.local  (signing:False)
SMB         192.168.100.11   445    PC01            [+] Enumerated shares
Share           Permissions     Remark
--------------------   -----------   -------
ADMIN$                          Remote Admin
C$                              Default share
"""

NXC_AUTH_FIXTURE = """SMB         192.168.100.10   445    DC01            [+] corp.local\\test:Pass123 (Pwn3d!)
SMB         192.168.100.11   445    PC01            [-] corp.local\\test:Pass123 STATUS_LOGON_FAILURE
"""

GETUSERSPNS_FIXTURE = """Impacket v0.12.0

[*] Getting credentials
ServicePrincipalName        Name        Memberof  PasswordLastSet
--------------------------  ----------  --------  ---------------
MSSQLSvc/sql01.corp.local   svc_sql              2024-01-01
HTTP/web01.corp.local       svc_web              2024-02-01
"""


class TestIntAdParsers(unittest.TestCase):
    def test_fscan(self):
        data = parse_fscan(FSCAN_FIXTURE)
        self.assertEqual(data["live_hosts"], ["192.168.100.10", "192.168.100.11"])
        self.assertIn(445, data["host_ports"]["192.168.100.10"])
        self.assertEqual(len(data["info"]), 1)

    def test_nxc_enum(self):
        data = parse_nxc_enum(NXC_ENUM_FIXTURE)
        self.assertEqual(data["signing"], {"192.168.100.10": True, "192.168.100.11": False})
        self.assertEqual(len(data["shares"]), 2)
        self.assertEqual(data["shares"][0]["share"], "ADMIN$")

    def test_nxc_auth(self):
        data = parse_nxc_auth(NXC_AUTH_FIXTURE)
        self.assertEqual(len(data["valid"]), 1)
        self.assertEqual(data["valid"][0]["host"], "192.168.100.10")
        self.assertEqual(data["pwned"], [{"host": "192.168.100.10"}])
        self.assertEqual(len(data["invalid"]), 1)

    def test_getuserspns(self):
        spns = parse_getuserspns(GETUSERSPNS_FIXTURE)
        self.assertEqual(len(spns), 2)
        self.assertEqual(spns[0]["user"], "svc_sql")
        self.assertEqual(spns[1]["spn"], "HTTP/web01.corp.local")


class TestWebParsers(unittest.TestCase):
    def test_httpx_line(self):
        line = "https://sub.example.com [200] [Site Title] [Nginx,PHP]"
        m = HTTPX_LINE_RE.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group("status"), "200")

    def test_nuclei_normalize_hosts(self):
        self.assertEqual(
            _normalize_hosts([{"url": "https://a.com"}, "https://b.com", "", None]),
            ["https://a.com", "https://b.com"],
        )

    def test_nuclei_line(self):
        m = NUCLEI_LINE_RE.match("[cve-2024-x] [high] [http] https://a.com")
        self.assertEqual(m.group("template"), "cve-2024-x")
        self.assertEqual(m.group("severity"), "high")


if __name__ == "__main__":
    unittest.main()


class TestC2Adapters(unittest.TestCase):
    def test_sessions_scope_and_task_gating(self):
        import tempfile
        from pathlib import Path
        from unittest import mock as _mock

        from camty.adapters.base import RunContext
        from camty.adapters.c2 import C2Error, C2SessionsAdapter, C2TaskAdapter
        from camty.guardrail.audit import Audit
        from camty.guardrail.scope import Scope, ScopeError

        class _FakeResp:
            def __init__(self, body):
                self._data = json.dumps(body).encode("utf-8")

            def read(self):
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def _fake_urlopen(req, timeout=None):
            url = req.full_url
            if url.endswith("/api/sessions"):
                return _FakeResp({"sessions": [
                    {"id": "s1", "host": "192.168.100.10", "user": "corp\a"},
                    {"id": "s2", "host": "8.8.8.8", "user": "corp\b"},
                ]})
            if "/tasks" in url:
                return _FakeResp({"task_id": "t-123"})
            raise AssertionError(f"unexpected url: {url}")

        with tempfile.TemporaryDirectory() as tmp:
            scope = Scope({"cidrs": ["192.168.100.0/24"], "min_interval_seconds": 0})
            ctx = RunContext(scope, Audit(Path(tmp) / "a.jsonl"), tmp)
            with _mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen):
                result = C2SessionsAdapter().run({"c2_url": "http://c2"}, ctx)
                self.assertEqual(len(result.data["sessions"]), 2)
                self.assertEqual(len(result.data["in_scope_sessions"]), 1, "范围外会话应被过滤")

                bad = {"session_id": "s2", "command": "whoami", "c2_url": "http://c2", "finding_id": "F-001"}
                with self.assertRaises(ScopeError):
                    C2TaskAdapter().run(bad, ctx)

                good = {"session_id": "s1", "command": "whoami", "c2_url": "http://c2", "finding_id": "F-001"}
                result = C2TaskAdapter().run(good, ctx)
                self.assertEqual(result.data["task_id"], "t-123")

            with self.assertRaises(C2Error):
                C2SessionsAdapter().run({}, ctx)


# ---------------------------------------------------------------------------
# F-07：browser-action digest 逐动作透出（goto 哪里 / 点了什么 / 填了什么字段）
# ---------------------------------------------------------------------------

class _FakeBrowserResponse:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = dict(headers or {})


class _FakeKeyboard:
    def press(self, key):
        pass


class _FakeBrowserPage:
    """最小 playwright Page 假体：只实现 browser 适配器用到的方法。"""

    def __init__(self, title="Example Home", url="https://example.com/home", dom=None):
        self._title = title
        self.url = url
        self.dom = dom or {}
        self.keyboard = _FakeKeyboard()
        self.frames = []
        self.context = mock.MagicMock()

    def title(self):
        return self._title

    def inner_text(self, selector):
        return "page body text"

    def goto(self, url, **kwargs):
        self.url = url
        return _FakeBrowserResponse(200)

    def fill(self, selector, value, **kwargs):
        pass

    def click(self, selector, **kwargs):
        pass

    def press(self, selector, key, **kwargs):
        pass

    def wait_for_selector(self, selector, **kwargs):
        pass

    def wait_for_timeout(self, ms):
        pass

    def screenshot(self, path=None, full_page=True):
        Path(path).write_bytes(b"png")

    def eval_on_selector_all(self, selector, script):
        return self.dom.get(selector, [])

    def get_attribute(self, selector, attr):
        return "attr-value"


class _FakeBrowserContext:
    def __init__(self, page):
        self._page = page

    def new_page(self):
        return self._page

    def add_init_script(self, script):
        pass


class _FakeBrowser:
    def __init__(self, context):
        self._context = context
        self.closed = False

    def new_context(self, **kwargs):
        return self._context

    def close(self):
        self.closed = True


class _FakePlaywright:
    """`with _playwright() as p: p.chromium.launch(...)` 的最小假体。"""

    def __init__(self, browser):
        self.chromium = self
        self._browser = browser

    def launch(self, **kwargs):
        return self._browser

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestBrowserActionDigest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _ctx(self):
        eng = mock.MagicMock()
        eng.dir = Path(self.tmp)
        eng.context = {"proxy": ""}
        return RunContext(
            Scope({"domains": ["example.com"], "min_interval_seconds": 0}),
            Audit(Path(self.tmp) / "audit.jsonl"), Path(self.tmp) / "evidence", eng=eng)

    def _run(self, args: dict, adapter_cls, page=None):
        page = page or _FakeBrowserPage()
        pw = _FakePlaywright(_FakeBrowser(_FakeBrowserContext(page)))
        with mock.patch("camty.adapters.browser._playwright", return_value=pw):
            return adapter_cls().run(args, self._ctx())

    def test_action_digest_visibility_and_value_truncation(self):
        long_value = "A" * 80
        actions = [
            {"type": "goto", "url": "https://example.com/login"},
            {"type": "fill", "selector": "#username", "value": "alice@example.com"},
            {"type": "fill", "selector": "#password", "value": long_value},
            {"type": "click", "selector": "button[type=submit]"},
            {"type": "screenshot"},
        ]
        from camty.adapters.browser import BrowserActionAdapter

        result = self._run({"actions": actions}, BrowserActionAdapter)
        # summary 逐动作可见：URL/选择器全可见，值截断
        self.assertIn("goto:https://example.com/login", result.summary)
        self.assertIn("fill:#username=alice@example.com", result.summary)
        self.assertIn("click:button[type=submit]", result.summary)
        self.assertIn("screenshot", result.summary)
        self.assertIn(f"fill:#password={'A' * 30}", result.summary)
        self.assertNotIn("A" * 40, result.summary)
        self.assertNotIn("A" * 40, json.dumps(result.data, ensure_ascii=False))
        # data.actions 结构化数组：type/target/value摘要/ok/状态码
        entries = result.data["actions"]
        self.assertEqual([e["type"] for e in entries],
                         ["goto", "fill", "fill", "click", "screenshot"])
        self.assertEqual(entries[0]["target"], "https://example.com/login")
        self.assertEqual(entries[0]["status"], 200)
        self.assertTrue(entries[0]["ok"])
        self.assertEqual(entries[1]["target"], "#username")
        self.assertEqual(entries[1]["value"], "alice@example.com")
        self.assertEqual(entries[2]["value"], "A" * 30, "fill 值摘要应截断 30 字符")
        self.assertEqual(entries[3]["target"], "button[type=submit]")
        self.assertTrue(all(e["ok"] for e in entries))
        # 紧凑摘要列表 + 旧 actions_log 兼容保留
        self.assertEqual(result.data["actions_digest"], [
            "goto:https://example.com/login",
            "fill:#username=alice@example.com",
            f"fill:#password={'A' * 30}",
            "click:button[type=submit]",
            "screenshot",
        ])
        self.assertEqual(len(result.data["actions_log"]), 5)

    def test_digest_covers_all_action_kinds(self):
        actions = [
            {"type": "goto", "url": "https://example.com/login"},
            {"type": "press", "selector": "#username", "key": "Enter"},
            {"type": "press", "key": "Tab"},
            {"type": "wait_selector", "selector": ".dashboard"},
            {"type": "wait", "ms": 500},
            {"type": "extract_text", "selector": "#profile"},
            {"type": "extract_attr", "selector": "a.logout", "attr": "href"},
        ]
        from camty.adapters.browser import BrowserActionAdapter

        result = self._run({"actions": actions}, BrowserActionAdapter)
        expected = [
            "goto:https://example.com/login",
            "press:#username+Enter",
            "press:Tab",
            "wait_selector:.dashboard",
            "wait:500ms",
            "extract_text:#profile",
            "extract_attr:a.logout@href",
        ]
        self.assertEqual(result.data["actions_digest"], expected)
        self.assertIn(", ".join(expected), result.summary)
        entries = result.data["actions"]
        self.assertEqual(len(entries), 7)
        self.assertTrue(all(e["ok"] for e in entries))
        self.assertEqual(entries[5]["target"], "#profile")
        self.assertIn("chars", entries[5], "extract_text 记录字符数")

    def test_summary_and_audit_note_carry_digest(self):
        from camty.adapters.browser import BrowserActionAdapter

        actions = [{"type": "fill", "selector": "#q", "value": "x"}]
        result = self._run({"actions": actions, "start_url": "https://example.com/search"},
                           BrowserActionAdapter)
        self.assertIn("执行 1 个动作", result.summary)
        self.assertIn("最终页", result.summary)
        self.assertIn("https://example.com/search", result.summary)
        self.assertEqual(result.data["start_url"], "https://example.com/search")
        notes = [e.get("note", "") for e in Audit(Path(self.tmp) / "audit.jsonl").entries()]
        self.assertTrue(any("fill:#q=x" in n for n in notes), "审计 note 应含动作摘要")

    def test_visit_summary_surfaces_forms_and_inputs(self):
        from camty.adapters.browser import BrowserVisitAdapter

        page = _FakeBrowserPage(title="Member Portal", url="https://example.com/")
        page.dom = {
            "a[href]": ["https://example.com/profile"],
            "form": [{"action": "https://example.com/login", "method": "post",
                      "fields": [{"name": "user", "type": "text"}]}],
            "input,textarea": [{"name": "user", "type": "text"}],
            "script[src]": ["https://example.com/app.js"],
        }
        result = self._run({"url": "https://example.com/"}, BrowserVisitAdapter, page=page)
        self.assertIn("Member Portal", result.summary)
        self.assertIn("1 链接", result.summary)
        self.assertIn("1 表单/1 输入框", result.summary)
        self.assertIn("状态 200", result.summary)
        self.assertEqual(result.data["page"]["forms"][0]["method"], "post")


# ---------------------------------------------------------------------------
# F-04：skill-lookup 中英术语别名表——英文主题命中中文技能库
# ---------------------------------------------------------------------------

class TestSkillLookupBilingual(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _ctx(self):
        return RunContext(
            Scope({"domains": ["example.com"], "min_interval_seconds": 0}),
            Audit(Path(self.tmp) / "audit.jsonl"), Path(self.tmp) / "evidence")

    def _make_skill(self, name: str, text: str) -> Path:
        d = Path(self.tmp) / "fixtures" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "SKILL.md").write_text(text, encoding="utf-8")
        return d.parent

    def _run_topic(self, fixture_root: Path, topic: str):
        from camty.adapters.skill_lookup import SkillLookupAdapter

        adapter = SkillLookupAdapter()
        with mock.patch.dict(os.environ, {"CAMTY_SKILL_EXTRA_DIRS": str(fixture_root)}):
            return adapter.run({"topic": topic}, self._ctx())

    def test_english_topic_hits_chinese_skill(self):
        root = self._make_skill(
            "zskill-passwd", "# 密码重置投毒\n重置投毒：操纵邮箱重置流程接管目标账号。")
        result = self._run_topic(root, "password reset poisoning")
        self.assertTrue(result.data["hits"], "英文主题应经别名命中中文技能")
        top = result.data["hits"][0]
        self.assertEqual(top["name"], "zskill-passwd")
        self.assertEqual(top["matched"], "密码重置投毒", "别名命中应透出命中的别名")

    def test_original_topic_ranks_above_alias(self):
        root = self._make_skill("aaa-en-hit", "# deserialization guide\nJava deserialization chains.")
        root = self._make_skill("mmm-both-hit", "# deserialization 与 反序列化\n两种术语都写。")
        root = self._make_skill("zzz-cn-hit", "# 反序列化\nysoserial 利用链。")
        result = self._run_topic(root, "deserialization")
        names = [h["name"] for h in result.data["hits"]]
        self.assertTrue(set(("aaa-en-hit", "mmm-both-hit", "zzz-cn-hit")) <= set(names))
        self.assertEqual(names[0], "aaa-en-hit", "原名命中应排在别名命中前")
        self.assertLess(names.index("aaa-en-hit"), names.index("zzz-cn-hit"))
        self.assertEqual(names.count("mmm-both-hit"), 1, "同一技能只计一次")
        both = next(h for h in result.data["hits"] if h["name"] == "mmm-both-hit")
        self.assertEqual(both["matched"], "deserialization", "原名命中时 matched 为原名")

    def test_chinese_topic_no_regression(self):
        root = self._make_skill("zskill-cn", "# 反序列化\nysoserial 利用链。")
        root = self._make_skill("zskill-en", "# deserialization guide\nJava chains.")
        result = self._run_topic(root, "反序列化")
        self.assertTrue(result.data["hits"], "中文主题检索不应回归")
        top = result.data["hits"][0]
        self.assertEqual(top["name"], "zskill-cn")
        self.assertEqual(top["matched"], "反序列化")

    def test_real_library_english_queries(self):
        """真实仓库技能库：英文主题经别名命中含对应中文术语的技能。"""
        repo_skills = Path(__file__).resolve().parent.parent / "skills"
        if not repo_skills.is_dir():
            self.skipTest("仓库 skills/ 目录不存在（打包环境）")
        from camty.adapters.skill_lookup import SkillLookupAdapter

        adapter = SkillLookupAdapter()
        with mock.patch.dict(os.environ, {"CAMTY_SKILL_EXTRA_DIRS": ""}):
            result = adapter.run({"topic": "password reset poisoning"}, self._ctx())
        hits = result.data["hits"]
        self.assertTrue(hits, "password reset poisoning 应命中含 密码重置 的技能")
        self.assertEqual(hits[0]["matched"], "密码重置")

        with mock.patch.dict(os.environ, {"CAMTY_SKILL_EXTRA_DIRS": ""}):
            result = adapter.run({"topic": "deserialization"}, self._ctx())
        self.assertTrue(result.data["hits"], "deserialization 应命中含 反序列化 的技能")
        self.assertTrue(all(h["matched"] == "反序列化" for h in result.data["hits"]))


# ---------------------------------------------------------------------------
# F-05：dir-scan content-discovery findings 按归一化 URL 去重
# ---------------------------------------------------------------------------

class TestDirScanDedup(unittest.TestCase):
    RAW = [
        {"url": "https://example.com/Login", "status": 200, "length": 100,
         "content_type": "text/html"},
        {"url": "https://example.com/login", "status": 301, "length": 0, "content_type": ""},
        {"url": "https://example.com/login", "status": 200, "length": 100,
         "content_type": "text/html"},
        {"url": "https://example.com/API/Users?z=1&a=2", "status": 200, "length": 50,
         "content_type": "application/json"},
        {"url": "https://example.com/api/users?a=2&z=1", "status": 200, "length": 50,
         "content_type": "application/json"},
        {"url": "https://example.com/admin", "status": 401, "length": 0, "content_type": ""},
    ]

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _run(self):
        from camty.adapters.recon_web import DirScanAdapter

        ctx = RunContext(
            Scope({"domains": ["example.com"], "min_interval_seconds": 0}),
            Audit(Path(self.tmp) / "audit.jsonl"), Path(self.tmp) / "evidence")
        with mock.patch("camty.modules.dir_scan.scan", return_value=list(self.RAW)):
            return DirScanAdapter().run({"base": "https://example.com/"}, ctx)

    def test_case_and_query_variants_dedup_to_one(self):
        result = self._run()
        findings = result.data["findings"]
        urls = [f["url"] for f in findings]
        self.assertEqual(len(findings), 3, "大小写/重复/query 顺序变体折叠，不同路径保留")
        self.assertEqual(len(urls), len(set(urls)))
        self.assertEqual(urls[0], "https://example.com/Login", "同 URL 变体保留首个")
        self.assertEqual(findings[0]["detail"]["status"], 200, "跨状态码保留首个")
        self.assertIn("https://example.com/admin", urls)
        severities = {f["url"]: f["severity"] for f in findings}
        self.assertEqual(severities["https://example.com/API/Users?z=1&a=2"], "medium")
        self.assertEqual(severities["https://example.com/admin"], "low")
        self.assertEqual(len(result.data["discovered"]), 3)
        self.assertIn("3 个非 fallback 路径", result.summary)

    def test_repeated_run_dedups_each_time(self):
        first = self._run()
        second = self._run()
        self.assertEqual(len(first.data["findings"]), len(second.data["findings"]))
        self.assertEqual([f["url"] for f in first.data["findings"]],
                         [f["url"] for f in second.data["findings"]])

    def test_evidence_keeps_raw_scan_output(self):
        result = self._run()
        raw = Path(result.evidence).read_text(encoding="utf-8")
        for url in ("https://example.com/Login", "https://example.com/login",
                    "https://example.com/api/users?a=2&z=1"):
            self.assertIn(url, raw, "证据文件保留原始扫描输出")
        self.assertEqual(raw.count('"url"'), 6, "原始 6 条全量落档（证据不丢信息）")


if __name__ == "__main__":
    unittest.main()
