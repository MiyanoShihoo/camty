"""模块级测试：sqli-probe（本地靶机）与 int-ad 适配器解析器（fixture）。"""

from __future__ import annotations

import http.server
import json
import threading
import unittest
from urllib.parse import parse_qsl, urlparse

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


if __name__ == "__main__":
    unittest.main()
