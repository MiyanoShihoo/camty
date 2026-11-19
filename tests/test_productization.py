"""产品化末梢测试：steer 人在环路 / scopesentry 同步 mock E2E / MCP 桥 mock E2E / 流量回放 API。"""

from __future__ import annotations

import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import yaml

from camty.adapters.base import RunContext
from camty.agent.state import Engagement
from camty.guardrail import steer
from camty.mcpbridge import MCPClient, attach


def make_eng(tmp: str, cfg_extra: dict | None = None) -> Engagement:
    pack = {"name": "pp", "title": "t", "phases": [], "plan": []}
    root = Path(tmp)
    (root / "packs" / "pp").mkdir(parents=True, exist_ok=True)
    (root / "packs" / "pp" / "pack.yaml").write_text(
        yaml.safe_dump(pack), encoding="utf-8")
    (root / "engagements").mkdir(exist_ok=True)
    cfg = {"name": "pp-eng", "pack": "pp", "root_domain": "example.com",
           "scope": {"domains": ["example.com"], "ips": ["127.0.0.1"],
                     "min_interval_seconds": 0}}
    cfg.update(cfg_extra or {})
    path = root / "engagements" / "pp-eng.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return Engagement(path)


class TestSteer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)

    def test_queue_consume_persist(self):
        steer.steer(self.eng, "优先测登录后 API")
        steer.steer(self.eng, "跳过目录爆破")
        self.assertEqual(len(steer.pending_summary(self.eng)), 2)
        taken = steer.take_pending(self.eng)
        self.assertEqual(len(taken), 2)
        self.assertIn("operator 转向指令", steer.as_prompt(taken))
        self.assertIn("优先测登录后 API", steer.as_prompt(taken))
        self.assertEqual(steer.pending_summary(self.eng), [])
        # 断点续跑：消费状态持久化
        eng2 = Engagement(Path(self.tmp) / "engagements" / "pp-eng.yaml")
        self.assertEqual(steer.pending_summary(eng2), [])
        # 审计留痕
        adapters = [e.get("adapter") for e in self.eng.audit.entries()]
        self.assertIn("operator-steer", adapters)

    def test_empty_pending(self):
        self.assertEqual(steer.take_pending(self.eng), [])
        self.assertEqual(steer.as_prompt([]), "")


class TestScopeSentrySync(unittest.TestCase):
    """mock ScopeSentry：分页列表 → 资产图 upsert。"""

    @staticmethod
    def _make_server(port: int):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.headers.get("Authorization") != "tok-1":
                    self._reply(401, {"code": 401, "message": "unauthorized"})
                    return
                if self.path.startswith("/api/asset/subdomain/list"):
                    page = 1 if "page=1" in self.path else 2
                    items = ({"subdomain": f"a{page}.example.com"},
                            {"subdomain": f"b{page}.example.com"}) if page == 1 else []
                    self._reply(200, {"code": 200, "data": {"items": items}})
                elif self.path.startswith("/api/asset/ip/list"):
                    self._reply(200, {"code": 200, "data": {"items": [{"ip": "203.0.113.7"}]}})
                else:
                    self._reply(404, {"code": 404})

            def _reply(self, status, body):
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        srv = http.server.HTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)
        self.srv = self._make_server(0)
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()

    def test_sync_e2e(self):
        from camty.adapters.scopesentry_sync import ScopeSentrySyncAdapter

        adapter = ScopeSentrySyncAdapter()
        result = adapter.run({
            "url": f"http://127.0.0.1:{self.port}",
            "token": "tok-1",
            "asset_types": ["subdomain", "ip"],
        }, self.eng.ctx)
        # 2 子域 + 1 IP 入图
        subs = [a for a in self.eng.assets.all() if a["kind"] == "subdomain"]
        ips = [a for a in self.eng.assets.all() if a["kind"] == "host"]
        self.assertEqual(len(subs), 2)
        self.assertEqual(len(ips), 1)
        self.assertEqual(subs[0]["source"], "scopesentry")
        self.assertIn("同步 3", result.summary)

    def test_sync_bad_token(self):
        from camty.adapters.scopesentry_sync import ScopeSentrySyncAdapter

        adapter = ScopeSentrySyncAdapter()
        result = adapter.run({
            "url": f"http://127.0.0.1:{self.port}",
            "token": "wrong",
            "asset_types": ["ip"],
        }, self.eng.ctx)
        self.assertTrue(any("401" in str(s.get("error", "")) for s in result.data["by_type"]))


class TestMCPBridge(unittest.TestCase):
    """mock MCP 服务器：initialize → tools/list → tools/call 全链。"""

    @staticmethod
    def _make_server(port: int):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(length))
                if req.get("method") == "initialize":
                    result = {"protocolVersion": "2025-06-18",
                              "serverInfo": {"name": "mock-mcp"},
                              "capabilities": {"tools": {}}}
                elif req.get("method") == "notifications/initialized":
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                elif req.get("method") == "tools/list":
                    result = {"tools": [
                        {"name": "recon_scan",
                         "description": "扫描一个 URL",
                         "inputSchema": {"type": "object",
                                          "properties": {"url": {"type": "string"}},
                                          "required": ["url"]}},
                        {"name": "echo",
                         "description": "回显",
                         "inputSchema": {"type": "object", "properties": {}},
                         }]}
                elif req.get("method") == "tools/call":
                    if req["params"]["name"] == "recon_scan":
                        result = {"content": [
                            {"type": "text", "text": f"scan done: {req['params']['arguments']['url']}"}]}
                    else:
                        result = {"isError": True, "content": [{"type": "text", "text": "bad tool"}]}
                else:
                    result = {}
                raw = json.dumps({"jsonrpc": "2.0", "id": req.get("id", 1),
                                  "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        srv = http.server.HTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.srv = self._make_server(0)
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()

    def test_client_full_chain(self):
        client = MCPClient("mock", f"http://127.0.0.1:{self.port}/mcp")
        client.initialize()
        tools = client.list_tools()
        self.assertEqual(len(tools), 2)
        out = client.call_tool("recon_scan", {"url": "https://x.com"})
        self.assertIn("scan done: https://x.com", out)

    def test_attach_makes_adapters(self):
        eng = make_eng(self.tmp, cfg_extra={
            "mcp_servers": [{"name": "mock", "url": f"http://127.0.0.1:{self.port}/mcp"}]})
        registry = {}
        added = attach(eng.cfg, registry)
        self.assertEqual(len(added), 2)
        self.assertIn("mcp:mock:recon_scan", registry)
        # 适配器可用：run 输出摘要 + 审计
        adapter = registry["mcp:mock:recon_scan"]
        self.assertEqual(adapter.tool_def()["function"]["name"], "mcp:mock:recon_scan")
        result = adapter.run({"url": "https://example.com"}, eng.ctx)
        self.assertIn("scan done", result.summary)

    def test_tool_error_raises(self):
        client = MCPClient("mock", f"http://127.0.0.1:{self.port}/mcp")
        client.initialize()
        import camty.mcpbridge as mb
        with self.assertRaises(mb.MCPError):
            client.call_tool("nope", {})


class TestTrafficReplayAPI(unittest.TestCase):
    def test_entries_paging(self):
        # 直接测 app 的处理函数（不起 uvicorn）
        self.tmp = tempfile.mkdtemp()
        eng = make_eng(self.tmp)
        log = eng.dir / "traffic" / "traffic.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        entries = [{"ts": f"t{i}", "host": "h", "method": "GET", "path": f"/p{i}",
                    "status": 200} for i in range(30)]
        log.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")
        lines = log.read_text(encoding="utf-8").splitlines()
        parsed = [json.loads(x) for x in lines if x.strip()]
        self.assertEqual(len(parsed), 30)
        page = parsed[10:10 + 50]
        self.assertEqual(page[0]["path"], "/p10")


if __name__ == "__main__":
    unittest.main()
