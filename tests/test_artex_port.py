"""ARTEX 移植测试：资产图/探索图/规则门/审批/多 agent 引擎/流量代理/推送/池退避/血缘。"""

from __future__ import annotations

import json
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import yaml

from camty.adapters.base import RunContext, ToolResult
from camty.adapters.mock import MockSubfinder
from camty.agent.assets import AssetGraph, normalize
from camty.agent.explore import ExplorationGraph, Todolist
from camty.agent.runner import DeterministicRunner, _merge_result, ingest_assets
from camty.agent.state import Engagement
from camty.guardrail.approval import decide_confirm, model_review
from camty.guardrail.rules import active_rules, check_rules
from camty.llm.router import LLMError, LLMRouter, ProviderConfig
from camty.notify import _format_text, push_findings
from camty.storage import StateDB
from camty.traffic import CertFactory, TrafficProxy

from tests.test_auto import MockFindings
from tests.test_planner import make_project


def build_registry():
    from camty.adapters.registry import REGISTRY

    return {"mock-subfinder": MockSubfinder(),
            "mock-findings": MockFindings(),
            "report": REGISTRY["report"]}


def make_eng(tmp: str, plan: list | None = None, extra_cfg: dict | None = None) -> Engagement:
    pack = {"name": "port-pack", "title": "移植测试", "phases": [], "plan": plan or []}
    root = Path(tmp)
    (root / "packs" / "port-pack").mkdir(parents=True, exist_ok=True)
    (root / "packs" / "port-pack" / "pack.yaml").write_text(
        yaml.safe_dump(pack), encoding="utf-8")
    (root / "engagements").mkdir(exist_ok=True)
    cfg = {
        "name": "port-eng",
        "pack": "port-pack",
        "root_domain": "example.com",
        "scope": {"domains": ["example.com"], "min_interval_seconds": 0},
        "auto_confirm": True,
    }
    cfg.update(extra_cfg or {})
    path = root / "engagements" / "port-eng.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return Engagement(path)


class TestAssetGraph(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = StateDB(Path(self.tmp) / "state.db")
        self.graph = AssetGraph(self.db)

    def test_normalize(self):
        self.assertEqual(normalize("service", "https://a.com:8443/x?y=1"), "https://a.com:8443")
        self.assertEqual(normalize("endpoint", "https://a.com/api/x?q=1"), "https://a.com/api/x")
        self.assertEqual(normalize("subdomain", "WWW.A.com."), "www.a.com")

    def test_auto_parent_chain(self):
        self.graph.upsert("root_domain", "example.com")
        self.graph.upsert("subdomain", "a.example.com")
        self.graph.upsert("host", "a.example.com")
        self.graph.upsert("service", "https://a.example.com")
        self.graph.upsert("endpoint", "https://a.example.com/api/v1/users")
        nodes = {a["dedup_key"]: a for a in self.graph.all()}
        self.assertEqual(nodes["subdomain|a.example.com"]["parent_key"], "root_domain|example.com")
        self.assertEqual(nodes["host|a.example.com"]["parent_key"], "subdomain|a.example.com")
        self.assertEqual(nodes["service|https://a.example.com"]["parent_key"], "host|a.example.com")
        self.assertEqual(
            nodes["endpoint|https://a.example.com/api/v1/users"]["parent_key"],
            "service|https://a.example.com")
        # 幂等
        self.graph.upsert("subdomain", "a.example.com")
        self.assertEqual(len(self.graph.all()), 5)

    def test_mark_tested_and_coverage(self):
        self.graph.upsert("root_domain", "example.com")
        self.graph.upsert("endpoint", "https://example.com/api/x")
        self.assertEqual(self.graph.mark_tested("https://example.com/api/x"), 1)
        # 幂等：重复标记不重复计数
        self.assertEqual(self.graph.mark_tested("https://example.com/api/x"), 0)
        cov = self.graph.coverage()
        self.assertEqual(cov["tested"], 1)
        self.assertEqual(cov["by_kind"]["endpoint"]["tested"], 1)
        # 未知 endpoint 路径退化为标记所属 service（父链 root_domain 不连坐）
        self.graph.upsert("service", "https://example.com")
        self.assertEqual(self.graph.mark_tested("https://example.com/unknown/path"), 1)
        by = {a["kind"]: a for a in self.graph.all()}
        self.assertTrue(by["service"]["tested"])
        self.assertFalse(by["root_domain"]["tested"], "最深命中即停：父链不应连坐标记")

    def test_tree(self):
        self.graph.upsert("root_domain", "example.com")
        self.graph.upsert("subdomain", "a.example.com")
        tree = self.graph.tree()
        self.assertEqual(len(tree), 1)
        self.assertEqual(tree[0]["children"][0]["value"], "a.example.com")


class TestExplorationGraph(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)
        self.graph = ExplorationGraph(self.eng)

    def test_nodes_edges_anchors(self):
        goal = self.graph.add_node("goal", "取 leaderboard 用户")
        intent = self.graph.add_node("intent", "探测存活")
        self.graph.link(goal, intent, "spawns")
        self.graph.anchor(intent, "root_domain|example.com")
        fact = self.graph.add_node("fact", "53 个端点")
        self.graph.link(intent, fact, "yields")
        self.graph.set_status(intent, "done")
        state = self.graph.graph()
        ids = {n["node_id"] for n in state["nodes"]}
        self.assertTrue(intent in ids)
        rels = {(e["src"], e["dst"], e["relation"]) for e in state["edges"]}
        self.assertIn((goal, intent, "spawns"), rels)
        self.assertIn((intent, fact, "yields"), rels)
        self.assertEqual(len(state["anchors"]), 1)
        self.assertEqual(self.graph.intents_pending(), [])
        self.assertEqual(self.graph.overview()["counts"]["fact"], 1)

    def test_todolist_ready(self):
        todo = Todolist(self.eng)
        todo.replace([
            {"item_id": "T1", "title": "侦察", "depends_on": [], "status": "pending"},
            {"item_id": "T2", "title": "利用", "depends_on": ["T1"], "status": "pending"},
        ])
        ready = todo.ready_items()
        self.assertEqual([i["item_id"] for i in ready], ["T1"])
        todo.mark("T1", "done")
        ready = todo.ready_items()
        self.assertEqual([i["item_id"] for i in ready], ["T2"])

    def test_trace_and_search(self):
        self.graph.trace("I-001", 1, "nuclei", {"hosts": "x"}, "3 hits", "e.txt")
        self.graph.trace("I-002", 1, "subfinder", {"domain": "x"}, "10 hosts", None)
        hits = self.graph.search_traces("hits", exclude_node="I-001")
        self.assertEqual(hits, [])  # 排除自己后无命中
        hits = self.graph.search_traces("hits", exclude_node="I-002")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["node_id"], "I-001")


class TestRules(unittest.TestCase):
    def test_delete_path_deny(self):
        reason = check_rules({}, "browser-action",
                             {"actions": [{"type": "goto", "url": "http://a.com/api/user/delete?id=1"}]})
        self.assertIsNotNone(reason)
        self.assertIn("http-delete-path", reason)

    def test_no_false_positive_on_similar_words(self):
        self.assertIsNone(check_rules({}, "browser-action",
                                       {"actions": [{"type": "goto", "url": "http://a.com/delivery"}]}))

    def test_sql_destructive(self):
        self.assertIsNotNone(check_rules({}, "sqli-exploit", {"query": "DROP TABLE users"}))
        self.assertIsNone(check_rules({}, "sqli-exploit", {"query": "SELECT version()"}))

    def test_shell_destructive(self):
        self.assertIsNotNone(check_rules({}, "c2-task", {"command": "rm -rf /"}))

    def test_scope_restricted_adapters(self):
        # 规则只作用于 applies 列出的适配器
        self.assertIsNone(check_rules({}, "report", {"url": "http://a.com/api/delete"}))

    def test_disable_and_extra(self):
        cfg = {"rules": {"disable": ["http-delete-path"],
                         "extra": [{"id": "x", "applies": ["report"], "pattern": "forbidden"}]}}
        self.assertIsNone(check_rules(cfg, "browser-action",
                                      {"actions": [{"url": "http://a.com/api/delete"}]}))
        self.assertIsNotNone(check_rules(cfg, "report", {"x": "forbidden"}))
        self.assertEqual([r["id"] for r in active_rules(cfg)][-1], "x")


class TestApproval(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)

    def test_auto_confirm_cfg(self):
        adapter = build_registry()["mock-findings"]
        proceed, mode, _ = decide_confirm(self.eng, adapter, {})
        self.assertTrue(proceed)
        self.assertEqual(mode, "auto_confirm")

    def test_auto_mode(self):
        self.eng.cfg["approval"] = {"mode": "auto"}
        proceed, mode, _ = decide_confirm(self.eng, build_registry()["mock-findings"], {})
        self.assertTrue(proceed)
        self.assertEqual(mode, "auto")

    def test_model_review_approve_and_deny(self):
        router = mock.MagicMock()
        router.chat.return_value = {"content": '{"approve": true, "reason": "只读侦察"}'}
        ok, reason = model_review(router, build_registry()["mock-findings"], {}, self.eng)
        self.assertTrue(ok)
        router.chat.return_value = {"content": '{"approve": false, "reason": "目标在范围外"}'}
        ok, reason = model_review(router, build_registry()["mock-findings"], {}, self.eng)
        self.assertFalse(ok)
        # 不可解析 → 保守拒绝
        router.chat.return_value = {"content": "approve it please"}
        ok, _ = model_review(router, build_registry()["mock-findings"], {}, self.eng)
        self.assertFalse(ok)

    def test_model_mode_no_router(self):
        self.eng.cfg["approval"] = {"mode": "model"}
        proceed, _, note = decide_confirm(self.eng, build_registry()["mock-findings"], {})
        self.assertFalse(proceed)
        self.assertIn("保守拒绝", note)


class TestMergeLineageAssets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)

    def test_merge_ingests_assets_and_lineage(self):
        result = ToolResult(
            summary="ok",
            data={
                "subdomains": ["a.example.com", "b.example.com"],
                "live_sites": [{"url": "https://a.example.com", "status": 200}],
                "endpoints": [{"endpoint": "https://a.example.com/api/v1/users"}],
                "findings": [
                    {"template": "secret/openai-api-key", "severity": "high",
                     "url": "https://a.example.com", "detail": "sk-xxx"},
                ],
            },
            evidence=None,
        )
        _merge_result(self.eng, result, derived_from=["F-001"])
        kinds = [a["kind"] for a in self.eng.assets.all()]
        self.assertIn("subdomain", kinds)
        self.assertIn("service", kinds)
        self.assertIn("endpoint", kinds)
        f = self.eng.ledger.findings[0]
        self.assertEqual(f.derived_from, ["F-001"])
        # finding url → 已测标记
        svc = [a for a in self.eng.assets.all() if a["kind"] == "service"]
        self.assertTrue(svc[0]["tested"])

    def test_runner_single_records_lineage(self):
        eng = self.eng
        eng.ledger.add(kind="vuln", target="https://example.com", detail="mock-vuln", verified=True)
        runner = DeterministicRunner(eng, build_registry())
        runner._run_single({"adapter": "mock-findings", "args": {"finding_id": "F-001"}})
        derived = [f.derived_from for f in eng.ledger.findings
                   if f.detail == "mock-vuln" and f.id != "F-001"]
        self.assertEqual(derived, [["F-001"]])


class TestEngineDeterministic(unittest.TestCase):
    """引擎确定性模式：pack plan → todolist → 意图 → 并行 worker → 写回。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_pack_plan_run(self):
        from camty.agent.engine import Engine

        plan = [
            {"adapter": "mock-subfinder", "args": {"domain": "{root_domain}"},
             "provides": ["subdomains"]},
            {"adapter": "mock-findings", "requires": ["subdomains"], "provides": ["findings"]},
            {"adapter": "report"},
        ]
        eng = make_eng(self.tmp, plan=plan)
        engine = Engine(eng, router=None, registry=build_registry(), n_workers=3)
        self.assertTrue(engine.run())
        todo = {i["item_id"]: i for i in Todolist(eng).items()}
        self.assertEqual(len(todo), 3)
        self.assertTrue(all(i["status"] == "done" for i in todo.values()))
        graph = ExplorationGraph(eng).graph()
        kinds = [n["kind"] for n in graph["nodes"]]
        self.assertEqual(kinds.count("intent"), 3)
        self.assertGreaterEqual(kinds.count("fact"), 3)
        # activity 过程落库
        self.assertGreaterEqual(len(eng.db.load_activity()), 3)
        self.assertTrue(eng.ledger.findings)
        self.assertIn("subdomains", eng.context)


class TestEngineLLM(unittest.TestCase):
    """引擎 LLM 模式：规划者 JSON → worker 工具循环 → 重规划收束。"""

    class MockRouter:
        def __init__(self, script):
            self.script = list(script)
            self.calls = []

        def chat(self, role, messages, tools=None, timeout=None):
            self.calls.append(role)
            return self.script.pop(0)

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_llm_plan_and_worker(self):
        from camty.agent.engine import Engine

        eng = make_eng(self.tmp)
        todolist_json = json.dumps({
            "todolist": [{"item_id": "T1", "title": "子域侦察", "depends_on": [],
                          "status": "pending", "note": ""}], "spawn": ["T1"]})
        worker_tool = {"content": "", "tool_calls": [
            {"id": "c1", "name": "mock-subfinder", "arguments": {"domain": "example.com"}}]}
        router = self.MockRouter([
            {"content": todolist_json, "tool_calls": []},   # 规划 1
            worker_tool,                                      # worker 工具调用
            {"content": "子域侦察完成\n[RESULT: 成功]", "tool_calls": []},  # worker 总结（结果标记协议）
            {"content": todolist_json.replace('"pending"', '"done"'), "tool_calls": []},  # 规划 2
        ])
        engine = Engine(eng, router=router, registry=build_registry(), n_workers=2,
                        max_total_steps=10)
        self.assertTrue(engine.run())
        # T1 done、意图 done、context 产出
        todo = {i["item_id"]: i for i in Todolist(eng).items()}
        self.assertEqual(todo["T1"]["status"], "done")
        self.assertIn("subdomains", eng.context)
        nodes = {n["node_id"]: n for n in ExplorationGraph(eng).graph()["nodes"]}
        intent = next(n for n in nodes.values() if n["kind"] == "intent")
        self.assertEqual(intent["status"], "done")

    def test_llm_rule_deny_in_worker(self):
        from camty.agent.engine import Engine

        from camty.adapters.registry import REGISTRY

        eng = make_eng(self.tmp)
        registry = {**build_registry(), "browser-action": REGISTRY["browser-action"]}
        todolist_json = json.dumps({
            "todolist": [{"item_id": "T1", "title": "删除接口探测", "depends_on": [],
                          "status": "pending"}], "spawn": ["T1"]})
        router = self.MockRouter([
            {"content": todolist_json, "tool_calls": []},
            {"content": "", "tool_calls": [
                {"id": "c1", "name": "browser-action",
                 "arguments": {"actions": [{"type": "goto", "url": "http://example.com/api/delete"}]}}]},
            {"content": "被规则拦截，意图放弃", "tool_calls": []},
            {"content": todolist_json, "tool_calls": []},
        ])
        engine = Engine(eng, router=router, registry=registry, max_total_steps=10)
        engine.run()
        # 规则门拒绝记录在案（且从未真启动浏览器：拒绝发生在 adapter.run 之前）
        notes = [e.get("note", "") for e in eng.audit.entries()]
        self.assertTrue(any("rule-deny" in n for n in notes))


class TestTrafficProxy(unittest.TestCase):
    """MITM 代理 E2E：本地 HTTPS 靶机 + CONNECT 解密 + scope 拦截。"""

    @staticmethod
    def _make_server(cert_file: str, port: int):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file)

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = json.dumps({"ok": True, "path": self.path}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = HTTPServer(("127.0.0.1", port), H)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp, extra_cfg={
            "scope": {"domains": ["example.com"], "ips": ["127.0.0.1"],
                      "min_interval_seconds": 0}})

    def test_https_mitm_record(self):
        import urllib.request

        certs = CertFactory(Path(self.tmp) / "ca")
        leaf = certs.leaf_path("127.0.0.1")
        srv = self._make_server(leaf, 0)
        srv_port = srv.server_address[1]
        proxy = TrafficProxy(self.eng, port=0,
                             upstream_cafile=str(certs.ca_cert_path))
        proxy.start()
        try:
            ca_ctx = ssl.create_default_context(cafile=str(certs.ca_cert_path))
            import os

            os.environ["https_proxy"] = proxy.proxy_url()
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ca_ctx))
            with opener.open(f"https://127.0.0.1:{srv_port}/api/data", timeout=30) as resp:
                body = json.loads(resp.read().decode())
            self.assertTrue(body["ok"])
            stats = proxy.stats()
            self.assertEqual(stats["requests"], 1)
            self.assertIn("127.0.0.1", stats["hosts"])
            entry = json.loads(
                (self.eng.dir / "traffic" / "traffic.jsonl").read_text().splitlines()[0])
            self.assertEqual(entry["status"], 200)
            self.assertEqual(entry["scheme"], "https")
            self.assertIn("/api/data", entry["path"])
        finally:
            os.environ.pop("https_proxy", None)
            proxy.stop()
            srv.shutdown()

    def test_scope_enforcement(self):
        import urllib.error
        import urllib.request

        proxy = TrafficProxy(self.eng, port=0)
        proxy.start()
        try:
            # 用显式 ProxyHandler 的局部 opener，不碰全局 opener 也不碰
            # os.environ：urllib.request.urlopen 首次调用会把代理 env 焊进
            # 进程级 _opener 缓存，env pop 救不回来，会污染后续测试。
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy.proxy_url()}))
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                opener.open("http://203.0.113.9/x", timeout=10)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            proxy.stop()


class TestTrafficLeftoverPlumbing(unittest.TestCase):
    def test_overread_returns_tail_not_socket_attr(self):
        """头+体一次过读的交接必须走返回值，不能挂 socket 属性。

        Python 3.13+ 的 socket 对象没有 __dict__，旧实现把过读尾部挂
        sock._camty_leftover 会直接 AttributeError（真实 socketpair 可复现）。
        """
        import socket as socket_mod
        from camty.traffic import _read_body, _read_headers

        a, b = socket_mod.socketpair()
        try:
            b.sendall(b"POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nHELLO")
            b.close()  # 让 recv 读尽后自然 EOF
            headers, tail = _read_headers(a)
            self.assertEqual(dict(headers)[b"Content-Length"], b"5")
            self.assertEqual(tail, b"HELLO")
            self.assertFalse(hasattr(a, "_camty_leftover"))  # 零隐藏状态
            body = _read_body(a, headers, tail)
            self.assertEqual(body, b"HELLO")
        finally:
            a.close()


class TestConnectDrainShapes(unittest.TestCase):
    """CONNECT 排空必须双形态兼容：带隧道头（3.12+ urllib）与裸 CONNECT（≤3.11）。

    旧实现按 "\r\n\r\n" 找终止符，裸形态剩余恰为 "\r\n" → 永等不齐 → 双向死锁。
    死锁在测试里表现为 socket 超时（settimeout 兜底），而不是挂死测试进程。
    """

    def _drain_roundtrip(self, raw: bytes):
        import socket as socket_mod
        from camty.traffic import _drain_connect_headers, _read_line

        a, b = socket_mod.socketpair()
        try:
            b.sendall(raw)
            b.close()
            a.settimeout(5)  # 若实现退化为阻塞死锁，5s 后 timeout 使测试快速失败
            first = _read_line(a)
            self.assertTrue(first.startswith(b"CONNECT"))
            _drain_connect_headers(a)  # 死锁形态下这里抛 socket.timeout
        finally:
            a.close()

    def test_drain_with_tunnel_headers(self):
        self._drain_roundtrip(b"CONNECT 127.0.0.1:8443 HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n")

    def test_drain_bare_connect(self):
        self._drain_roundtrip(b"CONNECT 127.0.0.1:8443 HTTP/1.0\r\n\r\n")


class TestTodolistMarkConcurrency(unittest.TestCase):
    """并发 mark 不得丢失更新（引擎多 worker 会并发写 todolist）。

    旧 RMW 实现（load→改→DELETE 全表重插）在放大调度密度下 270/300 丢失
    （PoC 实测）；修复后单条 UPDATE 原子，任意切换密度零丢失。
    """

    ROUNDS = 200

    def test_no_lost_update_under_concurrent_marks(self):
        import sys as sys_mod
        import threading

        from camty.agent.explore import Todolist

        tmp = tempfile.mkdtemp()
        eng = make_eng(tmp)
        try:
            items = [{"item_id": f"T{i}", "title": f"t{i}", "depends_on": [],
                      "status": "pending"} for i in range(1, 4)]
            todo = Todolist(eng)
            todo.replace(items)
            old_interval = sys_mod.getswitchinterval()
            sys_mod.setswitchinterval(1e-6)  # 放大竞态窗口（模拟满载 CI 调度密度）
            try:
                for _ in range(self.ROUNDS):
                    todo.replace(items)  # 重置为全 pending
                    barrier = threading.Barrier(3)

                    def worker(item_id):
                        barrier.wait()
                        todo.mark(item_id, "done", note=f"n-{item_id}")

                    threads = [threading.Thread(target=worker, args=(f"T{i}",))
                               for i in range(1, 4)]
                    for t in threads:
                        t.start()
                    for t in threads:
                        t.join()
                    states = {i["item_id"]: i["status"] for i in todo.items()}
                    self.assertEqual(
                        {s: "done" for s in ("T1", "T2", "T3")}, states,
                        "并发 mark 丢失更新（RMW 覆盖回归）")
            finally:
                sys_mod.setswitchinterval(old_interval)
        finally:
            eng.close()


class TestNotify(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)

    def test_format_text(self):
        text = _format_text("eng", [{"severity": "high", "target": "a.com",
                                     "detail": "x", "verified": True,
                                     "derived_from": ["F-001"]}])
        self.assertIn("[HIGH] a.com", text)
        self.assertIn("F-001", text)

    def test_push_filters_by_severity(self):
        self.eng.cfg["notify"] = [{"type": "feishu", "url": "http://hook.example/x",
                                   "min_severity": "high"}]
        captured = {}

        def fake_open(req, timeout=0):
            captured["data"] = req.data.decode("utf-8")
            return mock.MagicMock(read=lambda: b"{}")

        findings = [
            {"severity": "high", "target": "a.com", "detail": "x"},
            {"severity": "info", "target": "b.com", "detail": "y"},  # 过滤掉
        ]
        with mock.patch("camty.notify.urllib.request.urlopen", side_effect=fake_open):
            results = push_findings(self.eng, findings)
        self.assertEqual(results[0][1], True)
        payload = json.loads(captured["data"])
        self.assertEqual(payload["msg_type"], "text")
        self.assertIn("a.com", payload["content"]["text"])
        self.assertNotIn("b.com", payload["content"]["text"])

    def test_push_error_does_not_raise(self):
        self.eng.cfg["notify"] = [{"type": "webhook", "url": "http://hook.example/x"}]
        with mock.patch("camty.notify.urllib.request.urlopen",
                        side_effect=OSError("boom")):
            results = push_findings(self.eng, [{"severity": "critical",
                                                "target": "a.com", "detail": "x"}])
        self.assertFalse(results[0][1])


class TestLLMPool(unittest.TestCase):
    def _bare_router(self) -> LLMRouter:
        """绕过 __init__ 构造最小 router（补 chat() 依赖的 usage 记账器）。"""
        from camty.llm.router import UsageLog

        router = LLMRouter.__new__(LLMRouter)
        router.vault_path = Path(tempfile.mkdtemp()) / "keys.json"
        router.usage = UsageLog(router.vault_path.parent / "usage.jsonl")
        return router

    def test_pool_failover(self):
        router = self._bare_router()
        router.providers = {
            "a": ProviderConfig("a", "openai", "http://x", "key-a", {"decide": "m1"}),
            "b": ProviderConfig("b", "openai", "http://y", "key-b", {"decide": "m2"}),
        }
        with mock.patch.object(LLMRouter, "_chat_openai", side_effect=[LLMError("boom"),
                                                                      {"content": "ok", "tool_calls": []}]):
            resp = router.chat("decide", [{"role": "user", "content": "hi"}])
        self.assertEqual(resp["content"], "ok")
        # 池退避留痕：失败一次 + 成功一次
        totals = router.usage.totals()
        self.assertEqual(totals["calls"], 2)
        self.assertEqual(totals["errors"], 1)

    def test_pool_all_fail(self):
        router = self._bare_router()
        router.providers = {"a": ProviderConfig("a", "openai", "http://x", "", {"decide": "m"})}
        with mock.patch.object(LLMRouter, "_chat_openai", side_effect=LLMError("boom")):
            with self.assertRaises(LLMError):
                router.chat("decide", [])


class TestEvidenceSearch(unittest.TestCase):
    def test_search_evidence_and_activity(self):
        from camty.adapters.evidence_search import EvidenceSearchAdapter
        from camty.adapters.registry import REGISTRY

        tmp = tempfile.mkdtemp()
        eng = make_eng(tmp)
        eng.ctx.save_evidence("nuclei", "example.com matched template cve-2024-1")
        eng.db.add_activity("I-001", 1, "nuclei", '{"hosts":"example.com"}',
                            "2 hits cve-2024-1", None)
        adapter: EvidenceSearchAdapter = REGISTRY["evidence-search"]
        result = adapter.run({"query": "cve-2024-1"}, eng.ctx)
        sources = {h["kind"] for h in result.data["hits"]}
        self.assertIn("evidence", sources)
        self.assertIn("activity", sources)


if __name__ == "__main__":
    unittest.main()
