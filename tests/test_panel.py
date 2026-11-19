"""面板工程测试：LLM 用量记账 + Bearer 鉴权 + SSE 活动流。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from camty.llm.router import LLMError, LLMRouter, ProviderConfig, UsageLog
from tests.test_artex_port import make_eng


class TestUsageLog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = UsageLog(Path(self.tmp) / "usage.jsonl")

    def test_record_and_totals(self):
        self.log.record("decide", "p1", "m1", prompt_tokens=100, completion_tokens=50)
        self.log.record("decide", "p1", "m1", prompt_tokens=30, completion_tokens=20)
        self.log.record("recon", "p2", "m2", ok=False, error="HTTP 429")
        totals = self.log.totals()
        self.assertEqual(totals["calls"], 3)
        self.assertEqual(totals["errors"], 1)
        self.assertEqual(totals["prompt_tokens"], 130)
        self.assertEqual(totals["completion_tokens"], 70)
        self.assertEqual(totals["by_provider"]["p2"]["errors"], 1)

    def test_read_tail_and_corrupt_line_tolerated(self):
        path = Path(self.tmp) / "usage.jsonl"
        path.write_text('{"bad json\n', encoding="utf-8")
        self.log.record("decide", "p", "m", prompt_tokens=1)
        records = self.log.read(limit=10)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["prompt_tokens"], 1)

    def test_missing_file(self):
        log = UsageLog(Path(self.tmp) / "nope" / "usage.jsonl")
        self.assertEqual(log.totals()["calls"], 0)
        self.assertEqual(log.read(), [])

    def test_router_records_on_success_and_failure(self):
        router = LLMRouter.__new__(LLMRouter)
        router.providers = {"a": ProviderConfig("a", "openai", "http://x", "k",
                                                {"decide": "m"})}
        router.vault_path = Path(self.tmp) / "keys.json"
        router.usage = UsageLog(Path(self.tmp) / "usage.jsonl")
        ok_body = {"content": "hi", "tool_calls": [],
                   "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
        with mock.patch.object(LLMRouter, "_chat_openai", return_value=ok_body):
            resp = router.chat("decide", [{"role": "user", "content": "hi"}])
        self.assertEqual(resp["content"], "hi")
        with mock.patch.object(LLMRouter, "_chat_openai", side_effect=LLMError("boom")):
            with self.assertRaises(LLMError):
                router.chat("decide", [])
        totals = router.usage.totals()
        self.assertEqual(totals["calls"], 2)
        self.assertEqual(totals["errors"], 1)
        self.assertEqual(totals["prompt_tokens"], 10)

    def test_anthropic_usage_normalized(self):
        router = LLMRouter.__new__(LLMRouter)
        body = {"content": [{"type": "text", "text": "hi"}],
                "usage": {"input_tokens": 7, "output_tokens": 3}}
        out = router._norm_usage_anthropic(body)
        self.assertEqual(out, {"prompt_tokens": 7, "completion_tokens": 3})
        # openai 风格
        self.assertEqual(router._norm_usage_openai({"usage": {"prompt_tokens": 9}}),
                         {"prompt_tokens": 9, "completion_tokens": 0})


class TestPanelAuthAndSSE(unittest.TestCase):
    """FastAPI 面板：CAMTY_PANEL_TOKEN 鉴权 + SSE 流 + usage 端点。"""

    def setUp(self):
        import os

        from fastapi.testclient import TestClient

        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)
        os.environ["CAMTY_VAULT"] = str(Path(self.tmp) / "keys.json")
        from camty.api import app as app_mod

        # 面板发现交战靠 CWD/engagements，这里直接注入内存实例
        app_mod._ENGAGEMENTS[self.eng.name] = self.eng
        self.client = TestClient(app_mod.app)
        self.app_mod = app_mod

    def tearDown(self):
        self.app_mod._ENGAGEMENTS.pop(self.eng.name, None)
        import os

        os.environ.pop("CAMTY_PANEL_TOKEN", None)

    def test_no_token_required_by_default(self):
        resp = self.client.get(f"/api/engagements/{self.eng.name}/ledger")
        self.assertEqual(resp.status_code, 200)

    def test_bearer_required_when_configured(self):
        self.app_mod.os.environ["CAMTY_PANEL_TOKEN"] = "sekret"
        resp = self.client.get(f"/api/engagements/{self.eng.name}/ledger")
        self.assertEqual(resp.status_code, 401)
        resp = self.client.get(f"/api/engagements/{self.eng.name}/ledger",
                               headers={"Authorization": "Bearer wrong"})
        self.assertEqual(resp.status_code, 401)
        resp = self.client.get(f"/api/engagements/{self.eng.name}/ledger",
                               headers={"Authorization": "Bearer sekret"})
        self.assertEqual(resp.status_code, 200)
        # SSE 走 ?token= 查询参数（duration=0.1 使流立刻收口）
        resp = self.client.get(
            f"/api/engagements/{self.eng.name}/events",
            params={"token": "sekret", "duration": 0.1, "interval": 0.05},
            headers={"Authorization": "Bearer sekret"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/event-stream", resp.headers["content-type"])

    def test_usage_endpoint(self):
        log = UsageLog(Path(self.tmp) / "usage.jsonl")
        log.record("decide", "p1", "m1", prompt_tokens=100, completion_tokens=50)
        resp = self.client.get("/api/usage")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["totals"]["calls"], 1)
        self.assertEqual(data["totals"]["prompt_tokens"], 100)

    def test_blackboard_endpoints(self):
        resp = self.client.post(f"/api/engagements/{self.eng.name}/blackboard",
                                json={"kind": "operator", "note": "注意限流"})
        self.assertEqual(resp.status_code, 200)
        resp = self.client.get(f"/api/engagements/{self.eng.name}/blackboard")
        notes = resp.json()["notes"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["source"], "panel")
        # 空备注被拒
        resp = self.client.post(f"/api/engagements/{self.eng.name}/blackboard",
                                json={"kind": "operator", "note": " "})
        self.assertEqual(resp.status_code, 400)

    def test_sse_streams_activity(self):
        self.eng.db.add_activity("I-001", 1, "nuclei", "{}", "2 hits", None)
        resp = self.client.get(f"/api/engagements/{self.eng.name}/events",
                               params={"duration": 0.1, "interval": 0.05})
        self.assertEqual(resp.status_code, 200)
        data_lines = [line for line in resp.text.splitlines()
                      if line.startswith("data:")]
        self.assertTrue(data_lines)
        payload = json.loads(data_lines[0][5:].strip())
        self.assertEqual(len(payload["activity"]), 1)
        self.assertEqual(payload["activity"][0]["tool"], "nuclei")
        self.assertIn("engine", payload["state"])


if __name__ == "__main__":
    unittest.main()
