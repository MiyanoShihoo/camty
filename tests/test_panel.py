"""面板工程测试：LLM 用量记账 + Bearer 鉴权 + SSE 活动流 + XSS 加固。"""

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


# ---- P0-2 面板存储型 XSS（目标 → 操作员）----


def _panel_page() -> str:
    from camty.api import app as app_mod

    return app_mod._PAGE


def _scan_template(src: str, start: int, sink: list) -> int:
    """start 指向模板字面量的开反引号；收集其中每个 ${...}（嵌套模板递归收集），
    返回配对闭合反引号的索引。"""
    i, n = start + 1, len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            return i
        if c == "$" and i + 1 < n and src[i + 1] == "{":
            depth, j = 1, i + 2
            while j < n:
                cj = src[j]
                if cj == "\\":
                    j += 2
                    continue
                if cj == "{":
                    depth += 1
                elif cj == "}":
                    depth -= 1
                    if depth == 0:
                        break
                elif cj == "`":
                    j = _scan_template(src, j, sink)
                    continue
                j += 1
            sink.append(src[i + 2:j])
            i = j + 1
            continue
        i += 1
    return n


def _extract_interpolations(src: str) -> list[str]:
    """提取 _PAGE 中 JS 模板字面量里的全部 ${...} 插值原文（含嵌套模板内部）。"""
    sink: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            i = _scan_template(src, i, sink) + 1
            continue
        i += 1
    return sink


def _extract_esc_body(page: str) -> str:
    """提取 _PAGE 中 esc() 函数体（花括号配平）。"""
    start = page.index("function esc(")
    brace = page.index("{", start)
    depth, i = 1, brace + 1
    while depth and i < len(page):
        if page[i] == "{":
            depth += 1
        elif page[i] == "}":
            depth -= 1
        elif page[i] == "`":
            i = page.index("`", i + 1)
        i += 1
    return page[brace:i]


class TestPanelXssHardening(unittest.TestCase):
    """P0-2：_PAGE 全部动态插值必须 esc() 包裹或显式白名单；token 改 sessionStorage；CSP 元标签。"""

    # 显式白名单：逐个列明每处保留原因（插值原文 → 原因）。
    # 除计数/长度外，仅两类额外豁免：行构造变量（内部动态插值全部 esc()）、
    # 静态字面量三元/查表（分支均为字面量，无动态数据）。
    WHITELIST: dict[str, str] = {
        # 纯计数/长度/索引（数字，无注入面）
        "d.findings.length": "计数",
        "v.total": "计数",
        "v.tested": "计数",
        "d.traffic.requests": "计数",
        "Object.keys(d.traffic.hosts||{}).length": "计数",
        "(rt.records||[]).length": "计数",
        "(d.coverage.tested||0)": "计数",
        "d.coverage.total||0": "计数",
        "d.total||0": "计数",
        "(d.nodes||[]).length": "计数",
        "(d.edges||[]).length": "计数",
        "t.calls||0": "计数",
        "t.errors||0": "计数",
        "(t.prompt_tokens||0).toLocaleString()": "计数",
        "(t.completion_tokens||0).toLocaleString()": "计数",
        "v.calls": "计数",
        "v.errors": "计数",
        "(v.prompt_tokens||0).toLocaleString()": "计数",
        "(v.completion_tokens||0).toLocaleString()": "计数",
        "i": "索引（data-i 行序号，数组下标）",
        # sev()：调用点入参已包 esc()，函数体插值的是已转义值
        "sev(esc(f.severity))": "sev() 调用点，入参已 esc()",
        "s": "sev() 内部插值，入参在全部调用点已 esc()",
        # 行构造变量：所有单元格动态插值均 esc() 包裹后 join
        "findingRows": "行构造（内部动态插值已全 esc）",
        "assetRows": "行构造（内部动态插值已全 esc）",
        "todoRows": "行构造（内部动态插值已全 esc）",
        "recordRows": "行构造（内部动态插值已全 esc）",
        "assetTreeRows": "行构造（内部动态插值已全 esc）",
        "trafficRows": "行构造（内部动态插值已全 esc）",
        "nodeRows": "行构造（内部动态插值已全 esc）",
        "edgeRows": "行构造（内部动态插值已全 esc）",
        "activityRows": "行构造（内部动态插值已全 esc）",
        "providerRows": "行构造（内部动态插值已全 esc）",
        "recentRows": "行构造（内部动态插值已全 esc）",
        # 静态字面量三元/查表：分支均为字面量，无动态数据
        "f.disposal==='fixed' ? '<span style=\"color:#2ecc71\">已修复</span>' : '开放'": "静态字面量三元",
        ("r.verdict==='fixed' ? '<span style=\"color:#2ecc71\">已修复</span>' :"
         " r.verdict==='reproduced' ? '<span style=\"color:#e74c3c\">仍可复现</span>' : '无法确认'"): "静态字面量三元",
        "colors[hit.kind]||'#fff'": "固定色板查表",
    }
    # 期望清点：esc() 包裹处数 / 白名单命中处数（新增插值必须显式归类，防止漏包）
    # 当前清点：117 处插值 = 77 处 esc() + 40 处白名单（计数 20、sev 内部/调用点 4、
    # 行构造变量 13、静态字面量三元/查表 3）
    ESC_COUNT = 77
    WHITELIST_COUNT = 40

    def test_no_bare_interpolations(self):
        page = _panel_page()
        bare = [e for e in _extract_interpolations(page)
                if not e.strip().startswith("esc(") and e.strip() not in self.WHITELIST]
        self.assertEqual(bare, [], f"发现未转义插值: {bare}")

    def test_interpolation_inventory(self):
        page = _panel_page()
        exprs = [e.strip() for e in _extract_interpolations(page)]
        esc_n = sum(1 for e in exprs if e.startswith("esc("))
        wl_n = sum(1 for e in exprs if e in self.WHITELIST)
        self.assertEqual(esc_n, self.ESC_COUNT)
        self.assertEqual(wl_n, self.WHITELIST_COUNT)
        self.assertEqual(esc_n + wl_n, len(exprs))

    def test_esc_escapes_xss_payload(self):
        import re as _re

        page = _panel_page()
        body = _extract_esc_body(page)
        chars = _re.search(r"replace\(/\[([^\]]*)\]/g", body)
        self.assertIsNotNone(chars, "esc() 未按字符类全局替换")
        mapping = {m[1]: m[3] for m in
                   _re.findall(r"(['\"])(.)\1\s*:\s*(['\"])(.*?)\3", body)}
        self.assertEqual(sorted(chars.group(1)), sorted("&<>\"'"))
        self.assertEqual(sorted(mapping), sorted("&<>\"'"))
        self.assertEqual(mapping["&"], "&amp;")
        self.assertEqual(mapping["<"], "&lt;")
        self.assertEqual(mapping[">"], "&gt;")
        self.assertEqual(mapping["\""], "&quot;")
        self.assertEqual(mapping["'"], "&#39;")
        payload = "</pre><img src=x onerror=alert(1)>"
        escaped = "".join(mapping.get(ch, ch) for ch in payload)
        self.assertNotIn("<img", escaped)
        self.assertNotIn("<", escaped)
        self.assertNotIn(">", escaped)
        self.assertIn("&lt;img", escaped)

    def test_csp_meta_present(self):
        page = _panel_page()
        self.assertIn(
            '<meta http-equiv="Content-Security-Policy" '
            "content=\"object-src 'none'; base-uri 'none'; frame-ancestors 'none'\">",
            page)
        # 不加 script-src 限制，避免破坏内联脚本
        self.assertNotIn("script-src", page.split("</head>")[0])

    def test_token_storage_moved_to_session_storage(self):
        page = _panel_page()
        self.assertNotIn("localStorage", page)
        # 读写点：api() 读、401 写入、EventSource URL 构造处读
        self.assertGreaterEqual(page.count("sessionStorage"), 3)


if __name__ == "__main__":
    unittest.main()
