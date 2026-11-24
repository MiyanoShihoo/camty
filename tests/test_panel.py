"""面板工程测试：LLM 用量记账 + Bearer 鉴权 + SSE 活动流 + XSS 加固。"""

from __future__ import annotations

import json
import tempfile
import threading
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
        os.environ.pop("CAMTY_PANEL_TOKEN", None)
        from camty.api import app as app_mod

        # P0-3 后 /api/* 一律需鉴权：默认走进程生成的随机 token（fail-secure）
        app_mod._reset_panel_token_for_tests()
        self.gen_token = app_mod._panel_token()
        self.auth = {"Authorization": f"Bearer {self.gen_token}"}
        # 面板发现交战靠 CWD/engagements，这里直接注入内存实例
        app_mod._ENGAGEMENTS[self.eng.name] = self.eng
        self.client = TestClient(app_mod.app)
        self.app_mod = app_mod

    def tearDown(self):
        self.app_mod._ENGAGEMENTS.pop(self.eng.name, None)
        import os

        os.environ.pop("CAMTY_PANEL_TOKEN", None)

    def test_unset_token_fail_secure(self):
        """P0-3：未设 CAMTY_PANEL_TOKEN → 自动生成随机 token，无 token 访问 /api/* 一律 401。

        原 test_no_token_required_by_default 断言的正是本任务修复的 fail-open 行为，
        随行为修复重写（详见 CHANGES.md P0-3 节）。
        """
        resp = self.client.get(f"/api/engagements/{self.eng.name}/ledger")
        self.assertEqual(resp.status_code, 401)
        resp = self.client.get(f"/api/engagements/{self.eng.name}/ledger",
                               headers=self.auth)
        self.assertEqual(resp.status_code, 200)

    def test_bearer_required_when_configured(self):
        self.app_mod.os.environ["CAMTY_PANEL_TOKEN"] = "sekret"
        resp = self.client.get(f"/api/engagements/{self.eng.name}/ledger")
        self.assertEqual(resp.status_code, 401)
        resp = self.client.get(f"/api/engagements/{self.eng.name}/ledger",
                               headers={"Authorization": "Bearer wrong"})
        self.assertEqual(resp.status_code, 401)
        # 显式环境变量优先：进程先前生成的随机 token 不再生效
        resp = self.client.get(f"/api/engagements/{self.eng.name}/ledger",
                               headers={"Authorization": f"Bearer {self.gen_token}"})
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
        resp = self.client.get("/api/usage", headers=self.auth)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["totals"]["calls"], 1)
        self.assertEqual(data["totals"]["prompt_tokens"], 100)

    def test_blackboard_endpoints(self):
        resp = self.client.post(f"/api/engagements/{self.eng.name}/blackboard",
                                json={"kind": "operator", "note": "注意限流"},
                                headers=self.auth)
        self.assertEqual(resp.status_code, 200)
        resp = self.client.get(f"/api/engagements/{self.eng.name}/blackboard",
                               headers=self.auth)
        notes = resp.json()["notes"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["source"], "panel")
        # 空备注被拒
        resp = self.client.post(f"/api/engagements/{self.eng.name}/blackboard",
                                json={"kind": "operator", "note": " "},
                                headers=self.auth)
        self.assertEqual(resp.status_code, 400)

    def test_sse_streams_activity(self):
        self.eng.db.add_activity("I-001", 1, "nuclei", "{}", "2 hits", None)
        resp = self.client.get(f"/api/engagements/{self.eng.name}/events",
                               params={"duration": 0.1, "interval": 0.05},
                               headers=self.auth)
        self.assertEqual(resp.status_code, 200)
        data_lines = [line for line in resp.text.splitlines()
                      if line.startswith("data:")]
        self.assertTrue(data_lines)
        payload = json.loads(data_lines[0][5:].strip())
        self.assertEqual(len(payload["activity"]), 1)
        self.assertEqual(payload["activity"][0]["tool"], "nuclei")
        self.assertIn("engine", payload["state"])


class TestPanelAuthFailSecure(unittest.TestCase):
    """P0-3：未设 CAMTY_PANEL_TOKEN 时自动生成随机 token 并强制鉴权（fail-secure）。

    对齐 c2/server/camty_c2.py 的缺省随机 token 模式；比较用 hmac.compare_digest；
    不做回环判断（反向代理下恒为 127.0.0.1，不可靠）。
    """

    def setUp(self):
        import os

        from fastapi.testclient import TestClient

        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)
        os.environ["CAMTY_VAULT"] = str(Path(self.tmp) / "keys.json")
        os.environ.pop("CAMTY_PANEL_TOKEN", None)
        from camty.api import app as app_mod

        app_mod._reset_panel_token_for_tests()
        app_mod._ENGAGEMENTS[self.eng.name] = self.eng
        self.client = TestClient(app_mod.app)
        self.app_mod = app_mod

    def tearDown(self):
        import os

        self.app_mod._ENGAGEMENTS.pop(self.eng.name, None)
        os.environ.pop("CAMTY_PANEL_TOKEN", None)
        self.app_mod._reset_panel_token_for_tests()

    def test_unset_env_generates_token_and_blocks_unauthenticated(self):
        resp = self.client.get("/api/engagements")
        self.assertEqual(resp.status_code, 401)
        token = self.app_mod._panel_token()  # 只读获取进程生成的 token
        self.assertRegex(token, r"^[0-9a-f]{32}$")  # secrets.token_hex(16)
        resp = self.client.get("/api/engagements",
                               headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)
        resp = self.client.get("/api/engagements",
                               headers={"Authorization": "Bearer wrong"})
        self.assertEqual(resp.status_code, 401)
        # ?token= 通道（SSE 需要）
        resp = self.client.get("/api/engagements", params={"token": token})
        self.assertEqual(resp.status_code, 200)
        # 静态页面壳不带数据，无需 token（JS 内 prompt 后走 /api/*）
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

    def test_non_ascii_token_rejected_not_500(self):
        # compare_digest 的 str 形式对非 ASCII 会 TypeError；实现须按字节比较避免 500。
        # httpx 只接受 ascii/bytes 头值，这里直接给原始字节构造非 ASCII 凭据。
        resp = self.client.get("/api/engagements",
                              headers={"Authorization": "Bearer 密码1324".encode("utf-8")})
        self.assertEqual(resp.status_code, 401)

    def test_token_reused_and_env_precedence(self):
        first = self.app_mod._panel_token()
        self.assertEqual(first, self.app_mod._panel_token())  # 进程生命周期内复用
        self.app_mod.os.environ["CAMTY_PANEL_TOKEN"] = "explicit-token"
        self.assertEqual(self.app_mod._panel_token(), "explicit-token")  # 显式指定优先
        self.app_mod.os.environ.pop("CAMTY_PANEL_TOKEN", None)
        self.app_mod._reset_panel_token_for_tests()
        regen = self.app_mod._panel_token()  # 重置后重新生成
        self.assertRegex(regen, r"^[0-9a-f]{32}$")
        self.assertNotEqual(regen, first)

    def test_generation_prints_token_to_stderr(self):
        import contextlib
        import io

        self.app_mod._reset_panel_token_for_tests()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            token = self.app_mod._panel_token()
        self.assertIn(token, err.getvalue())
        self.assertIn("CAMTY_PANEL_TOKEN", err.getvalue())

    def test_uses_constant_time_compare(self):
        import inspect

        src = inspect.getsource(self.app_mod)
        self.assertIn("hmac.compare_digest", src)
        self.assertNotIn("supplied != token", src)


class TestPanelConcurrencyAndLogging(unittest.TestCase):
    """P2-9：engine/retest 的 check-then-act 用模块级锁保护（并发只允许一个进入），
    宽泛 except 补 logging.exception（不改变返回行为）。保留 threading.Thread。"""

    N_CALLERS = 8

    def setUp(self):
        import os

        self.tmp = tempfile.mkdtemp()
        self.eng = make_eng(self.tmp)
        os.environ["CAMTY_VAULT"] = str(Path(self.tmp) / "keys.json")
        from camty.api import app as app_mod

        app_mod._ENGAGEMENTS[self.eng.name] = self.eng
        app_mod._ENGINE_STATE.pop(self.eng.name, None)
        app_mod._RETEST_STATE.pop(self.eng.name, None)
        self.app_mod = app_mod

    def tearDown(self):
        self.app_mod._ENGAGEMENTS.pop(self.eng.name, None)
        self.app_mod._ENGINE_STATE.pop(self.eng.name, None)
        self.app_mod._RETEST_STATE.pop(self.eng.name, None)

    def _run_concurrent(self, invoke):
        """N 个线程同时调用 invoke；在进入 handler 的公共入口（_engagement）处对齐，
        返回结果列表。修复前：8 个全过检查（无人置 running）→ 多个 started；
        修复后：锁内 check+set 原子化，仅 1 个 started。"""
        import time as _time

        gate = threading.Event()
        results: list[str] = []
        lock = threading.Lock()
        orig_engagement = self.app_mod._engagement

        def gated_engagement(name):
            gate.wait(timeout=3)
            return orig_engagement(name)

        def caller():
            status = invoke()["status"]
            with lock:
                results.append(status)

        threads = [threading.Thread(target=caller) for _ in range(self.N_CALLERS)]
        with mock.patch.object(self.app_mod, "_engagement", gated_engagement):
            for t in threads:
                t.start()
            _time.sleep(0.5)  # 等全部调用者对齐在 gate 上（此时无人置 running）
            gate.set()
            for t in threads:
                t.join(timeout=15)
        return results

    def test_concurrent_engine_start_single_entry(self):
        from camty.api.app import EngineRequest

        entered = threading.Event()
        release = threading.Event()

        class _BlockingEngine:
            def __init__(self, *args, **kwargs):
                pass

            def run(self):
                entered.set()
                release.wait(timeout=10)  # 卡住 "running" 窗口，暴露 check-then-act 竞态
                return True

        self.eng.save_state = lambda: None  # 测试不落盘
        with mock.patch.object(self.app_mod, "Engine", _BlockingEngine):
            results = self._run_concurrent(
                lambda: self.app_mod.start_engine(self.eng.name, EngineRequest()))
        try:
            self.assertEqual(sorted(results),
                             ["already-running"] * (self.N_CALLERS - 1) + ["started"])
            self.assertTrue(entered.wait(timeout=5), "引擎应被唯一放行方启动")
        finally:
            release.set()

    def test_concurrent_retest_single_entry(self):
        from camty.api.app import RetestRequest

        self.eng.ledger.add(kind="vuln", target="https://a.example.com/api",
                            detail="d", severity="high", verified=True)
        fid = self.eng.ledger.findings[0].id
        entered = threading.Event()
        release = threading.Event()

        def fake_run_retest(eng, router, finding_id, note=""):
            entered.set()
            release.wait(timeout=10)
            return {"verdict": "fixed", "finding_id": finding_id, "summary": ""}

        with mock.patch("camty.agent.retester.run_retest", side_effect=fake_run_retest):
            results = self._run_concurrent(
                lambda: self.app_mod.start_retest(
                    self.eng.name, RetestRequest(finding_id=fid, note="")))
        try:
            self.assertEqual(sorted(results),
                             ["already-running"] * (self.N_CALLERS - 1) + ["started"])
            self.assertTrue(entered.wait(timeout=5), "复测应被唯一放行方启动")
        finally:
            release.set()

    def test_engine_error_logged_with_exception(self):
        import time as _time

        from camty.api.app import EngineRequest

        class _BoomEngine:
            def __init__(self, *args, **kwargs):
                pass

            def run(self):
                raise RuntimeError("boom")

        self.eng.save_state = lambda: None
        with mock.patch.object(self.app_mod, "Engine", _BoomEngine):
            with self.assertLogs(level="ERROR") as captured:
                status = self.app_mod.start_engine(self.eng.name, EngineRequest())
                self.assertEqual(status["status"], "started")
                for _ in range(200):
                    if (self.app_mod._ENGINE_STATE.get(self.eng.name, {})
                            .get("status") == "error"):
                        break
                    _time.sleep(0.05)
        state = self.app_mod._ENGINE_STATE[self.eng.name]
        self.assertEqual(state["status"], "error")  # 返回行为不变
        self.assertIn("boom", state["error"])
        self.assertTrue(any("boom" in (rec.exc_text or "") for rec in captured.records),
                        "宽泛 except 应记录完整异常栈")

    def test_all_broad_excepts_log(self):
        import inspect
        import re as _re

        src = inspect.getsource(self.app_mod)
        sites = list(_re.finditer(r"except Exception[^\n]*:", src))
        self.assertGreaterEqual(len(sites), 4)  # list_engagements/engine/retest/ask 四处
        for m in sites:
            window = src[m.end():m.end() + 400]
            self.assertIn("logging.exception", window,
                          f"宽泛 except 缺 logging.exception: {src[m.start():m.end()]}")


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
        # sev()：esc 已内移函数体（纵深防御），调用点直接传原始值
        "sev(f.severity)": "sev() 调用点，函数体已内部 esc()",
        "s": "sev() 内部插值，函数体 esc(s) 后再插值",
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
        "Object.hasOwn(colors, hit.kind) ? colors[hit.kind] : '#fff'": "固定色板查表（Object.hasOwn 守卫原型链）",
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
