"""C2 全链 E2E：真实服务端 + 模拟 beacon + camty C2 适配器（真 HTTP 往返）。

验证三件事：
1. 契约互操作：camty c2-sessions/c2-task/c2-collect 适配器直连服务端无改动可用
2. 线缆协议：seal/open framing 在真实 HTTP 上工作
3. 护栏联动：范围外会话被适配器过滤、任务下发被 scope 拦截
"""

from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "c2" / "server"))

from camty.adapters.base import RunContext
from camty.adapters.c2 import C2CollectAdapter, C2SessionsAdapter, C2TaskAdapter
from camty.guardrail.audit import Audit
from camty.guardrail.scope import Scope, ScopeError
from fake_beacon import FakeBeacon
import protocol


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestC2EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.beacon_port = _free_port()
        cls.api_port = _free_port()
        cls.psk = protocol.gen_psk()
        cls.token = "e2e-token-123"
        cls.server = subprocess.Popen(
            [
                sys.executable, str(Path(__file__).resolve().parent.parent / "c2" / "server" / "camty_c2.py"),
                "--beacon-port", str(cls.beacon_port),
                "--api-port", str(cls.api_port),
                "--token", cls.token,
                "--psk", cls.psk.hex(),
                "--ops-log", str(Path(cls.tmp.name) / "ops.jsonl"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls._wait_api()
        cls.beacons = [
            FakeBeacon(f"http://127.0.0.1:{cls.beacon_port}", cls.psk,
                       host="192.168.100.10", user="corp\\in-scope", beacon_id="IN-1"),
            FakeBeacon(f"http://127.0.0.1:{cls.beacon_port}", cls.psk,
                       host="203.0.113.7", user="corp\\out-of-scope", beacon_id="OUT-1"),
        ]
        cls.threads = [b.start() for b in cls.beacons]
        cls._wait_sessions(2)

    @classmethod
    def _wait_api(cls, timeout=15.0):
        import urllib.request
        from urllib.request import ProxyHandler, build_opener

        deadline = time.time() + timeout
        opener = build_opener(ProxyHandler({}))  # 回环绕过系统代理
        while time.time() < deadline:
            try:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{cls.api_port}/health",
                    headers={"Authorization": f"Bearer {cls.token}"},
                )
                with opener.open(req, timeout=2) as resp:
                    if resp.status == 200:
                        return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("C2 服务端未在超时内就绪")

    @classmethod
    def _wait_sessions(cls, count: int, timeout=15.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = C2SessionsAdapter().run(
                {"c2_url": f"http://127.0.0.1:{cls.api_port}", "c2_token": cls.token},
                _ctx(cls),
            )
            if len(result.data["sessions"]) >= count:
                return
            time.sleep(0.3)
        raise RuntimeError("beacon 未在超时内注册")

    @classmethod
    def tearDownClass(cls):
        for b in cls.beacons:
            b.stop.set()
        cls.server.terminate()
        try:
            cls.server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.server.kill()
        cls.tmp.cleanup()

    def test_contract_interop_and_scope_gating(self):
        ctx = _ctx(self)
        url = f"http://127.0.0.1:{self.api_port}"
        base = {"c2_url": url, "c2_token": self.token}

        result = C2SessionsAdapter().run(dict(base), ctx)
        self.assertEqual(len(result.data["sessions"]), 2)
        self.assertEqual(len(result.data["in_scope_sessions"]), 1, "范围外会话应被过滤")

        with self.assertRaises(ScopeError):
            C2TaskAdapter().run(
                {**base, "session_id": "OUT-1", "command": "whoami", "finding_id": "F-001"}, ctx
            )

        task = C2TaskAdapter().run(
            {**base, "session_id": "IN-1", "command": "echo camty-c2-e2e", "finding_id": "F-001"}, ctx
        )
        task_id = task.data["task_id"]
        self.assertTrue(task_id)

        deadline = time.time() + 15
        status = None
        while time.time() < deadline:
            collect = C2CollectAdapter().run({**base, "task_id": task_id}, ctx)
            status = collect.data["status"]
            if status == "done":
                self.assertIn("camty-c2-e2e", collect.data["output"])
                break
            time.sleep(0.3)
        self.assertEqual(status, "done", f"任务未完成，状态: {status}")

        self.assertIn("echo camty-c2-e2e", self.beacons[0].executed)

    def test_unauthorized_token_rejected(self):
        from camty.adapters.c2 import C2Error

        with self.assertRaises(C2Error):
            C2SessionsAdapter().run(
                {"c2_url": f"http://127.0.0.1:{self.api_port}", "c2_token": "wrong-token"},
                _ctx(self),
            )

    def test_api_rejects_missing_or_wrong_bearer(self):
        """P2-8：operator API 无 token / 错 token 一律 401（恒时比较的行为不变式）。"""
        import urllib.error
        import urllib.request
        from urllib.request import ProxyHandler, build_opener

        opener = build_opener(ProxyHandler({}))
        for headers in ({}, {"Authorization": "Bearer wrong-token"},
                        {"Authorization": f"Bearer {self.token}x"}):
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.api_port}/health", headers=headers)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                opener.open(req, timeout=5)
            self.assertEqual(ctx.exception.code, 401, f"应 401: {headers}")


def _ctx(test):
    import camty.adapters.c2  # noqa: F401 - 确保 RunContext 无 eng 也能工作

    return RunContext(
        Scope({"cidrs": ["192.168.100.0/24"], "min_interval_seconds": 0}),
        Audit(Path(test.tmp.name) / "audit.jsonl"),
        Path(test.tmp.name),
    )


if __name__ == "__main__":
    unittest.main()
