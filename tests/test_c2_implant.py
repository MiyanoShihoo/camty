"""真实植入体 E2E：beacon.exe（C 编译产物）↔ 服务端 ↔ camty 适配器。

前置：c2/implant/beacon.exe 已用测试 PSK（00112233…ddeeff）构建，
运行时用环境变量 C2_HOST/C2_PORT 指向测试服务端。
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

from camty.adapters.base import RunContext
from camty.adapters.c2 import C2CollectAdapter, C2SessionsAdapter, C2TaskAdapter
from camty.guardrail.audit import Audit
from camty.guardrail.scope import Scope

IMPLANT = Path(__file__).resolve().parent.parent / "c2" / "implant" / "beacon.exe"
C2_DIR = Path(__file__).resolve().parent.parent / "c2" / "server"
TEST_PSK = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(IMPLANT.exists(), "beacon.exe 未构建（c2/implant/build.ps1）")
class TestRealImplantE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile

        cls.tmp = tempfile.TemporaryDirectory()
        cls.beacon_port = _free_port()
        cls.api_port = _free_port()
        cls.token = "implant-e2e-token"
        cls.server = subprocess.Popen(
            [
                sys.executable, str(C2_DIR / "camty_c2.py"),
                "--beacon-port", str(cls.beacon_port),
                "--api-port", str(cls.api_port),
                "--token", cls.token,
                "--psk", TEST_PSK,
                "--ops-log", str(Path(cls.tmp.name) / "ops.jsonl"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls._wait_health()
        env = {
            **os.environ,
            "C2_HOST": "127.0.0.1",
            "C2_PORT": str(cls.beacon_port),
            "C2_SLEEP": "1",
        }
        cls.implant = subprocess.Popen([str(IMPLANT)], env=env,
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)

    @classmethod
    def _wait_health(cls, timeout=15.0):
        import urllib.request
        from urllib.request import ProxyHandler, build_opener

        deadline = time.time() + timeout
        opener = build_opener(ProxyHandler({}))
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
        raise RuntimeError("服务端未就绪")

    @classmethod
    def tearDownClass(cls):
        cls.implant.kill()
        try:
            cls.implant.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        cls.server.terminate()
        try:
            cls.server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.server.kill()
        cls.tmp.cleanup()

    def test_implant_registers_executes_reports(self):
        import socket as _socket

        base = {"c2_url": f"http://127.0.0.1:{self.api_port}", "c2_token": self.token}
        # 植入体上报的 host 是真实主机名，scope 需把它与 127.0.0.1 一并纳入
        ctx = RunContext(
            Scope({"ips": ["127.0.0.1"], "domains": [_socket.gethostname().lower()],
                   "min_interval_seconds": 0}),
            Audit(Path(self.tmp.name) / "audit.jsonl"),
            Path(self.tmp.name),
        )

        sessions = []
        deadline = time.time() + 20
        while time.time() < deadline:
            result = C2SessionsAdapter().run(dict(base), ctx)
            sessions = result.data["sessions"]
            if sessions:
                break
            time.sleep(0.5)
        self.assertTrue(sessions, "真实植入体应完成注册")

        sid = sessions[0]["id"]
        task = C2TaskAdapter().run(
            {**base, "session_id": sid, "command": "echo real-implant-e2e",
             "finding_id": "F-001"}, ctx,
        )
        task_id = task.data["task_id"]

        deadline = time.time() + 25
        output = None
        while time.time() < deadline:
            collect = C2CollectAdapter().run({**base, "task_id": task_id}, ctx)
            if collect.data["status"] == "done":
                output = collect.data["output"]
                break
            time.sleep(0.5)
        self.assertIsNotNone(output, "任务应在超时内完成")
        self.assertIn("real-implant-e2e", output)

    def test_implant_bad_psk_rejected(self):
        """PSK 不匹配的 beacon 应被拒（403）——坏密钥注册不上。"""
        import urllib.request
        import sys as _sys
        from urllib.request import ProxyHandler, build_opener

        _sys.path.insert(0, str(C2_DIR))
        import protocol

        psk = bytes.fromhex(TEST_PSK)
        body = protocol.seal(bytes(32), b'{"id":"rogue","host":"127.0.0.1","user":"x","arch":"x64","sleep":1}')
        opener = build_opener(ProxyHandler({}))
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.beacon_port}/beacon", data=body,
            headers={"Content-Type": "application/octet-stream"},
        )
        try:
            with opener.open(req, timeout=5) as resp:
                code = resp.status
        except urllib.error.HTTPError as exc:
            code = exc.code
        self.assertEqual(code, 403)


if __name__ == "__main__":
    unittest.main()
