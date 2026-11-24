"""P2-8 vault 明文兜底收紧：cryptography 缺失时默认拒绝写入，opt-in 才允许明文。

本机未安装 cryptography，全部用例用 mock 强制 _fernet_cls 返回 None，
因此无论环境是否装了 cryptography 行为断言都成立。
"""

from __future__ import annotations

import unittest
from unittest import mock

from camty.llm import vault
from camty.llm.vault import decrypt_text, encrypt_text, plaintext_fallback_allowed

NO_CRYPTO = {"_fernet_cls.return_value": None}


class TestPlaintextFallbackGate(unittest.TestCase):
    def test_fallback_requires_explicit_one(self):
        """只有 CAMTY_ALLOW_PLAINTEXT_KEYS 恰为 "1" 才放行。"""
        for value in ("", "0", "true", "yes", " 1", "1 "):
            with mock.patch.dict("os.environ", {vault.PLAINTEXT_ENV: value}, clear=False):
                self.assertFalse(plaintext_fallback_allowed(), f"env={value!r} 不应放行")
        with mock.patch.dict("os.environ", {vault.PLAINTEXT_ENV: "1"}, clear=False):
            self.assertTrue(plaintext_fallback_allowed())

    def test_encrypt_refuses_without_cryptography(self):
        """cryptography 缺失且未 opt-in：默认拒绝写入新密钥（RuntimeError 提示安装）。"""
        env = {k: v for k, v in __import__("os").environ.items()
               if k != vault.PLAINTEXT_ENV}
        with mock.patch.object(vault, "_fernet_cls", return_value=None), \
                mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                encrypt_text('{"deepseek": {"api_key": "sk-123"}}', "master")
        self.assertIn("pip install cryptography", str(ctx.exception))
        self.assertIn(vault.PLAINTEXT_ENV, str(ctx.exception))

    def test_encrypt_plaintext_fallback_optin(self):
        """opt-in 后允许明文兜底：返回 encrypted=False 标记 blob 并发 warning。"""
        payload = '{"deepseek": {"api_key": "sk-123"}}'
        with mock.patch.object(vault, "_fernet_cls", return_value=None), \
                mock.patch.dict("os.environ", {vault.PLAINTEXT_ENV: "1"}, clear=False):
            with self.assertWarns(UserWarning):
                blob = encrypt_text(payload, "master")
        self.assertIs(blob["encrypted"], False)
        self.assertIn("明文", blob["warning"])
        self.assertEqual(blob["payload"], payload)

    def test_plaintext_blob_roundtrip(self):
        """明文兜底 blob 可读回（写入已获同意，读取不设二次门禁），无需 cryptography。"""
        blob = {"encrypted": False, "warning": "x", "payload": "secret-text"}
        with mock.patch.object(vault, "_fernet_cls", return_value=None):
            self.assertEqual(decrypt_text(blob, "master"), "secret-text")

    def test_decrypt_encrypted_blob_refuses_without_cryptography(self):
        """已加密 blob 在无 cryptography 时仍拒绝（不因 opt-in 放宽）。"""
        blob = {"encrypted": True, "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "payload": "tok"}
        with mock.patch.object(vault, "_fernet_cls", return_value=None), \
                mock.patch.dict("os.environ", {vault.PLAINTEXT_ENV: "1"}, clear=False):
            with self.assertRaises(RuntimeError):
                decrypt_text(blob, "master")

    def test_real_crypto_unchanged(self):
        """有 cryptography 时正常加密路径不受影响（环境装了才跑，本机跳过）。"""
        if not vault.HAS_CRYPTO:
            self.skipTest("cryptography 未安装")
        blob = encrypt_text("secret", "master-pass")
        self.assertTrue(blob["encrypted"])
        self.assertEqual(decrypt_text(blob, "master-pass"), "secret")


if __name__ == "__main__":
    unittest.main()
