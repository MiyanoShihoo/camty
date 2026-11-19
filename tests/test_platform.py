"""平台层测试：playbook 命中、报告引擎、vault 加密、LLM 消息格式转换。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from camty.knowledge.playbooks import PlaybookLibrary
from camty.llm.router import LLMRouter
from camty.llm.vault import HAS_CRYPTO, decrypt_text, encrypt_text

PACK = {
    "name": "test-pack",
    "title": "测试包",
    "phases": [{"id": "p1", "title": "t", "steps": [{"adapter": "subfinder", "args": {"domain": "{root_domain}"}}]}],
}
CFG = {
    "name": "plat-eng",
    "pack": "test-pack",
    "root_domain": "example.com",
    "scope": {"domains": ["example.com"], "min_interval_seconds": 0},
}


def make_engagement(tmp: str) -> Path:
    root = Path(tmp)
    (root / "packs" / "test-pack").mkdir(parents=True, exist_ok=True)
    (root / "packs" / "test-pack" / "pack.yaml").write_text(yaml.safe_dump(PACK), encoding="utf-8")
    (root / "engagements").mkdir(exist_ok=True)
    cfg = root / "engagements" / "plat-eng.yaml"
    cfg.write_text(yaml.safe_dump(CFG), encoding="utf-8")
    return cfg


class TestPlaybooks(unittest.TestCase):
    def test_match_tech(self):
        with tempfile.TemporaryDirectory() as tmp:
            pb = Path(tmp) / "pb.yaml"
            pb.write_text(
                "name: wp\ntitle: 测试手册\nmatch:\n  tech:\n    - WordPress\nactions:\n  - 检查 wp-login.php\n",
                encoding="utf-8",
            )
            lib = PlaybookLibrary(root=tmp)
            self.assertEqual(len(lib.match_tech({"http://x": ["WordPress", "PHP"]})), 1)
            self.assertEqual(lib.match_tech({"http://x": ["Nginx"]}), [])
            prompt = PlaybookLibrary.as_prompt(lib.items[0])
            self.assertIn("[战术手册命中] wp", prompt)
            self.assertIn("wp-login.php", prompt)


class TestReport(unittest.TestCase):
    def test_write_and_compare(self):
        from camty.agent.state import Engagement
        from camty.report import compare, write_report

        tmp_a = tempfile.TemporaryDirectory()
        tmp_b = tempfile.TemporaryDirectory()
        eng_a = eng_b = None
        try:
            eng_a = Engagement(make_engagement(tmp_a.name))
            eng_a.ledger.add("vuln", "https://x.com", "finding-old", severity="high", verified=True)
            eng_b = Engagement(make_engagement(tmp_b.name))
            eng_b.ledger.add("vuln", "https://x.com", "finding-old", severity="high", verified=True)
            eng_b.ledger.add("vuln", "https://y.com", "finding-new", severity="critical", verified=True)
            path = write_report(eng_b)
            self.assertTrue(Path(path).exists())
            content = Path(path).read_text(encoding="utf-8")
            self.assertIn("finding-new", content)
            self.assertIn("交战报告", content)
            diff = compare(eng_a, eng_b)
            self.assertEqual(len(diff["new"]), 1)
            self.assertEqual(diff["new"][0]["detail"], "finding-new")
            self.assertEqual(len(diff["fixed"]), 0)
            self.assertEqual(len(diff["common"]), 1)
        finally:
            for eng in (eng_a, eng_b):
                if eng is not None:
                    eng.close()
            tmp_a.cleanup()
            tmp_b.cleanup()


@unittest.skipUnless(HAS_CRYPTO, "cryptography 未安装")
class TestVault(unittest.TestCase):
    def test_roundtrip(self):
        blob = encrypt_text('{"deepseek": {"api_key": "sk-123"}}', "master-pass")
        self.assertTrue(blob["encrypted"])
        self.assertEqual(decrypt_text(blob, "master-pass"), '{"deepseek": {"api_key": "sk-123"}}')

    def test_wrong_master(self):
        from cryptography.fernet import InvalidToken

        blob = encrypt_text("secret", "right")
        with self.assertRaises(InvalidToken):
            decrypt_text(blob, "wrong")

    def test_router_encrypted_vault(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "keys.json"
            with mock.patch.dict("os.environ", {"CAMTY_MASTER_KEY": "mp"}):
                router = LLMRouter(vault_path=vault)
                router.set_provider("deepseek", "openai", "https://api.deepseek.com/v1", "sk-x",
                                   {"decide": "deepseek-chat"})
                self.assertTrue(vault.read_text(encoding="utf-8").startswith("{\n  \"encrypted\""))
                reloaded = LLMRouter(vault_path=vault)
                cfg, model = reloaded.resolve("decide")
                self.assertEqual(cfg.name, "deepseek")
                self.assertEqual(model, "deepseek-chat")

    def test_no_downgrade_to_plaintext(self):
        from camty.llm.router import LLMError

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "keys.json"
            with mock.patch.dict("os.environ", {"CAMTY_MASTER_KEY": "mp"}):
                LLMRouter(vault_path=vault).set_provider("d", "openai", "http://x/v1", "k", {})
                router = LLMRouter(vault_path=vault)
            env = {k: v for k, v in __import__("os").environ.items() if k != "CAMTY_MASTER_KEY"}
            with mock.patch.dict("os.environ", env, clear=True):
                with self.assertRaises(LLMError):
                    router.save()


class TestRouterMessageFormat(unittest.TestCase):
    def test_openai_conversion(self):
        msg = LLMRouter._to_openai_msg(
            {"role": "assistant", "content": "hi", "tool_calls": [{"id": "1", "name": "t", "arguments": {"a": 1}}]}
        )
        self.assertEqual(msg["role"], "assistant")
        self.assertEqual(msg["tool_calls"][0]["function"]["name"], "t")
        self.assertEqual(msg["tool_calls"][0]["id"], "1")
        tool_msg = LLMRouter._to_openai_msg({"role": "tool", "tool_call_id": "1", "content": "out"})
        self.assertEqual(tool_msg["role"], "tool")
        self.assertEqual(tool_msg["tool_call_id"], "1")

    def test_anthropic_conversion(self):
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "tu1", "name": "t", "arguments": {"a": 1}}]},
            {"role": "tool", "tool_call_id": "tu1", "content": "result1"},
            {"role": "tool", "tool_call_id": "tu1", "content": "result2"},
        ]
        out = LLMRouter._to_anthropic_msgs(messages)
        self.assertEqual(out[0], {"role": "user", "content": "go"})
        self.assertEqual(out[1]["role"], "assistant")
        self.assertEqual(out[1]["content"][-1]["type"], "tool_use")
        # 连续 tool 结果应合并进同一条 user 消息（Anthropic 要求紧跟 tool_use）
        self.assertEqual(out[2]["role"], "user")
        self.assertEqual(len(out[2]["content"]), 2)
        self.assertEqual(out[2]["content"][0]["type"], "tool_result")




class FakeHTTPResponse:
    def __init__(self, body: dict):
        self._data = json.dumps(body).encode("utf-8")

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestResponsesProtocol(unittest.TestCase):
    def test_input_conversion(self):
        items = LLMRouter._to_responses_input(
            [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "go"},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"id": "fc_1", "name": "subfinder", "arguments": {"domain": "x.com"}}
                ]},
                {"role": "tool", "tool_call_id": "fc_1", "content": "out"},
            ]
        )
        self.assertEqual(items[0], {"role": "system", "content": "sys"})
        self.assertEqual(items[2], {"type": "function_call", "call_id": "fc_1", "name": "subfinder",
                                    "arguments": '{"domain": "x.com"}'})
        self.assertEqual(items[3], {"type": "function_call_output", "call_id": "fc_1", "output": "out"})

    def test_parse_output(self):
        body = {
            "output": [
                {"type": "message", "role": "assistant",
                 "content": [{"type": "output_text", "text": "hi"}]},
                {"type": "function_call", "call_id": "fc_9", "name": "nuclei",
                 "arguments": '{"hosts": ["https://a.com"]}'},
            ]
        }
        out = LLMRouter._parse_responses_output(body)
        self.assertEqual(out["content"], "hi")
        self.assertEqual(out["tool_calls"][0]["id"], "fc_9")
        self.assertEqual(out["tool_calls"][0]["arguments"], {"hosts": ["https://a.com"]})

    def test_chat_responses_mocked(self):
        from camty.llm.router import ProviderConfig

        body = {"output": [
            {"type": "function_call", "call_id": "fc_1", "name": "subfinder",
             "arguments": '{"domain": "example.com"}'},
        ]}
        with tempfile.TemporaryDirectory() as tmp:
            router = LLMRouter(vault_path=Path(tmp) / "none.json")
            router.providers["oai"] = ProviderConfig(
                "oai", "responses", "https://api.openai.com/v1", "sk-x", {"decide": "gpt-4.1"}
            )
            with mock.patch("urllib.request.urlopen", return_value=FakeHTTPResponse(body)):
                out = router.chat("decide", [{"role": "user", "content": "go"}])
        self.assertEqual(out["tool_calls"][0]["name"], "subfinder")
        self.assertEqual(out["tool_calls"][0]["arguments"], {"domain": "example.com"})


class TestBanner(unittest.TestCase):
    def test_show_contains_status(self):
        import contextlib
        import io

        from camty import banner as banner_mod

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            banner_mod.show(False)
        text = buf.getvalue()
        self.assertIn("Camty", text)
        self.assertIn("[工具]", text)
        self.assertIn("[模型]", text)

    def test_suppress(self):
        import contextlib
        import io

        from camty import banner as banner_mod

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            banner_mod.show(True)
        self.assertEqual(buf.getvalue(), "")




class TestAuditChain(unittest.TestCase):
    def test_chain_tamper_and_removal(self):
        from camty.guardrail.audit import Audit

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            audit = Audit(path)
            audit.record("t1", {"x": 1})
            audit.record("t2", {"x": 2}, ok=False, note="n")
            ok, bad = audit.verify()
            self.assertTrue(ok)
            self.assertEqual(len(audit.entries()), 2)

            audit2 = Audit(path)  # 新实例接力续链
            audit2.record("t3", {})
            ok, bad = Audit(path).verify()
            self.assertTrue(ok)
            self.assertEqual(len(audit2.entries()), 3)

            # 篡改中间行 → 断链
            lines = path.read_text(encoding="utf-8").splitlines()
            tampered = json.loads(lines[1])
            tampered["note"] = "hacked"
            lines[1] = json.dumps(tampered, ensure_ascii=False)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            ok, bad = Audit(path).verify()
            self.assertFalse(ok)
            self.assertEqual(bad, 1)

            # 删除行 → 断链
            lines = path.read_text(encoding="utf-8").splitlines()
            del lines[0]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            ok, bad = Audit(path).verify()
            self.assertFalse(ok)
            self.assertEqual(bad, 0)


class TestDocxReport(unittest.TestCase):
    def test_write_docx(self):
        import importlib.util

        if importlib.util.find_spec("docx") is None:
            self.skipTest("python-docx 未安装")
        from docx import Document

        from camty.agent.state import Engagement
        from camty.report import write_docx

        tmp = tempfile.TemporaryDirectory()
        eng = None
        try:
            eng = Engagement(make_engagement(tmp.name))
            eng.ledger.add("vuln", "https://x.com", "docx-finding", severity="high", verified=True)
            path = write_docx(eng)
            self.assertTrue(str(path).endswith(".docx"))
            doc = Document(str(path))
            self.assertTrue(any("交战报告" in p.text for p in doc.paragraphs))
            tables = doc.tables
            self.assertEqual(len(tables[0].rows), 2, "表头 + 1 条发现")
            self.assertEqual(tables[0].rows[1].cells[4].text, "docx-finding")
        finally:
            if eng is not None:
                eng.close()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
