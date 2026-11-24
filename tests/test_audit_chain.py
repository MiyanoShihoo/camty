"""审计哈希链硬化回归：尾部截断、全量重算篡改、旧格式兼容、锚定与 CLI 存档输出。

攻击者模型：
- 尾部截断：删掉末尾若干条，链本身仍然连贯，哈希链校验天然不可见 → 用锚点 (count, head_hash) 检测；
- 全量重算篡改：改写所有条目并重算 prev/hash，链仍然连贯 → 用 seq 连续性 + 可选 HMAC（CAMTY_AUDIT_KEY）检测；
- 旧格式：无 seq/hmac 的历史文件必须继续通过校验（兼容跳过）。
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from camty.guardrail.audit import Audit, _entry_hash
from camty.storage import StateDB

PACK = {
    "name": "test-pack",
    "title": "测试包",
    "phases": [{"id": "p1", "title": "t", "steps": []}],
}
CFG = {
    "name": "audit-eng",
    "pack": "test-pack",
    "root_domain": "example.com",
    "scope": {"domains": ["example.com"], "min_interval_seconds": 0},
}


def no_key():
    """临时移除 CAMTY_AUDIT_KEY，保证无 key 分支不受外部环境污染。"""
    env = {k: v for k, v in os.environ.items() if k != "CAMTY_AUDIT_KEY"}
    return mock.patch.dict(os.environ, env, clear=True)


def with_key(value: str = "unit-audit-key"):
    return mock.patch.dict(os.environ, {"CAMTY_AUDIT_KEY": value})


def recompute_chain(path: Path, mutate=None, keep_hmac: bool = False) -> None:
    """攻击者工具：篡改全部条目并重算整条哈希链（伪造 prev/hash 连贯）。"""
    entries = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    prev = ""
    lines = []
    for e in entries:
        old_hmac = e.get("hmac")
        body = {k: v for k, v in e.items() if k not in ("hash", "hmac")}
        if mutate is not None:
            body = mutate(body)
        body["prev"] = prev
        forged = dict(body)
        forged["hash"] = _entry_hash(body)
        if keep_hmac and old_hmac is not None:
            forged["hmac"] = old_hmac
        prev = forged["hash"]
        lines.append(json.dumps(forged, ensure_ascii=False))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def truncate_tail(path: Path, n: int = 1) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-n]) + "\n", encoding="utf-8")


def old_format_file(path: Path, count: int = 2) -> None:
    """构造修复前格式的历史审计文件（无 seq / hmac）。"""
    prev = ""
    lines = []
    for i in range(count):
        body = {
            "ts": f"2024-01-0{i + 1} 00:00:00",
            "adapter": f"t{i}",
            "args": {"i": i},
            "ok": True,
            "note": "",
            "prev": prev,
        }
        body["hash"] = _entry_hash(body)
        prev = body["hash"]
        lines.append(json.dumps(body, ensure_ascii=False))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestTailTruncationAnchor(unittest.TestCase):
    def test_tail_truncation_detected_with_anchor(self):
        with no_key():
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "a.jsonl"
                audit = Audit(path)
                for i in range(3):
                    audit.record(f"t{i}", {"i": i})
                count, head = audit.snapshot()

                ok, _ = audit.verify(anchors=[{"count": count, "head_hash": head}])
                self.assertTrue(ok)

                truncate_tail(path)  # 删除末尾条目：纯哈希链校验不可见
                ok, _ = Audit(path).verify()  # 无锚点时保持现状（不回归既有语义）
                self.assertTrue(ok)
                ok, bad = Audit(path).verify(anchors=[{"count": count, "head_hash": head}])
                self.assertFalse(ok)
                self.assertEqual(bad, 2)  # 指向锚定 count 位置：文件只剩 2 条

    def test_anchor_head_mismatch_detected(self):
        with no_key():
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "a.jsonl"
                audit = Audit(path)
                audit.record("t0", {})
                audit.record("t1", {})
                head = audit.entries()[-1]["hash"]
                # 全量重算（无 key）：count 对得上但锚定位置 hash 变了
                recompute_chain(path, mutate=lambda e: {**e, "note": "hacked"})
                ok, bad = Audit(path).verify(
                    anchors=[{"count": 2, "head_hash": head}]
                )
                self.assertFalse(ok)
                self.assertEqual(bad, 1)


class TestSeqContinuity(unittest.TestCase):
    def test_seq_detects_middle_deletion_with_recompute(self):
        with no_key():
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "a.jsonl"
                audit = Audit(path)
                for i in range(3):
                    audit.record(f"t{i}", {"i": i})
                lines = path.read_text(encoding="utf-8").splitlines()
                del lines[1]  # 删中间行
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                recompute_chain(path)  # 重算后链连贯：旧校验看不到
                ok, bad = Audit(path).verify()
                self.assertFalse(ok)  # seq 1,3 出现断层
                self.assertEqual(bad, 1)

    def test_seq_monotonic_across_instances(self):
        with no_key():
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "a.jsonl"
                Audit(path).record("t0", {})
                audit2 = Audit(path)  # 新实例接力
                audit2.record("t1", {})
                audit2.record("t2", {})
                entries = audit2.entries()
                self.assertEqual([e["seq"] for e in entries], [1, 2, 3])
                ok, _ = audit2.verify()
                self.assertTrue(ok)

    def test_old_format_file_still_verifies(self):
        with no_key():
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "old.jsonl"
                old_format_file(path, count=3)
                audit = Audit(path)
                ok, bad = audit.verify()
                self.assertTrue(ok)  # 旧条目无 seq：兼容跳过

                audit.record("new", {})  # 续链：旧前缀 + 新 seq 从 1 起
                entries = audit.entries()
                self.assertNotIn("seq", entries[0])
                self.assertEqual(entries[-1]["seq"], 1)
                ok, _ = audit.verify()
                self.assertTrue(ok)


class TestHmacKey(unittest.TestCase):
    def test_full_rewrite_recompute_detected_with_key(self):
        with with_key():
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "a.jsonl"
                audit = Audit(path)
                audit.record("t0", {"x": 1}, note="orig-0")
                audit.record("t1", {"x": 2}, note="orig-1")
                self.assertTrue(audit.verify()[0])

                # 攻击者重算链但拿不到 key：条目缺 hmac
                recompute_chain(path, mutate=lambda e: {**e, "note": "hacked"})
                ok, bad = Audit(path).verify()
                self.assertFalse(ok)

                # 攻击者把旧 hmac 原样抄回：内容已变，HMAC 校验失败
                recompute_chain(path, mutate=lambda e: {**e, "note": "hacked"}, keep_hmac=True)
                ok, _ = Audit(path).verify()
                self.assertFalse(ok)

    def test_hmac_entry_recorded_when_key_set(self):
        with with_key():
            with tempfile.TemporaryDirectory() as tmp:
                audit = Audit(Path(tmp) / "a.jsonl")
                audit.record("t0", {})
                entry = audit.entries()[0]
                self.assertIn("hmac", entry)
                self.assertTrue(audit.verify()[0])

    def test_hmac_entry_verifies_without_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            with with_key():
                Audit(path).record("t0", {})
            with no_key():
                ok, _ = Audit(path).verify()  # 无 key 时行为 = 现状 + seq（hmac 忽略）
                self.assertTrue(ok)

    def test_missing_hmac_fails_when_key_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            with no_key():
                Audit(path).record("t0", {})
            with with_key():
                ok, _ = Audit(path).verify()  # 有 key 时应有 hmac 而缺失 → fail
                self.assertFalse(ok)

    def test_wrong_key_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            with with_key("key-one"):
                Audit(path).record("t0", {})
            with with_key("key-two"):
                ok, _ = Audit(path).verify()
                self.assertFalse(ok)


class TestStateAnchorTable(unittest.TestCase):
    def test_anchor_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            try:
                self.assertEqual(db.load_audit_anchors(), [])
                db.add_audit_anchor(2, "deadbeef")
                db.add_audit_anchor(3, "cafe")
                anchors = db.load_audit_anchors()
                self.assertEqual([a["count"] for a in anchors], [2, 3])
                self.assertEqual([a["head_hash"] for a in anchors], ["deadbeef", "cafe"])
            finally:
                db.close()

    def test_reopen_legacy_db_gets_anchor_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            db = StateDB(path)
            db.close()
            db2 = StateDB(path)  # 旧库重开：锚定表自动补建
            try:
                db2.add_audit_anchor(0, "")
                self.assertEqual(db2.load_audit_anchors()[0]["count"], 0)
            finally:
                db2.close()


class EngagementFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "packs" / "test-pack").mkdir(parents=True)
        (root / "packs" / "test-pack" / "pack.yaml").write_text(
            yaml.safe_dump(PACK), encoding="utf-8")
        (root / "engagements").mkdir()
        self.cfg_path = root / "engagements" / "audit-eng.yaml"
        self.cfg_path.write_text(yaml.safe_dump(CFG), encoding="utf-8")
        from camty.agent.state import Engagement

        self.eng = Engagement(self.cfg_path)

    def tearDown(self) -> None:
        self.eng.close()
        self.tmp.cleanup()

    def test_save_state_anchors_and_detects_truncation(self):
        with no_key():
            eng = self.eng
            eng.audit.record("a", {"x": 1})
            eng.audit.record("b", {"x": 2})
            eng.save_state()

            anchors = eng.db.load_audit_anchors()
            self.assertEqual(len(anchors), 1)
            self.assertEqual(anchors[0]["count"], 2)
            self.assertEqual(anchors[0]["head_hash"], eng.audit.entries()[-1]["hash"])

            ok, _ = eng.audit.verify(anchors=anchors)
            self.assertTrue(ok)

            truncate_tail(eng.audit.path)  # 删尾 → 锚定比对失败
            ok, bad = eng.audit.verify(anchors=eng.db.load_audit_anchors())
            self.assertFalse(ok)
            self.assertEqual(bad, 1)

    def test_report_generation_anchors(self):
        from camty.report import write_report

        with no_key():
            eng = self.eng
            eng.audit.record("a", {"x": 1})
            before = len(eng.db.load_audit_anchors())
            path = write_report(eng)
            self.assertTrue(Path(path).exists())
            anchors = eng.db.load_audit_anchors()
            self.assertEqual(len(anchors), before + 1)
            self.assertEqual(anchors[-1]["count"], 1)
            self.assertEqual(anchors[-1]["head_hash"], eng.audit.entries()[-1]["hash"])

    def test_cmd_audit_prints_anchor_for_archival(self):
        from camty.cli import cmd_audit

        with no_key():
            eng = self.eng
            eng.audit.record("a", {"x": 1})
            eng.audit.record("b", {"x": 2})
            head = eng.audit.entries()[-1]["hash"]

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cmd_audit(argparse.Namespace(engagement=str(self.cfg_path)))
            out = buf.getvalue()
            self.assertIn("审计链完整", out)
            self.assertIn("head_hash", out)  # 供外部存档的 (count, head_hash)
            self.assertIn(head, out)
            self.assertIn("(2, ", out)

    def test_cmd_audit_exit_code_on_truncation(self):
        from camty.cli import cmd_audit

        with no_key():
            eng = self.eng
            eng.audit.record("a", {"x": 1})
            eng.save_state()
            truncate_tail(eng.audit.path)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as cm:
                    cmd_audit(argparse.Namespace(engagement=str(self.cfg_path)))
            self.assertEqual(cm.exception.code, 1)
            self.assertIn("断裂", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
