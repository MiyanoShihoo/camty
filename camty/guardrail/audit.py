"""append-only JSONL 审计 + 哈希链防篡改。

每条记录包含 prev（上一条 hash）与 hash（sha256(本条 canonical JSON)），
任何局部修改/删除/插入都会让 verify() 断链。

在此之上补两层检测，覆盖哈希链天然不可见的攻击面：
- seq 单调序列 + 可选 HMAC（CAMTY_AUDIT_KEY）：检测"篡改全部记录并重算整条链"；
- 锚定 (count, head_hash)：由 Engagement.save_state()/报告生成写入 state.db，
  verify(anchors=...) 比对文件条数与锚定位置 hash，检测"尾部截断"。
旧格式（无 seq/hmac）条目兼容跳过。
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
import threading
import time
from pathlib import Path

_AUDIT_KEY_ENV = "CAMTY_AUDIT_KEY"


def _canonical(entry: dict) -> str:
    return json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _entry_hash(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


def _entry_hmac(key: str, entry: dict) -> str:
    """HMAC-SHA256(key, canonical(含 hash 的完整条目))。"""
    mac = hmac_mod.new(key.encode("utf-8"), _canonical(entry).encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def _audit_key() -> str:
    return os.environ.get(_AUDIT_KEY_ENV, "")


class Audit:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._last_hash = ""
        self._last_seq = 0
        self._count = 0
        try:
            entries = self.entries()
            self._count = len(entries)
            if entries and entries[-1].get("hash"):
                self._last_hash = entries[-1]["hash"]
            for e in entries:
                seq = e.get("seq")
                if isinstance(seq, int) and seq > self._last_seq:
                    self._last_seq = seq
        except (OSError, json.JSONDecodeError):
            pass

    def record(self, adapter: str, args: dict, ok: bool = True, note: str = "") -> None:
        with self._lock:
            entry = {
                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                "adapter": adapter,
                "args": args,
                "ok": ok,
                "note": note,
                "seq": self._last_seq + 1,
                "prev": self._last_hash,
            }
            entry["hash"] = _entry_hash(entry)
            key = _audit_key()
            if key:
                entry["hmac"] = _entry_hmac(key, entry)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._last_hash = entry["hash"]
            self._last_seq = entry["seq"]
            self._count += 1

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def snapshot(self) -> tuple[int, str]:
        """当前 (条数, 链头 hash)，供锚定写入与外部存档。"""
        return self._count, self._last_hash

    def verify(self, anchors: list[dict] | None = None) -> tuple[bool, int | None]:
        """校验哈希链完整性。返回 (ok, 首个断裂行号)。

        anchors: 锚定列表（{"count": n, "head_hash": h}，来自 state.db anchor 表
        或外部存档），用于检测哈希链天然不可见的尾部截断与全量重写。
        """
        key = _audit_key()
        entries = self.entries()
        prev = ""
        expected_seq: int | None = None
        for i, entry in enumerate(entries):
            if "hash" not in entry or "prev" not in entry:
                return False, i
            if entry["prev"] != prev:
                return False, i
            body = {k: v for k, v in entry.items() if k not in ("hash", "hmac")}
            if _entry_hash(body) != entry["hash"]:
                return False, i
            if key:
                if "hmac" not in entry:
                    return False, i
                signed = {k: v for k, v in entry.items() if k != "hmac"}
                if _entry_hmac(key, signed) != entry["hmac"]:
                    return False, i
            seq = entry.get("seq")
            if seq is not None:
                # 含 seq 的条目必须严格 +1 连续；旧格式条目无 seq，兼容跳过
                if not isinstance(seq, int) or (expected_seq is not None and seq != expected_seq):
                    return False, i
                expected_seq = seq + 1
            prev = entry["hash"]
        for anchor in anchors or []:
            cnt = anchor.get("count")
            head = str(anchor.get("head_hash") or "")
            if not isinstance(cnt, int) or cnt < 0 or cnt > len(entries):
                return False, len(entries)
            if cnt > 0 and entries[cnt - 1].get("hash") != head:
                return False, cnt - 1
        return True, None
