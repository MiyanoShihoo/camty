"""append-only JSONL 审计 + 哈希链防篡改。

每条记录包含 prev（上一条 hash）与 hash（sha256(本条 canonical JSON)），
任何修改/删除/插入都会让 verify() 断链。
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path


def _canonical(entry: dict) -> str:
    return json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _entry_hash(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


class Audit:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._last_hash = ""
        try:
            entries = self.entries()
            if entries and entries[-1].get("hash"):
                self._last_hash = entries[-1]["hash"]
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
                "prev": self._last_hash,
            }
            entry["hash"] = _entry_hash(entry)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._last_hash = entry["hash"]

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def verify(self) -> tuple[bool, int | None]:
        """校验哈希链完整性。返回 (ok, 首个断裂行号)。"""
        prev = ""
        for i, entry in enumerate(self.entries()):
            if "hash" not in entry or "prev" not in entry:
                return False, i
            if entry["prev"] != prev:
                return False, i
            body = {k: v for k, v in entry.items() if k != "hash"}
            if _entry_hash(body) != entry["hash"]:
                return False, i
            prev = entry["hash"]
        return True, None
