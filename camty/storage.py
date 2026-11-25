"""SQLite 状态与断点存储。"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS context (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    evidence TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    created_ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
    dedup_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    parent_key TEXT,
    source TEXT,
    first_seen TEXT NOT NULL,
    tested INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS exploration (
    node_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    payload TEXT,
    created_ts TEXT NOT NULL,
    updated_ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exploration_edges (
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    relation TEXT NOT NULL,
    PRIMARY KEY (src, dst, relation)
);
CREATE TABLE IF NOT EXISTS exploration_anchors (
    node_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    PRIMARY KEY (node_id, asset_key)
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT,
    step INTEGER NOT NULL,
    tool TEXT NOT NULL,
    args_digest TEXT,
    result_digest TEXT,
    evidence TEXT,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS todolist (
    item_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    depends_on TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    intent_id TEXT,
    note TEXT
);
CREATE TABLE IF NOT EXISTS phase_progress (
    phase_id TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (phase_id, step_index)
);
CREATE TABLE IF NOT EXISTS finding_retests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence TEXT,
    created_ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blackboard (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    note TEXT NOT NULL,
    source TEXT,
    created_ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_anchor (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_count INTEGER NOT NULL,
    head_hash TEXT NOT NULL DEFAULT '',
    created_ts TEXT NOT NULL
);
"""


def _migrate(conn: sqlite3.Connection) -> None:
    """幂等迁移：老库补 derived_from / disposal 列（既有行为不破坏）。"""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}
    if "derived_from" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN derived_from TEXT")
    if "disposal" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN disposal TEXT NOT NULL DEFAULT 'open'")
    conn.commit()


class StateDB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.executescript(_SCHEMA)
        _migrate(self.conn)
        self.conn.commit()

    def update_context(self, data: dict) -> None:
        with self._lock:
            self.conn.executemany(
                "INSERT INTO context (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [(k, json.dumps(v, ensure_ascii=False)) for k, v in data.items()],
            )
            self.conn.commit()

    def load_context(self) -> dict:
        with self._lock:
            rows = self.conn.execute("SELECT key, value FROM context").fetchall()
        return {k: json.loads(v) for k, v in rows}

    def sync_findings(self, findings: list[dict]) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM findings")
            self.conn.executemany(
                "INSERT OR REPLACE INTO findings "
                "(id, kind, target, detail, severity, evidence, verified, created_ts, derived_from, disposal) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        f["id"], f["kind"], f["target"], f["detail"],
                        f.get("severity", "info"), f.get("evidence"),
                        1 if f.get("verified") else 0, f.get("created_ts") or time.strftime("%Y-%m-%d %H:%M:%S"),
                        json.dumps(f.get("derived_from") or [], ensure_ascii=False),
                        f.get("disposal", "open") or "open",
                    )
                    for f in findings
                ],
            )
            self.conn.commit()

    def load_findings(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, kind, target, detail, severity, evidence, verified, created_ts, derived_from, disposal "
                "FROM findings ORDER BY id"
            ).fetchall()
        return [
            {
                "id": r[0], "kind": r[1], "target": r[2], "detail": r[3],
                "severity": r[4], "evidence": r[5], "verified": bool(r[6]), "created_ts": r[7],
                "derived_from": json.loads(r[8] or "[]"), "disposal": r[9] or "open",
            }
            for r in rows
        ]

    def add_retest(self, finding_id: str, verdict: str, summary: str,
                    evidence: str | None) -> int:
        """登记一次复测结论（一 finding 多轮历史）。"""
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO finding_retests (finding_id, verdict, summary, evidence, created_ts) "
                "VALUES (?, ?, ?, ?, ?)",
                (finding_id, verdict, summary, evidence,
                 time.strftime("%Y-%m-%d %H:%M:%S")),
            )
            self.conn.commit()
            return cur.lastrowid

    def load_retests(self, finding_id: str | None = None) -> list[dict]:
        with self._lock:
            if finding_id is None:
                rows = self.conn.execute(
                    "SELECT id, finding_id, verdict, summary, evidence, created_ts "
                    "FROM finding_retests ORDER BY id").fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT id, finding_id, verdict, summary, evidence, created_ts "
                    "FROM finding_retests WHERE finding_id = ? ORDER BY id",
                    (finding_id,)).fetchall()
        return [
            {"id": r[0], "finding_id": r[1], "verdict": r[2], "summary": r[3],
             "evidence": r[4], "created_ts": r[5]}
            for r in rows
        ]

    def upsert_asset(self, kind: str, value: str, parent_key: str | None,
                     source: str) -> str:
        """资产入图（dedup_key 唯一）；冲突时保留首见，仅补 source 与 tested 标记。"""
        dedup = f"{kind}|{value}"
        with self._lock:
            self.conn.execute(
                "INSERT INTO assets (dedup_key, kind, value, parent_key, source, first_seen, tested) "
                "VALUES (?, ?, ?, ?, ?, ?, 0) "
                "ON CONFLICT(dedup_key) DO UPDATE SET source = excluded.source",
                (dedup, kind, value, parent_key, source, time.strftime("%Y-%m-%d %H:%M:%S")),
            )
            self.conn.commit()
        return dedup

    def mark_asset_tested(self, value: str) -> None:
        """按值标记已测（匹配 endpoint 精确值或其所属 service 前缀）。"""
        with self._lock:
            self.conn.execute(
                "UPDATE assets SET tested = 1 WHERE value = ?", (value,))
            self.conn.commit()

    def load_assets(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT dedup_key, kind, value, parent_key, source, first_seen, tested "
                "FROM assets ORDER BY kind, value"
            ).fetchall()
        return [
            {"dedup_key": r[0], "kind": r[1], "value": r[2], "parent_key": r[3],
             "source": r[4], "first_seen": r[5], "tested": bool(r[6])}
            for r in rows
        ]

    # ---- 探索图 ----

    def add_exploration_node(self, node_id: str, kind: str, title: str, payload: str | None) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO exploration (node_id, kind, title, status, payload, created_ts, updated_ts) "
                "VALUES (?, ?, ?, 'pending', ?, ?, ?)",
                (node_id, kind, title, payload, ts, ts),
            )
            self.conn.commit()

    def update_exploration_status(self, node_id: str, status: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE exploration SET status = ?, updated_ts = ? WHERE node_id = ?",
                (status, time.strftime("%Y-%m-%d %H:%M:%S"), node_id),
            )
            self.conn.commit()

    def add_edge(self, src: str, dst: str, relation: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO exploration_edges (src, dst, relation) VALUES (?, ?, ?)",
                (src, dst, relation),
            )
            self.conn.commit()

    def anchor(self, node_id: str, asset_key: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO exploration_anchors (node_id, asset_key) VALUES (?, ?)",
                (node_id, asset_key),
            )
            self.conn.commit()

    def load_exploration(self) -> dict:
        with self._lock:
            nodes = self.conn.execute(
                "SELECT node_id, kind, title, status, payload, created_ts, updated_ts FROM exploration"
            ).fetchall()
            edges = self.conn.execute(
                "SELECT src, dst, relation FROM exploration_edges"
            ).fetchall()
            anchors = self.conn.execute(
                "SELECT node_id, asset_key FROM exploration_anchors"
            ).fetchall()
        return {
            "nodes": [
                {"node_id": n[0], "kind": n[1], "title": n[2], "status": n[3],
                 "payload": n[4], "created_ts": n[5], "updated_ts": n[6]}
                for n in nodes
            ],
            "edges": [{"src": e[0], "dst": e[1], "relation": e[2]} for e in edges],
            "anchors": [{"node_id": a[0], "asset_key": a[1]} for a in anchors],
        }

    # ---- 过程跟踪（activity） ----

    def add_activity(self, node_id: str | None, step: int, tool: str,
                     args_digest: str, result_digest: str, evidence: str | None) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO activity (node_id, step, tool, args_digest, result_digest, evidence, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (node_id, step, tool, args_digest, result_digest, evidence,
                 time.strftime("%Y-%m-%d %H:%M:%S")),
            )
            self.conn.commit()

    def search_activity(self, query: str, exclude_node: str | None = None,
                        limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, node_id, step, tool, args_digest, result_digest, evidence, ts "
                "FROM activity WHERE (args_digest LIKE ? OR result_digest LIKE ?) "
                "AND (? IS NULL OR node_id IS NOT ?) ORDER BY id LIMIT ?",
                (f"%{query}%", f"%{query}%", exclude_node, exclude_node, limit),
            ).fetchall()
        return [
            {"id": r[0], "node_id": r[1], "step": r[2], "tool": r[3],
             "args_digest": r[4], "result_digest": r[5], "evidence": r[6], "ts": r[7]}
            for r in rows
        ]

    def load_activity(self, limit: int = 500) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, node_id, step, tool, args_digest, result_digest, evidence, ts "
                "FROM activity ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {"id": r[0], "node_id": r[1], "step": r[2], "tool": r[3],
             "args_digest": r[4], "result_digest": r[5], "evidence": r[6], "ts": r[7]}
            for r in rows
        ]

    # ---- 共享 todolist ----

    def mark_todolist_item(self, item_id: str, status: str, note: str = "") -> None:
        """单条原子更新（并发安全）。

        旧路径是 load→内存改→DELETE 全表+重插（RMW）：两线程并发 mark 不同项时，
        后提交者会以自己读到的旧快照覆盖前者（丢失更新，PoC 强制切换下 270/300 复现）。
        单条 UPDATE 由 sqlite 保证原子，无跨线程覆盖窗口。
        note 语义与旧版一致：仅当显式传入时才覆写。
        blocked 时同时释放 intent_id：blocked intent 不再占用 item 的派发位，
        规划者可重派（历史意图节点保留在探索图，MAX_RESPAWN 防死循环）。
        """
        with self._lock:
            if status == "blocked":
                if note:
                    self.conn.execute(
                        "UPDATE todolist SET status = ?, note = ?, intent_id = NULL WHERE item_id = ?",
                        (status, note, item_id))
                else:
                    self.conn.execute(
                        "UPDATE todolist SET status = ?, intent_id = NULL WHERE item_id = ?",
                        (status, item_id))
            elif note:
                self.conn.execute(
                    "UPDATE todolist SET status = ?, note = ? WHERE item_id = ?",
                    (status, note, item_id))
            else:
                self.conn.execute(
                    "UPDATE todolist SET status = ? WHERE item_id = ?",
                    (status, item_id))
            self.conn.commit()

    def sync_todolist(self, items: list[dict]) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM todolist")
            self.conn.executemany(
                "INSERT OR REPLACE INTO todolist (item_id, title, depends_on, status, intent_id, note) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (i["item_id"], i["title"],
                     json.dumps(i.get("depends_on") or [], ensure_ascii=False),
                     i.get("status", "pending"), i.get("intent_id"), i.get("note", ""))
                    for i in items
                ],
            )
            self.conn.commit()

    def load_todolist(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT item_id, title, depends_on, status, intent_id, note FROM todolist ORDER BY item_id"
            ).fetchall()
        return [
            {"item_id": r[0], "title": r[1], "depends_on": json.loads(r[2] or "[]"),
             "status": r[3], "intent_id": r[4], "note": r[5]}
            for r in rows
        ]

    def mark_step(self, phase_id: str, step_index: int, status: str = "done") -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO phase_progress (phase_id, step_index, status) VALUES (?, ?, ?) "
                "ON CONFLICT(phase_id, step_index) DO UPDATE SET status = excluded.status",
                (phase_id, step_index, status),
            )
            self.conn.commit()

    def completed_steps(self, phase_id: str) -> dict[int, str]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT step_index, status FROM phase_progress WHERE phase_id = ?", (phase_id,)
            ).fetchall()
        return {r[0]: r[1] for r in rows}

    def clear_phase(self, phase_id: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM phase_progress WHERE phase_id = ?", (phase_id,))
            self.conn.commit()

    def add_note(self, kind: str, note: str, source: str | None = None) -> int:
        """黑板：跨唤醒/跨 worker 的持久观察（ARTEX blackboard 语义）。"""
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO blackboard (kind, note, source, created_ts) VALUES (?, ?, ?, ?)",
                (kind, note, source, time.strftime("%Y-%m-%d %H:%M:%S")))
            self.conn.commit()
            return cur.lastrowid

    def load_notes(self, kind: str | None = None, limit: int = 50) -> list[dict]:
        with self._lock:
            if kind is None:
                rows = self.conn.execute(
                    "SELECT id, kind, note, source, created_ts FROM blackboard "
                    "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT id, kind, note, source, created_ts FROM blackboard "
                    "WHERE kind = ? ORDER BY id DESC LIMIT ?", (kind, limit)).fetchall()
        return [
            {"id": r[0], "kind": r[1], "note": r[2], "source": r[3], "created_ts": r[4]}
            for r in rows
        ]

    # ---- 审计锚定 ----

    def add_audit_anchor(self, count: int, head_hash: str) -> None:
        """追加审计锚点 (count, head_hash)：哈希链对尾部截断天然不敏感，
        锚点把"校验时刻的链长与链头"固化下来，供 verify 比对。"""
        with self._lock:
            self.conn.execute(
                "INSERT INTO audit_anchor (entry_count, head_hash, created_ts) VALUES (?, ?, ?)",
                (int(count), str(head_hash), time.strftime("%Y-%m-%d %H:%M:%S")),
            )
            self.conn.commit()

    def load_audit_anchors(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, entry_count, head_hash, created_ts FROM audit_anchor ORDER BY id"
            ).fetchall()
        return [
            {"id": r[0], "count": r[1], "head_hash": r[2], "created_ts": r[3]}
            for r in rows
        ]

    def close(self) -> None:
        with self._lock:
            self.conn.close()
