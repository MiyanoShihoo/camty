"""探索图：每交战的推进链（goal/intent/fact/finding/hint）+ 过程跟踪检索。

借鉴 ARTEX 探索图语义：节点以 spawns/yields/derived_from/proves 边连成血缘，
锚点把节点挂到资产图的资产上。TraceStore 记录每个 intent 的执行过程，
供后续 worker 跨意图检索（过程级信息交换）。
"""

from __future__ import annotations

import itertools
import threading

from camty.agent.state import Engagement

NODE_KINDS = ("goal", "intent", "fact", "finding", "hint", "retest")
_counter = itertools.count(1)
_lock = threading.Lock()


def _next_id(prefix: str) -> str:
    with _lock:
        return f"{prefix}-{next(_counter):03d}"


class ExplorationGraph:
    def __init__(self, eng: Engagement):
        self.eng = eng
        self.db = eng.db
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            state = self.db.load_exploration()
            self._nodes = {n["node_id"]: n for n in state["nodes"]}
            self._edges = state["edges"]
            self._anchors = state["anchors"]
            self._loaded = True

    def _flush(self) -> None:
        self._loaded = False

    # ---- 节点与边 ----

    def add_node(self, kind: str, title: str, payload: dict | None = None,
                  node_id: str | None = None) -> str:
        if kind not in NODE_KINDS:
            raise ValueError(f"未知节点类型 {kind}，可选: {NODE_KINDS}")
        node_id = node_id or _next_id({"goal": "G", "intent": "I", "fact": "T",
                                       "finding": "D", "hint": "H", "retest": "R"}[kind])
        import json
        import time

        self.db.add_exploration_node(
            node_id, kind, title,
            json.dumps(payload, ensure_ascii=False) if payload else None)
        self._flush()
        return node_id

    def set_status(self, node_id: str, status: str) -> None:
        """pending/running/done/blocked。"""
        self.db.update_exploration_status(node_id, status)
        self._flush()

    def link(self, src: str, dst: str, relation: str) -> None:
        """血缘边：spawns/derived_from/yields/proves。"""
        self.db.add_edge(src, dst, relation)
        self._flush()

    def anchor(self, node_id: str, asset_key: str) -> None:
        self.db.anchor(node_id, asset_key)
        self._flush()

    # ---- 读取 ----

    def nodes(self) -> list[dict]:
        self._ensure_loaded()
        return list(self._nodes.values())

    def intents_pending(self) -> list[dict]:
        self._ensure_loaded()
        return [n for n in self._nodes.values()
                if n["kind"] == "intent" and n["status"] == "pending"]

    def overview(self) -> dict:
        """planner 态势：目标/进行中意图/事实/发现计数 + 最近节点。"""
        self._ensure_loaded()
        by_kind: dict[str, int] = {}
        for n in self._nodes.values():
            by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
        return {
            "counts": by_kind,
            "goal": next((n for n in self._nodes.values() if n["kind"] == "goal"), None),
            "pending_intents": len(self.intents_pending()),
            "recent": sorted(self._nodes.values(),
                             key=lambda n: n["updated_ts"] or "")[-10:],
        }

    def graph(self) -> dict:
        """双图导出（报告/面板用）。"""
        self._ensure_loaded()
        return {
            "nodes": list(self._nodes.values()),
            "edges": self._edges,
            "anchors": self._anchors,
        }

    # ---- 过程跟踪 ----

    def trace(self, node_id: str | None, step: int, tool: str, args: dict,
              result_summary: str, evidence: str | None = None) -> None:
        import json

        self.db.add_activity(
            node_id, step, tool,
            json.dumps(args, ensure_ascii=False, default=str)[:800],
            result_summary[:800], evidence,
        )

    def search_traces(self, query: str, exclude_node: str | None = None,
                      limit: int = 20) -> list[dict]:
        """跨意图检索执行过程（排除自己，避免自我循环）。"""
        return self.db.search_activity(query, exclude_node=exclude_node, limit=limit)


class Todolist:
    """跨轮共享规划待办：攻击链串行依赖逐步派意图（ARTEX 语义）。"""

    def __init__(self, eng: Engagement):
        self.eng = eng
        self.db = eng.db

    def replace(self, items: list[dict]) -> None:
        self.db.sync_todolist(items)

    def items(self) -> list[dict]:
        return self.db.load_todolist()

    def mark(self, item_id: str, status: str, note: str = "") -> None:
        items = self.items()
        for item in items:
            if item["item_id"] == item_id:
                item["status"] = status
                if note:
                    item["note"] = note
        self.db.sync_todolist(items)

    def ready_items(self) -> list[dict]:
        """前置已完成的 pending 项。"""
        items = self.items()
        done = {i["item_id"] for i in items if i["status"] == "done"}
        return [
            i for i in items
            if i["status"] == "pending" and all(d in done for d in i.get("depends_on") or [])
        ]

    def summary(self) -> str:
        items = self.items()
        if not items:
            return "（todolist 空）"
        return "\n".join(
            f"{i['item_id']} [{i['status']}] {i['title']}"
            + (f"（前置 {','.join(i['depends_on'])}）" if i.get("depends_on") else "")
            for i in items
        )
