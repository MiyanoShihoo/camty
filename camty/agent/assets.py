"""资产图：交战资产真值库（root_domain/subdomain/host/service/endpoint）。

借鉴 ARTEX 资产图语义但保持 Camty 轻量：父子关系与去重全部程序计算，
适配器只提交原始值。覆盖度回答"范围内测了多少、还剩多少没测"。
"""

from __future__ import annotations

from urllib.parse import urlsplit

KINDS = ("root_domain", "subdomain", "host", "service", "endpoint")


def normalize(kind: str, value: str) -> str:
    """按资产类型归一化（去 scheme/路径/大小写/尾点）。"""
    v = str(value).strip().lower().rstrip(".")
    if kind in ("service", "endpoint"):
        parts = urlsplit(v if "://" in v else f"//{v}")
        host = parts.hostname or v
        port = parts.port
        if kind == "service":
            return f"{parts.scheme or 'http'}://{host}" + (f":{port}" if port else "")
        path = parts.path or "/"
        base = f"{parts.scheme or 'http'}://{host}" + (f":{port}" if port else "")
        return base + path
    if "://" in v:
        v = v.split("://", 1)[1]
    return v.split("/", 1)[0]


class AssetGraph:
    def __init__(self, db):
        self.db = db
        self._by_key: dict[str, dict] = {a["dedup_key"]: a for a in db.load_assets()}

    # ---- 写入 ----

    def upsert(self, kind: str, value: str, source: str = "") -> dict:
        """入图并自动挂父链，返回资产行。"""
        if kind not in KINDS:
            raise ValueError(f"未知资产类型 {kind}，可选: {KINDS}")
        value = normalize(kind, value)
        dedup = f"{kind}|{value}"
        if dedup in self._by_key:
            if source:
                self.db.upsert_asset(kind, value, self._by_key[dedup]["parent_key"], source)
            return self._by_key[dedup]
        parent_key = self._auto_parent(kind, value)
        self.db.upsert_asset(kind, value, parent_key, source)
        row = {"dedup_key": dedup, "kind": kind, "value": value,
               "parent_key": parent_key, "source": source, "tested": False}
        self._by_key[dedup] = row
        return row

    def _auto_parent(self, kind: str, value: str) -> str | None:
        """推导父资产：subdomain→root_domain(后缀)、service→host、endpoint→service。"""
        if kind == "subdomain":
            roots = [a for a in self._by_key.values() if a["kind"] == "root_domain"]
            for root in sorted(roots, key=lambda a: -len(a["value"])):
                if value.endswith("." + root["value"]) and value != root["value"]:
                    return root["dedup_key"]
            return None
        if kind == "host":
            subs = [a for a in self._by_key.values() if a["kind"] == "subdomain"]
            for sub in sorted(subs, key=lambda a: -len(a["value"])):
                if value == sub["value"] or value.endswith("." + sub["value"]):
                    return sub["dedup_key"]
            return None
        if kind == "service":
            return f"host|{normalize('host', value)}"
        if kind == "endpoint":
            return f"service|{normalize('service', value)}"
        return None

    def mark_tested(self, value: str, kind: str | None = None) -> int:
        """按值标记已测：命中最深一层即停（父链不连坐）；URL 无直接命中时退化为标记其所属 service。"""
        candidates = []
        if kind:
            candidates.append((kind, normalize(kind, value)))
        else:
            for k in ("endpoint", "service", "host", "subdomain", "root_domain"):
                candidates.append((k, normalize(k, value)))
        for k, v in candidates:
            row = self._by_key.get(f"{k}|{v}")
            if row:
                if not row["tested"]:
                    row["tested"] = True
                    self.db.mark_asset_tested(v)
                    return 1
                return 0
        if "://" in value:
            svc = normalize("service", value)
            row = self._by_key.get(f"service|{svc}")
            if row and not row["tested"]:
                row["tested"] = True
                self.db.mark_asset_tested(svc)
                return 1
        return 0

    # ---- 读取 ----

    def all(self) -> list[dict]:
        return list(self._by_key.values())

    def coverage(self) -> dict:
        by_kind: dict[str, dict[str, int]] = {}
        for a in self._by_key.values():
            slot = by_kind.setdefault(a["kind"], {"total": 0, "tested": 0})
            slot["total"] += 1
            slot["tested"] += 1 if a["tested"] else 0
        total = sum(s["total"] for s in by_kind.values())
        tested = sum(s["tested"] for s in by_kind.values())
        return {"total": total, "tested": tested, "by_kind": by_kind}

    def untested(self) -> list[dict]:
        return [a for a in self._by_key.values() if not a["tested"]]

    def tree(self) -> list[dict]:
        """父子树视图（孤儿节点挂顶层）。"""
        nodes = {a["dedup_key"]: {**a, "children": []} for a in self._by_key.values()}
        roots = []
        for key, node in nodes.items():
            parent = node.get("parent_key")
            if parent and parent in nodes and parent != key:
                nodes[parent]["children"].append(node)
            else:
                roots.append(node)
        return roots

    def summary(self) -> str:
        cov = self.coverage()
        parts = ", ".join(
            f"{k}×{v['total']}(测{v['tested']})"
            for k, v in sorted(cov["by_kind"].items())
        )
        return f"资产 {cov['total']} 个，已测 {cov['tested']}：{parts}" if cov["total"] else "（资产图空）"
