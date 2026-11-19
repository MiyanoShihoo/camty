"""战术手册库：按指纹/服务命中，把“看到 X → 试 Y”注入 Agent 上下文。"""

from __future__ import annotations

import os
from pathlib import Path

import yaml


class PlaybookLibrary:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root or os.environ.get("CAMTY_PLAYBOOKS", "playbooks"))
        self._items: list[dict] = []
        self._load()

    def _load(self) -> None:
        if not self.root.is_dir():
            return
        for path in sorted(self.root.rglob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                print(f"[playbook] 跳过损坏文件 {path}: {str(exc).splitlines()[0]}")
                continue
            if isinstance(data, dict) and data.get("name"):
                data["_path"] = str(path)
                self._items.append(data)

    @property
    def items(self) -> list[dict]:
        return self._items

    def match_tech(self, tech_map: dict) -> list[dict]:
        """tech_map: {url: [tech, ...]}（httpx 输出）。命中 match.tech 任一模式即返回。"""
        techs = set()
        for value in tech_map.values():
            if isinstance(value, list):
                techs.update(str(t).lower() for t in value)
            elif isinstance(value, str):
                techs.add(value.lower())
        hits = []
        for pb in self._items:
            patterns = [str(x).lower() for x in (pb.get("match") or {}).get("tech") or []]
            if patterns and any(any(p in t or t in p for t in techs) for p in patterns):
                hits.append(pb)
        return hits

    def match_findings(self, findings: list[dict]) -> list[dict]:
        """按台账 finding 的 template/detail 文本匹配（如 kerberoastable-spn）。"""
        texts = set()
        for f in findings or []:
            for field in ("template", "detail", "kind"):
                value = f.get(field) if isinstance(f, dict) else None
                if value:
                    texts.add(str(value).lower())
        hits = []
        for pb in self._items:
            patterns = [str(x).lower() for x in (pb.get("match") or {}).get("finding") or []]
            if patterns and any(any(p in t for t in texts) for p in patterns):
                hits.append(pb)
        return hits

    def match_service(self, services: list) -> list[dict]:
        svcs = {str(s).lower() for s in services}
        hits = []
        for pb in self._items:
            patterns = [str(x).lower() for x in (pb.get("match") or {}).get("service") or []]
            if patterns and svcs.intersection(patterns):
                hits.append(pb)
        return hits

    @staticmethod
    def as_prompt(pb: dict, limit: int = 800) -> str:
        body = yaml.safe_dump(
            {k: v for k, v in pb.items() if not k.startswith("_")},
            allow_unicode=True,
            sort_keys=False,
        )
        if len(body) > limit:
            body = body[:limit] + "..."
        return f"[战术手册命中] {pb['name']}\n{body}"
