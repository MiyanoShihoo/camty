"""证据与过程检索适配器：evidence 文件全文 + activity 过程库（跨意图检索）。"""

from __future__ import annotations

import json

from camty.adapters.base import RunContext, ToolAdapter, ToolResult

MAX_HITS = 50


class EvidenceSearchAdapter(ToolAdapter):
    name = "evidence-search"
    description = (
        "检索既有证据与执行过程：按关键字扫 evidence 文件与 activity 跟踪库，"
        "返回命中行与来源（复用历史观察，避免重复劳动）。"
    )

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "检索关键字（如域名/hash/端点）"},
                "max_hits": {"type": "integer", "default": 50},
            },
            "required": ["query"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        query = str(args.get("query", "")).strip()
        if not query:
            return ToolResult(summary="query 为空", data={"hits": []})
        limit = int(args.get("max_hits", MAX_HITS))
        hits: list[dict] = []
        # 1) evidence 文件全文
        for path in sorted(ctx.evidence_dir.glob("*")) if ctx.evidence_dir.is_dir() else []:
            if not path.is_file() or path.suffix not in (".txt", ".json", ".jsonl", ".log", ".md", ".html"):
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for no, line in enumerate(lines, 1):
                if query.lower() in line.lower():
                    hits.append({"source": str(path), "line": no,
                                 "text": line.strip()[:200], "kind": "evidence"})
                    if len(hits) >= limit:
                        break
            if len(hits) >= limit:
                break
        # 2) activity 过程库（跨意图过程级检索）
        eng = ctx.eng
        if eng is not None:
            for row in eng.db.search_activity(query, limit=limit):
                hits.append({"source": f"activity#{row['id']}", "line": row["step"],
                             "text": f"[{row['tool']}] {row['result_digest'][:160]}",
                             "kind": "activity", "node_id": row["node_id"]})
                if len(hits) >= limit:
                    break
        evidence = ctx.save_evidence(self.name, json.dumps(hits, ensure_ascii=False, indent=2))
        ctx.audit.record(self.name, {"query": query}, ok=True, note=f"{len(hits)} hits")
        return ToolResult(
            summary=f"命中 {len(hits)} 条（evidence + 过程库）",
            data={"query": query, "hits": hits},
            evidence=evidence,
        )
