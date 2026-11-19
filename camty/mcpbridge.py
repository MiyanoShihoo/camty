"""MCP 桥：把外部 MCP（Model Context Protocol）服务器的工具接入 Camty 适配器体系。

Streamable HTTP transport：JSON-RPC 2.0 POST 到 MCP endpoint。
交战配置：
  mcp_servers:
    - name: burp
      url: http://127.0.0.1:9876/mcp
      token: ""            # 可选 Bearer
启动时 MCPBridge.discover(registry) 拉工具清单 → 每个 MCP tool 生成
"mcp:<server>:<tool>" 适配器薄壳，LLM worker / Deterministic 步骤统一调用。
"""

from __future__ import annotations

import json
import urllib.request

PROTOCOL_VERSION = "2025-06-18"


def _post(url: str, payload: dict, token: str = "", timeout: float = 60.0) -> dict:
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", "replace")
        # Streamable HTTP：可能返回 SSE（event/data 行）或裸 JSON
        if raw.lstrip().startswith("{"):
            return json.loads(raw)
        for line in raw.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
        raise MCPError(f"MCP 响应不可解析: {raw[:200]}")


class MCPError(RuntimeError):
    pass


class MCPClient:
    """单 MCP 服务器的 JSON-RPC 客户端（initialize → tools/list → tools/call）。"""

    def __init__(self, name: str, url: str, token: str = ""):
        self.name = name
        self.url = url
        self.token = token
        self.session_id = ""
        self._next_id = 0
        self.client_info = {"name": "camty", "version": "0.2"}

    def _rpc(self, method: str, params: dict | None = None, timeout: float = 60.0) -> dict:
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            payload["params"] = params
        out = _post(self.url, payload, self.token, timeout)
        if "error" in out:
            raise MCPError(f"MCP {method} 错误: {out['error']}")
        return out.get("result", {})

    def initialize(self) -> dict:
        result = self._rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "clientInfo": self.client_info,
        })
        # Streamable HTTP 会话：服务端经 Mcp-Session-Id 头下发——urllib 层已透明，
        # 需要显式会话的服务器由后续请求自行处理；初始化通知按协议发出。
        try:
            _post(self.url, {"jsonrpc": "2.0", "method": "notifications/initialized"},
                  self.token, timeout=10)
        except Exception:  # noqa: BLE001 - 通知失败不阻塞（部分实现无需）
            pass
        return result

    def list_tools(self) -> list[dict]:
        result = self._rpc("tools/list", {})
        return result.get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> str:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        contents = result.get("content", [])
        parts = []
        for c in contents:
            if isinstance(c, dict):
                parts.append(str(c.get("text", c.get("image", "")) if not c.get("type")
                                 or c.get("type") == "text" else f"[{c.get('type')}]"))
        if result.get("isError"):
            raise MCPError(f"MCP 工具错误: {''.join(parts)[:300]}")
        return "".join(parts) or json.dumps(result, ensure_ascii=False)


def build_adapters(client: MCPClient) -> list:
    """MCP 工具清单 → Camty ToolAdapter 薄壳列表。"""
    from camty.adapters.base import ToolAdapter, ToolResult

    client.initialize()
    tools = client.list_tools()
    adapters = []
    for tool in tools:
        name = str(tool.get("name", "")).strip()
        if not name:
            continue
        mcp_client_ref = client

        class MCPToolAdapter(ToolAdapter):
            def __init__(self, tool_name: str, desc: str, schema: dict):
                self.name = f"mcp:{client.name}:{tool_name}"
                self.description = f"[MCP:{client.name}] {desc or tool_name}"
                self.schema = schema

            def available(self) -> bool:
                return True

            def tool_schema(self) -> dict:
                return self.schema or {"type": "object", "properties": {}}

            def run(self, args: dict, ctx) -> ToolResult:
                try:
                    output = mcp_client_ref.call_tool(self.name.rsplit(":", 1)[-1], args)
                except MCPError as exc:
                    return ToolResult(summary=f"MCP 调用失败: {exc}", data={})
                evidence = ctx.save_evidence(self.name, output[:8000])
                ctx.audit.record(self.name, args, ok=True,
                                 note=output[:80])
                return ToolResult(summary=output[:200] or "（空输出）",
                                  data={"output": output[:4000]},
                                  evidence=evidence)

        adapters.append(MCPToolAdapter(name, str(tool.get("description", "")),
                                       tool.get("inputSchema") or {}))
    return adapters


def attach(cfg: dict, registry: dict) -> list:
    """交战配置 mcp_servers → 发现工具并入 registry。返回并入的工具名。"""
    added = []
    for server in cfg.get("mcp_servers") or []:
        client = MCPClient(str(server.get("name", "mcp")),
                           str(server["url"]), str(server.get("token", "")))
        try:
            for adapter in build_adapters(client):
                if adapter.name not in registry:
                    registry[adapter.name] = adapter
                    added.append(adapter.name)
        except (MCPError, OSError, KeyError) as exc:
            print(f"[mcp] {server.get('name')} 接入失败: {exc}")
    if added:
        print(f"[mcp] 接入 {len(added)} 个 MCP 工具: {added[:6]}{'…' if len(added) > 6 else ''}")
    return added
