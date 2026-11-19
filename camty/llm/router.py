"""多 provider LLM 路由。

内部消息格式（引擎内统一使用）：
  {"role": "system"|"user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id", "name", "arguments": dict}]}
  {"role": "tool", "tool_call_id": str, "content": str}

由本模块转换为各 provider 的原生格式：
- openai:    Chat Completions 协议（官方 OpenAI 与全部第三方兼容端：DeepSeek/Qwen/Moonshot/vLLM/Ollama/OpenRouter…）
- responses: OpenAI Responses 原生协议（官方 /v1/responses 与第三方 responses 兼容网关）
- anthropic: Anthropic 原生 messages 协议
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from camty.llm.vault import HAS_CRYPTO, decrypt_text, encrypt_text

ROLE_RECON = "recon"
ROLE_DECIDE = "decide"
ROLE_REPORT = "report"
ROLES = (ROLE_RECON, ROLE_DECIDE, ROLE_REPORT)
KINDS = ("openai", "responses", "anthropic")


class LLMError(RuntimeError):
    pass


class UsageLog:
    """LLM 调用记账：JSONL 追加（usage.jsonl，与 vault 同目录），线程安全。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(self, role: str, provider: str, model: str,
                prompt_tokens: int = 0, completion_tokens: int = 0,
                ok: bool = True, error: str = "") -> None:
        import time

        line = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "role": role, "provider": provider, "model": model,
            "prompt_tokens": int(prompt_tokens or 0),
            "completion_tokens": int(completion_tokens or 0),
            "ok": ok, "error": (error or "")[:200],
        }
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(line, ensure_ascii=False) + "\n")

    def read(self, limit: int = 200) -> list[dict]:
        """最近 limit 条（尾部）。"""
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def totals(self) -> dict:
        """聚合计数：调用数 / token / 按 provider 分布 / 错误数。"""
        records = self.read(limit=100000)
        by_provider: dict[str, dict] = {}
        for rec in records:
            slot = by_provider.setdefault(rec.get("provider", "?"),
                                          {"calls": 0, "errors": 0,
                                           "prompt_tokens": 0, "completion_tokens": 0})
            slot["calls"] += 1
            slot["prompt_tokens"] += rec.get("prompt_tokens", 0)
            slot["completion_tokens"] += rec.get("completion_tokens", 0)
            if not rec.get("ok", True):
                slot["errors"] += 1
        return {
            "calls": sum(s["calls"] for s in by_provider.values()),
            "errors": sum(s["errors"] for s in by_provider.values()),
            "prompt_tokens": sum(s["prompt_tokens"] for s in by_provider.values()),
            "completion_tokens": sum(s["completion_tokens"] for s in by_provider.values()),
            "by_provider": by_provider,
        }


@dataclass
class ProviderConfig:
    name: str
    kind: str  # openai | responses | anthropic
    base_url: str
    api_key: str = ""
    models: dict[str, str] = field(default_factory=dict)

    def model_for(self, role: str) -> str:
        return self.models.get(role) or self.models.get("default", "")

    def masked_key(self) -> str:
        if not self.api_key:
            return ""
        return self.api_key[:4] + "..." + self.api_key[-4:] if len(self.api_key) > 8 else "****"


class LLMRouter:
    """按角色（recon/decide/report）路由到不同 provider/model。

    密钥来源优先级：vault 文件 > 环境变量 CAMTY_<NAME>_API_KEY。
    """

    def __init__(self, vault_path: str | Path | None = None):
        self.vault_path = Path(vault_path or os.environ.get("CAMTY_VAULT", "keys.json"))
        self.usage = UsageLog(self.vault_path.parent / "usage.jsonl")
        self.providers: dict[str, ProviderConfig] = {}
        self._load()

    def _load(self) -> None:
        if not self.vault_path.exists():
            return
        raw = json.loads(self.vault_path.read_text(encoding="utf-8"))
        if raw.get("encrypted"):
            master = os.environ.get("CAMTY_MASTER_KEY", "")
            if not master:
                raise LLMError("vault 已加密，请设置 CAMTY_MASTER_KEY 环境变量")
            raw = json.loads(decrypt_text(raw, master))
        for name, item in raw.items():
            kind = item.get("kind", "openai")
            if kind not in KINDS:
                raise LLMError(f"未知的 provider 类型: {kind}（支持 {' / '.join(KINDS)}）")
            self.providers[name] = ProviderConfig(
                name=name,
                kind=kind,
                base_url=item.get("base_url", "").rstrip("/"),
                api_key=item.get("api_key") or os.environ.get(f"CAMTY_{name.upper()}_API_KEY", ""),
                models=item.get("models", {}),
            )

    def save(self) -> None:
        data = {
            name: {
                "kind": cfg.kind,
                "base_url": cfg.base_url,
                "api_key": cfg.api_key,
                "models": cfg.models,
            }
            for name, cfg in self.providers.items()
        }
        master = os.environ.get("CAMTY_MASTER_KEY", "")
        was_encrypted = False
        if self.vault_path.exists():
            try:
                was_encrypted = json.loads(self.vault_path.read_text(encoding="utf-8")).get("encrypted", False)
            except (json.JSONDecodeError, OSError):
                pass
        if master and HAS_CRYPTO:
            text = json.dumps(data, ensure_ascii=False, indent=2)
            blob = encrypt_text(text, master)
            self.vault_path.write_text(json.dumps(blob, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            if was_encrypted:
                raise LLMError("vault 当前是加密的，但未设置 CAMTY_MASTER_KEY，拒绝降级为明文保存")
            self.vault_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(self.vault_path, 0o600)
        except OSError:
            pass

    def set_provider(self, name: str, kind: str, base_url: str, api_key: str, models: dict) -> ProviderConfig:
        if kind not in KINDS:
            raise LLMError(f"未知的 provider 类型: {kind}（支持 {' / '.join(KINDS)}）")
        cfg = ProviderConfig(name=name, kind=kind, base_url=base_url.rstrip("/"), api_key=api_key, models=models)
        self.providers[name] = cfg
        self.save()
        return cfg

    def resolve(self, role: str) -> tuple[ProviderConfig, str]:
        for cfg in self.providers.values():
            model = cfg.model_for(role)
            if model:
                return cfg, model
        raise LLMError(
            f"没有 provider 覆盖角色 '{role}'。"
            f"先用 `python -m camty keys set` 配置（见 README）"
        )

    def resolve_candidates(self, role: str) -> list[tuple[ProviderConfig, str]]:
        """同角色的全部候选（池退避：按配置顺序故障切换）。"""
        return [
            (cfg, cfg.model_for(role))
            for cfg in self.providers.values()
            if cfg.model_for(role)
        ]

    def chat(self, role: str, messages: list[dict], tools: list[dict] | None = None,
             timeout: float = 300.0) -> dict:
        """池化调用：候选 provider 依次尝试，故障自动切换下一个（llm 池退避）。

        timeout：单次 HTTP 请求上限（秒）。引擎内建议 45-60s，防 worker 空转。
        """
        candidates = self.resolve_candidates(role)
        if not candidates:
            raise LLMError(
                f"没有 provider 覆盖角色 '{role}'。"
                f"先用 `python -m camty keys set` 配置（见 README）"
            )
        last_exc: Exception | None = None
        for cfg, model in candidates:
            try:
                if cfg.kind == "anthropic":
                    result = self._chat_anthropic(cfg, model, messages, tools, timeout)
                elif cfg.kind == "responses":
                    result = self._chat_responses(cfg, model, messages, tools, timeout)
                else:
                    result = self._chat_openai(cfg, model, messages, tools, timeout)
                usage = result.get("usage") or {}
                self.usage.record(
                    role, cfg.name, model,
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
                    ok=True)
                return result
            except LLMError as exc:
                self.usage.record(role, cfg.name, model, ok=False, error=str(exc))
                last_exc = exc
                if len(candidates) > 1:
                    print(f"[llm-pool] {cfg.name} 调用失败，切换下一候选: {exc}")
        raise last_exc  # type: ignore[misc]

    @staticmethod
    def _norm_usage_openai(body: dict) -> dict:
        usage = body.get("usage") or {}
        return {"prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0)}

    @staticmethod
    def _norm_usage_anthropic(body: dict) -> dict:
        usage = body.get("usage") or {}
        return {"prompt_tokens": usage.get("input_tokens", 0),
                "completion_tokens": usage.get("output_tokens", 0)}

    @staticmethod
    def _post(url: str, headers: dict, payload: dict, timeout: float = 300.0) -> dict:
        """Chrome 指纹优先（curl_cffi，过 CF 类封禁），回退 urllib。"""
        from camty.modules import http_fp

        body = json.dumps(payload).encode("utf-8")
        out = http_fp.fetch(url, method="POST", headers={"Content-Type": "application/json", **headers},
                            body=body, timeout=timeout)
        if out is not None:
            text, status = out
            if status == 200:
                return json.loads(text)
            raise LLMError(f"HTTP {status}: {str(text)[:500]}")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", **headers},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            raise LLMError(f"HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise LLMError(f"网络错误: {exc.reason}") from exc
        except TimeoutError as exc:
            raise LLMError(f"LLM 请求超时（>{timeout:.0f}s）") from exc

    def _chat_openai(self, cfg: ProviderConfig, model: str, messages: list[dict], tools: list[dict] | None, timeout: float = 300.0) -> dict:
        payload: dict = {"model": model, "messages": [self._to_openai_msg(m) for m in messages], "stream": False}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        body = self._post(
            cfg.base_url + "/chat/completions",
            {"Authorization": f"Bearer {cfg.api_key}"},
            payload,
            timeout,
        )
        msg = body["choices"][0]["message"]
        tool_calls = [
            {
                "id": tc.get("id", ""),
                "name": tc["function"]["name"],
                "arguments": json.loads(tc["function"]["arguments"] or "{}"),
            }
            for tc in msg.get("tool_calls") or []
        ]
        return {"content": msg.get("content") or "", "tool_calls": tool_calls,
                "usage": self._norm_usage_openai(body)}

    def _chat_anthropic(self, cfg: ProviderConfig, model: str, messages: list[dict], tools: list[dict] | None, timeout: float = 300.0) -> dict:
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        payload: dict = {
            "model": model,
            "max_tokens": 4096,
            "messages": self._to_anthropic_msgs([m for m in messages if m["role"] != "system"]),
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = [
                {
                    "name": t["function"]["name"],
                    "description": t["function"].get("description", ""),
                    "input_schema": t["function"].get("parameters", {"type": "object"}),
                }
                for t in tools
            ]
        body = self._post(
            cfg.base_url + "/messages",
            {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01"},
            payload,
            timeout,
        )
        content, tool_calls = "", []
        for block in body.get("content", []):
            if block["type"] == "text":
                content += block["text"]
            elif block["type"] == "tool_use":
                tool_calls.append({"id": block["id"], "name": block["name"], "arguments": block.get("input", {})})
        return {"content": content, "tool_calls": tool_calls,
                "usage": self._norm_usage_anthropic(body)}

    def _chat_responses(self, cfg: ProviderConfig, model: str, messages: list[dict], tools: list[dict] | None, timeout: float = 300.0) -> dict:
        payload: dict = {"model": model, "input": self._to_responses_input(messages), "stream": False}
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "name": t["function"]["name"],
                    "description": t["function"].get("description", ""),
                    "parameters": t["function"].get("parameters", {"type": "object"}),
                }
                for t in tools
            ]
        body = self._post(
            cfg.base_url + "/responses",
            {"Authorization": f"Bearer {cfg.api_key}"},
            payload,
            timeout,
        )
        result = self._parse_responses_output(body)
        result["usage"] = self._norm_usage_anthropic(body)
        return result

    @staticmethod
    def _to_responses_input(messages: list[dict]) -> list[dict]:
        items: list[dict] = []
        for m in messages:
            if m["role"] == "system":
                items.append({"role": "system", "content": m["content"]})
            elif m["role"] == "user":
                items.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                if m.get("content"):
                    items.append({"role": "assistant", "content": m["content"]})
                for tc in m.get("tool_calls") or []:
                    items.append(
                        {
                            "type": "function_call",
                            "call_id": tc["id"],
                            "name": tc["name"],
                            "arguments": json.dumps(tc["arguments"], ensure_ascii=False),
                        }
                    )
            elif m["role"] == "tool":
                items.append(
                    {"type": "function_call_output", "call_id": m["tool_call_id"], "output": m["content"]}
                )
        return items

    @staticmethod
    def _parse_responses_output(body: dict) -> dict:
        content, tool_calls = "", []
        for item in body.get("output", []):
            if item.get("type") == "message":
                for block in item.get("content", []):
                    if block.get("type") == "output_text":
                        content += block.get("text", "")
            elif item.get("type") == "function_call":
                tool_calls.append(
                    {
                        "id": item.get("call_id", item.get("id", "")),
                        "name": item.get("name", ""),
                        "arguments": json.loads(item.get("arguments") or "{}"),
                    }
                )
        return {"content": content, "tool_calls": tool_calls}

    @staticmethod
    def _to_openai_msg(m: dict) -> dict:
        if m["role"] == "assistant" and m.get("tool_calls"):
            return {
                "role": "assistant",
                "content": m.get("content") or None,
                "tool_calls": [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"], ensure_ascii=False)},
                    }
                    for tc in m["tool_calls"]
                ],
            }
        if m["role"] == "tool":
            return {"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]}
        return {"role": m["role"], "content": m["content"]}

    @staticmethod
    def _to_anthropic_msgs(messages: list[dict]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m["role"] == "system":
                continue
            role = "assistant" if m["role"] == "assistant" else "user"
            if m["role"] == "assistant":
                blocks = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls") or []:
                    blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]})
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]})
            elif m["role"] == "tool":
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list) and out[-1]["content"] and out[-1]["content"][0]["type"] == "tool_result":
                    out[-1]["content"].append(
                        {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
                    )
                else:
                    out.append({"role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
                    ]})
            else:
                out.append({"role": "user", "content": m["content"]})
        return out
