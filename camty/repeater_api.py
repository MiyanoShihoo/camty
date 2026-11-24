"""Repeater 的 FastAPI 守护层。

独立模块的原因：repeater.py 顶层有 `from __future__ import annotations`（延迟注解），
而 FastAPI 依赖运行时解析类型注解——闭包内 import 的类型它解析不到，
会把 Request/Pydantic 模型全当成 query 参数（实测踩坑）。本模块不带延迟注解，
fastapi/pydantic 全部模块级 import，与 camty/api/app.py 同一模式。

鉴权：全部端点要求 Bearer token（或 ?token=）。未设置 CAMTY_REPEATER_TOKEN
时自动生成随机 token 并打印 stderr（fail-secure，模式对齐面板）——守护能发
请求、读历史、借走会话 Cookie，裸奔等于把认证态开放给本机任意进程。
"""

import hmac
import os
import secrets
import sys
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from camty.guardrail.scope import ScopeError
from camty.repeater import RepeaterSession

_GENERATED_TOKEN: str | None = None


def _repeater_token() -> str:
    """面板同款 fail-secure：优先环境变量，未设置则生成随机 token（进程内复用）。"""
    global _GENERATED_TOKEN
    env_token = os.environ.get("CAMTY_REPEATER_TOKEN", "")
    if env_token:
        return env_token
    if _GENERATED_TOKEN is None:
        _GENERATED_TOKEN = secrets.token_hex(16)
        print(f"[camty] CAMTY_REPEATER_TOKEN 未设置，已生成随机 repeater token: {_GENERATED_TOKEN}"
              "（可用 CAMTY_REPEATER_TOKEN 显式指定）", file=sys.stderr)
    return _GENERATED_TOKEN


def _reset_repeater_token_for_tests() -> None:
    """测试专用：清空生成的随机 token（不影响 CAMTY_REPEATER_TOKEN 优先级与生产语义）。"""
    global _GENERATED_TOKEN
    _GENERATED_TOKEN = None


class Req(BaseModel):
    method: str = "GET"
    url: str
    headers: dict | None = None
    body: Any = None
    mode: str = "http"
    auto_csrf: str = ""
    render: bool = False


class Vec(BaseModel):
    url: str
    param: str
    payloads: list
    method: str = "GET"
    body: dict | None = None
    mode: str = "http"
    baseline: str | None = None
    gap: str = "url"
    auto_csrf: str = ""
    render: bool | None = None
    headers: dict | None = None


class Seq(BaseModel):
    requests: list[dict]


def build_app(session: RepeaterSession) -> FastAPI:
    app = FastAPI(title="Camty Repeater", version="0.1.0")

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        """全端点鉴权：Bearer 或 ?token=（与面板同模式，字节级恒时比较）。"""
        token = _repeater_token()
        auth_header = request.headers.get("Authorization", "")
        supplied = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
        supplied = supplied or request.query_params.get("token", "")
        # 按字节比较：compare_digest 的 str 形式对非 ASCII 输入会 TypeError
        if not hmac.compare_digest(supplied.encode("utf-8"), token.encode("utf-8")):
            return JSONResponse(status_code=401, content={"error": "repeater 未授权（Bearer token 错误）"})
        return await call_next(request)

    @app.post("/req")
    async def do_req(r: Req):
        try:
            return JSONResponse(session.send(**r.model_dump()))
        except ScopeError as e:
            return JSONResponse(status_code=403, content={"error": f"scope: {e}"})
        except TypeError as e:
            return JSONResponse(status_code=400, content={"error": f"参数错误: {e}"})

    @app.post("/vector")
    async def do_vec(v: Vec):
        try:
            return JSONResponse(session.vector(**v.model_dump()))
        except ScopeError as e:
            return JSONResponse(status_code=403, content={"error": f"scope: {e}"})

    @app.post("/seq")
    async def do_seq(s: Seq):
        try:
            return JSONResponse({"results": session.seq(s.requests)})
        except ScopeError as e:
            return JSONResponse(status_code=403, content={"error": f"scope: {e}"})

    @app.get("/log")
    async def get_log():
        return JSONResponse({"log": session.log[-200:]})

    @app.get("/state")
    async def get_state():
        return JSONResponse(session.state())

    @app.post("/stop")
    async def do_stop():
        session.close()
        return JSONResponse({"ok": True})

    return app
