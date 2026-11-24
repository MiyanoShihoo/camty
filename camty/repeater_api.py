"""Repeater 的 FastAPI 守护层。

独立模块的原因：repeater.py 顶层有 `from __future__ import annotations`（延迟注解），
而 FastAPI 依赖运行时解析类型注解——闭包内 import 的类型它解析不到，
会把 Request/Pydantic 模型全当成 query 参数（实测踩坑）。本模块不带延迟注解，
fastapi/pydantic 全部模块级 import，与 camty/api/app.py 同一模式。
"""

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from camty.guardrail.scope import ScopeError
from camty.repeater import RepeaterSession


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
