"""MITM 流量记录代理：全程留痕（HTTP 全量 + HTTPS 解密）。

ARTEX 流量留痕的 Camty 落地：
- 交战目录生成 CA（traffic/ca.crt/ca.key，cryptography），HTTPS 逐域动态签发叶子证书
- 适配器/浏览器把代理指到 127.0.0.1:<port>（ctx.traffic.proxy_url()）
- 每笔请求 → traffic/traffic.jsonl：方法/路径/状态/头/体（截断）+ 字节数
- enforce_scope：范围外主机直接拒绝 CONNECT/转发（纵深防御，默认开）
- 运行完 selftest 可用 openssl s_client -proxy 验证 CA

依赖 vendor 里的 cryptography（camty 包 import 时自动挂载）。
"""

from __future__ import annotations

import datetime
import json
import os
import socket
import ssl
import threading
import time
from pathlib import Path

BODY_LIMIT = 8192
REDACT_HEADERS = ("authorization", "cookie", "set-cookie", "proxy-authorization")

_certs_lock = threading.Lock()
_certs_cache: dict[str, str] = {}


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


class CertFactory:
    """CA + 按域叶子证书（磁盘缓存 traffic/certs/）。"""

    def __init__(self, ca_dir: Path):
        self.ca_dir = ca_dir
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = ca_dir / "ca.crt"
        self.ca_key_path = ca_dir / "ca.key"
        self.certs_dir = ca_dir / "certs"
        self._ca_cert = self._ca_key = None

    def ensure_ca(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            self._ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
            self._ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), None)
            return
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Camty Traffic CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                            critical=False)
            .sign(key, hashes.SHA256())
        )
        self.ca_key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self._ca_cert, self._ca_key = cert, key

    def leaf_path(self, host: str) -> str:
        with _certs_lock:
            cached = _certs_cache.get(host)
            if cached and Path(cached).exists():
                return cached
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID

            self.ensure_ca()
            self.certs_dir.mkdir(exist_ok=True)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
            try:
                import ipaddress

                san_entry = x509.IPAddress(ipaddress.ip_address(host))
            except ValueError:
                san_entry = x509.DNSName(host)
            san = x509.SubjectAlternativeName([san_entry])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(name).issuer_name(self._ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(san, critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                               critical=False)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
                    critical=False)
                .sign(self._ca_key, hashes.SHA256())
            )
            path = self.certs_dir / f"{host.replace(':', '_')}.pem"
            path.write_bytes(
                key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                   serialization.NoEncryption())
                + cert.public_bytes(serialization.Encoding.PEM))
            _certs_cache[host] = str(path)
            return str(path)


def _redact(headers: list[tuple[bytes, bytes]]) -> list[list[str]]:
    out = []
    for k, v in headers:
        name = k.decode("latin-1", "replace").lower()
        value = v.decode("latin-1", "replace") if name not in REDACT_HEADERS else "***"
        out.append([name, value[:300]])
    return out


class TrafficProxy:
    """线程化 MITM 记录代理。start() → proxy_url()；stop() 幂等。"""

    def __init__(self, eng, port: int = 8899, enforce_scope: bool = True,
                 upstream_cafile: str | None = None):
        self.eng = eng
        self.port = port
        self.enforce_scope = enforce_scope
        self.upstream_cafile = upstream_cafile  # 内网自签上游时指定其 CA（缺省系统根）
        self.out_dir = eng.dir / "traffic"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.out_dir / "traffic.jsonl"
        self.cert_factory = CertFactory(self.out_dir / "ca")
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._n = 0
        self._alive = False

    # ---- 生命周期 ----

    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> str:
        self.cert_factory.ensure_ca()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self.port = self._sock.getsockname()[1]  # port=0 时取系统分配，避测试端口竞争
        self._sock.listen(64)
        self._alive = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self.proxy_url()

    def stop(self) -> None:
        self._alive = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _accept_loop(self):
        while self._alive:
            try:
                client, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    # ---- 记录 ----

    def _record(self, entry: dict) -> None:
        with self._lock:
            self._n += 1
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def stats(self) -> dict:
        n = 0
        hosts: dict[str, int] = {}
        if self.log_path.exists():
            for line in self.log_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                n += 1
                try:
                    entry = json.loads(line)
                    hosts[entry.get("host", "?")] = hosts.get(entry.get("host", "?"), 0) + 1
                except json.JSONDecodeError:
                    continue
        return {"requests": n, "hosts": hosts}

    def _scope_ok(self, host: str) -> bool:
        if not self.enforce_scope:
            return True
        try:
            self.eng.scope.require(host)
            return True
        except Exception:  # noqa: BLE001 - scope 拒绝即拦
            return False

    # ---- 协议处理 ----

    def _handle(self, client: socket.socket):
        try:
            first = _read_line(client)
            if not first:
                client.close()
                return
            parts = first.split()
            if len(parts) < 2:
                client.close()
                return
            if parts[0] == b"CONNECT":
                self._handle_connect(client, parts[1].decode("latin-1"))
            else:
                self._handle_plain(client, first)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _handle_plain(self, client, first_line: bytes):
        """绝对形式 HTTP（http:// 代理流量）：解析头后直转，记录往返。"""
        method, target = first_line.split()[0], first_line.split()[1].decode("latin-1")
        headers, tail = _read_headers(client)
        host = _header(headers, b"host") or target.split("//")[-1].split("/")[0]
        if not self._scope_ok(host):
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        body = _read_body(client, headers, tail)
        self._forward_and_record(client, method, target, host, headers, body)

    def _handle_connect(self, client, hostport: str):
        host = hostport.split(":")[0]
        port = int(hostport.split(":")[1]) if ":" in hostport else 443
        if not self._scope_ok(host):
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        _recv_until(client, b"\r\n\r\n")  # 排空 CONNECT 请求剩余头，避免污染 TLS 握手
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        # MITM：以叶子证书把隧道降级为明文 HTTP
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert_factory.leaf_path(host))
        try:
            tls_client = ctx.wrap_socket(client, server_side=True)
        except (ssl.SSLError, OSError):
            return
        while True:
            try:
                first = _read_line(tls_client)
                if not first:
                    break
                parts = first.split()
                if len(parts) < 2:
                    break
                headers, tail = _read_headers(tls_client)
                body = _read_body(tls_client, headers, tail)
                self._forward_and_record(
                    tls_client, parts[0].decode("latin-1"),
                    parts[1].decode("latin-1"), host, headers, body, tls=True,
                    upstream_port=port)
            except (ssl.SSLError, OSError, ConnectionResetError):
                break
        try:
            tls_client.close()
        except OSError:
            pass

    def _forward_and_record(self, client, method: str, path: str, host: str,
                            headers: list[tuple[bytes, bytes]], body: bytes,
                            tls: bool = False, upstream_port: int = 80):
        upstream_host = host.split(":")[0]
        try:
            sctx = ssl.create_default_context(cafile=self.upstream_cafile) if tls else None
            with socket.create_connection((upstream_host, upstream_port), timeout=20) as usock:
                stream = usock
                if tls:
                    stream = sctx.wrap_socket(usock, server_hostname=upstream_host)
                req = f"{method} {path} HTTP/1.1\r\n".encode("latin-1")
                for k, v in headers:
                    if k.lower() not in (b"proxy-connection", b"connection"):
                        req += k + b": " + v + b"\r\n"
                req += b"Connection: close\r\n\r\n" + body
                stream.sendall(req)
                status, resp_headers, resp_body = _read_response(stream)
        except OSError as exc:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            self._record({"ts": _now(), "host": host, "method": method, "path": path,
                          "error": f"upstream: {exc}"})
            return
        # 留痕先于响应：保证调用方收到 200 时记录必然已落盘（审计完整性）
        self._record({
            "ts": _now(), "host": host, "scheme": "https" if tls else "http",
            "method": method, "path": path, "status": status,
            "req_headers": _redact(headers),
            "req_body": body[:BODY_LIMIT].decode("utf-8", "replace"),
            "resp_headers": _redact(resp_headers),
            "resp_body": resp_body[:BODY_LIMIT].decode("utf-8", "replace"),
            "resp_bytes": len(resp_body),
        })
        try:
            client.sendall(_render_response(status, resp_headers, resp_body))
        except OSError:
            pass


# ---- 原始套接字 HTTP 解析 ----

def _recv_until(sock, marker: bytes, limit: int = 65536) -> bytes:
    buf = b""
    while marker not in buf and len(buf) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def _read_line(sock) -> bytes | None:
    buf = b""
    while b"\r\n" not in buf:
        chunk = sock.recv(1)
        if not chunk:
            return None if not buf else buf
        buf += chunk
        if len(buf) > 8192:
            break
    return buf.split(b"\r\n", 1)[0] or None


def _read_headers(sock) -> tuple[list[tuple[bytes, bytes]], bytes]:
    """解析头并返回 (headers, 过读尾部)。

    _recv_until 可能一次读越过 \r\n\r\n——Python 3.13+ 的 socket 对象没有
    __dict__，不能挂自定义属性暂存（挂属性即 AttributeError），因此过读
    字节以返回值显式传给 _read_body，不落任何隐藏状态。
    """
    raw = _recv_until(sock, b"\r\n\r\n")
    if not raw:
        return [], b""
    head, _, tail = raw.partition(b"\r\n\r\n")
    headers = []
    for line in head.split(b"\r\n"):
        if b":" in line and not line[:1].isspace():
            k, v = line.split(b":", 1)
            headers.append((k.strip(), v.strip()))
    return headers, tail


def _read_body(sock, headers: list[tuple[bytes, bytes]], leftover: bytes = b"") -> bytes:
    length = 0
    for k, v in headers:
        if k.lower() == b"content-length":
            try:
                length = int(v)
            except ValueError:
                length = 0
    body = leftover[:length]
    while len(body) < length and length - len(body) > 0:
        chunk = sock.recv(min(65536, length - len(body)))
        if not chunk:
            break
        body += chunk
    # 多读的部分（keep-alive 后续请求）弃用——代理侧每请求一连接足够
    return body[:BODY_LIMIT * 4]


def _read_response(stream) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    raw = b""
    while b"\r\n\r\n" not in raw and len(raw) < 65536:
        chunk = stream.recv(4096)
        if not chunk:
            break
        raw += chunk
    if not raw:
        return 502, [], b""
    head, _, tail = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        status = 0
    headers = []
    length = None
    chunked = False
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers.append((k.strip(), v.strip()))
            if k.strip().lower() == b"content-length":
                length = int(v.strip() or 0)
            elif k.strip().lower() == b"transfer-encoding" and b"chunked" in v.lower():
                chunked = True
    body = tail
    if chunked:
        while b"0\r\n\r\n" not in body[-10:] if body else True:
            chunk = stream.recv(65536)
            if not chunk:
                break
            body += chunk
            if len(body) > 2 * BODY_LIMIT * 16:
                break
    elif length is not None:
        while len(body) < length:
            chunk = stream.recv(min(65536, length - len(body)))
            if not chunk:
                break
            body += chunk
    else:
        stream.settimeout(20)
        try:
            while True:
                chunk = stream.recv(65536)
                if not chunk:
                    break
                body += chunk
                if len(body) > BODY_LIMIT * 16:
                    break
        except OSError:
            pass
    return status, headers, body


def _render_response(status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> bytes:
    head = f"HTTP/1.1 {status} X\r\n".encode("latin-1")
    for k, v in headers:
        if k.lower() in (b"transfer-encoding", b"content-length", b"connection"):
            continue
        head += k + b": " + v + b"\r\n"
    head += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("latin-1")
    return head + body


def _header(headers: list[tuple[bytes, bytes]], name: bytes) -> str:
    for k, v in headers:
        if k.lower() == name.lower():
            return v.decode("latin-1")
    return ""
