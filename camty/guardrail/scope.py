"""交战范围护栏：deny-by-default 白名单 + DNS 解析校验 + 速率限制。"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
import urllib.parse


class ScopeError(RuntimeError):
    pass


class Scope:
    def __init__(self, cfg: dict):
        self.domains = {d.strip().lower().strip(".") for d in cfg.get("domains", []) if d}
        self.networks = [ipaddress.ip_network(c, strict=False) for c in cfg.get("cidrs", []) if c]
        self.ips = {ipaddress.ip_address(i) for i in cfg.get("ips", []) if i}
        # 单 IP 授权等价主机网络 /32（IPv4）或 /128（IPv6），保证 require_cidr 语义一致
        existing = {str(n) for n in self.networks}
        self.networks += [
            ipaddress.ip_network(f"{i}/{i.max_prefixlen}")
            for i in self.ips
            if f"{i}/{i.max_prefixlen}" not in existing
        ]
        self.min_interval = float(cfg.get("min_interval_seconds", 0.5))
        self._last_hit: dict[str, float] = {}
        self._lock = threading.Lock()

    def _host_allowed(self, host: str) -> bool:
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        return False

    def _ip_allowed(self, addr: ipaddress.ip_address) -> bool:
        if addr in self.ips:
            return True
        return any(addr in net for net in self.networks)

    def require_cidr(self, cidr: str) -> None:
        """校验探测网段整体落在授权网段内。"""
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
        if not any(net.subnet_of(n) for n in self.networks):
            raise ScopeError(f"网段不在交战范围内: {cidr}")

    def _extract_host(self, raw_host: str) -> str:
        """从主机名或完整 URL 提取规范主机名。

        用 urllib.parse.urlsplit 做标准 RFC 3986 解析：userinfo（user:pass@）
        与后续主机名之间的歧义是手写 split 的经典绕过源，一律在解析层拒绝。
        """
        text = str(raw_host).strip()
        if "://" not in text and not text.startswith("//"):
            text = "//" + text  # 无 scheme 时补 //，让 urlsplit 走 netloc 解析
        parts = urllib.parse.urlsplit(text)
        if parts.username or parts.password:
            raise ScopeError(f"拒绝携带 userinfo 的目标: {raw_host}")
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            raise ScopeError(f"无法解析目标主机: {raw_host}")
        return host

    def require(self, raw_host: str) -> None:
        """校验目标在范围内，直接进行，不在，询问，用户告诉后，直接进行，域名先解析再校验 IP，防止“形似目标域”绕过。"""
        host = self._extract_host(raw_host)

        if not self._host_allowed(host):
            # IP 字面量（含 IPv6 方括号形式）直接按授权集合校验，不经解析器，
            # 保证格式归一且不依赖平台 resolver 对字面量的处理差异。
            try:
                literal = ipaddress.ip_address(host)
            except ValueError:
                literal = None
            if literal is not None:
                if not self._ip_allowed(literal):
                    raise ScopeError(f"目标不在交战范围内: {host}")
            else:
                # TODO(DNS pinning): 这里的解析与 HTTP 客户端真正建连是两次独立解析，
                # 存在 TOCTOU / DNS rebinding 风险（校验时解析到授权 IP，连接时解析到任意外 IP）。
                # 后续应把本次解析出的授权 IP 固定（pin）下来，并强制客户端用该 IP 建连。
                try:
                    infos = socket.getaddrinfo(host, None)
                except OSError as exc:
                    raise ScopeError(f"目标不在交战范围且无法解析: {host}") from exc
                for info in infos:
                    try:
                        addr = ipaddress.ip_address(info[4][0])
                    except ValueError:
                        continue
                    if self._ip_allowed(addr):
                        break
                else:
                    raise ScopeError(f"目标不在交战范围内: {host}")

        with self._lock:
            last = self._last_hit.get(host, 0.0)
            wait = self.min_interval - (time.monotonic() - last) if self.min_interval > 0 else 0.0
            self._last_hit[host] = time.monotonic()
        if wait > 0:
            time.sleep(wait)
