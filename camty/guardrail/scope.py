"""交战范围护栏：deny-by-default 白名单 + DNS 解析校验 + 速率限制。"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time


class ScopeError(RuntimeError):
    pass


class Scope:
    def __init__(self, cfg: dict):
        self.domains = {d.strip().lower().strip(".") for d in cfg.get("domains", []) if d}
        self.networks = [ipaddress.ip_network(c, strict=False) for c in cfg.get("cidrs", []) if c]
        self.ips = {ipaddress.ip_address(i) for i in cfg.get("ips", []) if i}
        # 单 IP 授权等价 /32 网络（require_cidr 的语义一致性）
        self.networks += [ipaddress.ip_network(f"{i}/32") for i in self.ips
                          if f"{i}/32" not in [str(n) for n in self.networks]]
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

    def require(self, raw_host: str) -> None:
        """校验目标在范围内，直接进行，不在，询问，用户告诉后，直接进行，域名先解析再校验 IP，防止“形似目标域”绕过。"""
        host = str(raw_host).strip().lower()
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0].split(":", 1)[0]

        if not self._host_allowed(host):
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
