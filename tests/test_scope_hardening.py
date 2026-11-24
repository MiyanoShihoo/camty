"""范围护栏 URL 解析硬化回归：userinfo 绕过、IPv6 等价网络、解析语义保留。

- userinfo 形如 http://target.com:80@evil.com/ 会被旧的手写 split 误放行（实际连接 evil.com）；
- 单 IPv6 授权在旧代码里硬编码 /32 直接 ValueError；
- 所有涉及 DNS 的用例均 monkeypatch socket.getaddrinfo，禁止真实网络。
"""

from __future__ import annotations

import unittest
from unittest import mock

from camty.guardrail.scope import Scope, ScopeError


def _scope(**cfg) -> Scope:
    base = {"min_interval_seconds": 0}
    base.update(cfg)
    return Scope(base)


def _fake_resolve(*addrs):
    """构造 getaddrinfo 返回值（(family, type, proto, canonname, sockaddr) 五元组）。"""
    return [(2, 1, 6, "", (a, 0)) for a in addrs]


class TestUserinfoBypass(unittest.TestCase):
    """userinfo 解析差异绕过：require 必须在解析层直接拒绝。"""

    def test_userinfo_urls_rejected(self):
        s = _scope(domains=["target.com"])
        for url in (
            "http://target.com:@evil.com/x",
            "http://target.com:80@evil.com/x",
            "http://user@target.com/",
            "http://:password@target.com/",
        ):
            with self.assertRaises(ScopeError, msg=url):
                s.require(url)

    def test_userinfo_rejected_before_dns(self):
        s = _scope(domains=["target.com"])
        with mock.patch("camty.guardrail.scope.socket.getaddrinfo") as gai:
            with self.assertRaises(ScopeError):
                s.require("http://target.com:80@evil.com/x")
            gai.assert_not_called()


class TestWhitelistedForms(unittest.TestCase):
    """既有授权形态不得回归：子域、带端口、裸主机、尾部点。"""

    def test_passing_forms(self):
        s = _scope(domains=["target.com"])
        s.require("https://sub.target.com:8443/p?q=1")
        s.require("target.com")
        s.require("target.com:443")
        s.require("https://target.com./")

    def test_out_of_scope_domain_blocked(self):
        s = _scope(domains=["target.com"])
        with mock.patch(
            "camty.guardrail.scope.socket.getaddrinfo",
            return_value=_fake_resolve("93.184.216.34"),
        ):
            with self.assertRaises(ScopeError):
                s.require("http://evil.com/")

    def test_domain_resolves_into_ip_whitelist(self):
        """白名单外域名解析后按 IP 白名单校验（保留既有语义）。"""
        s = _scope(ips=["10.10.10.10"])
        with mock.patch(
            "camty.guardrail.scope.socket.getaddrinfo",
            return_value=_fake_resolve("10.10.10.10"),
        ) as gai:
            s.require("http://another-target.com/")
            gai.assert_called_once()


class TestIpv6Handling(unittest.TestCase):
    def test_single_ipv6_ip_does_not_crash(self):
        s = _scope(ips=["::1"])  # 旧代码硬编码 /32 直接 ValueError
        s.require("http://[::1]:8080/")
        s.require("[::1]:8080")
        s.require("[::1]")  # 带括号裸形式

    def test_ipv6_cidr_authorized(self):
        s = _scope(cidrs=["::1/128"])
        s.require("http://[::1]:8080/")

    def test_ipv6_literal_out_of_scope(self):
        s = _scope(cidrs=["192.168.100.0/24"])
        with self.assertRaises(ScopeError):
            s.require("http://[::1]:8080/")

    def test_single_ipv4_ip_still_equivalent_to_slash_32(self):
        s = _scope(ips=["10.10.10.10"])
        s.require_cidr("10.10.10.10/32")
        with self.assertRaises(ScopeError):
            s.require_cidr("10.10.10.11/32")


class TestEmptyAndMalformed(unittest.TestCase):
    def test_empty_host_rejected(self):
        s = _scope(cidrs=["192.168.100.0/24"])
        with self.assertRaises(ScopeError):
            s.require("")

    def test_bare_scheme_rejected(self):
        s = _scope(cidrs=["192.168.100.0/24"])
        with self.assertRaises(ScopeError):
            s.require("http://")


if __name__ == "__main__":
    unittest.main()
