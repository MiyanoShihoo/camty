"""mail-code 适配器：IMAP 收取验证码邮件（注册/验证流程通用件）。

支持 QQ/163/Gmail 等任意 IMAP 服务商（QQ 用授权码非登录密码）。
实战沉淀自 onyx-ai 交战（scripts/onyx_register_v2.py 手写流程工具化）。
"""

from __future__ import annotations

import imaplib
import json
import re
import time
from email.header import decode_header
from email.utils import parseaddr

from camty.adapters.base import RunContext, ToolAdapter, ToolResult

DEFAULT_HOSTS = {
    "qq.com": "imap.qq.com",
    "163.com": "imap.163.com",
    "126.com": "imap.126.com",
    "gmail.com": "imap.gmail.com",
    "outlook.com": "outlook.office365.com",
    "hotmail.com": "outlook.office365.com",
    "foxmail.com": "imap.qq.com",
}

DEFAULT_SUBJECT_KEYWORDS = ("验证", "verification", "verify", "code", "您的", "动态密码")


def _host_for(email: str, override: str | None) -> str:
    if override:
        return override
    domain = email.rsplit("@", 1)[-1].lower()
    return DEFAULT_HOSTS.get(domain, f"imap.{domain}")


def _decode_part(raw: str) -> str:
    out = []
    for text, enc in decode_header(raw):
        if isinstance(text, bytes):
            out.append(text.decode(enc or "utf-8", "replace"))
        else:
            out.append(text)
    return "".join(out)


def _read_code(mail, email: str, password: str, keywords: tuple[str, ...],
               code_pattern: str, window: int, poll_sec: float) -> dict | None:
    mail.login(email, password)
    deadline = time.time() + window
    while time.time() < deadline:
        mail.select("INBOX")
        _, data = mail.search(None, "ALL")
        ids = data[0].split()
        for mid in reversed(ids[-12:]):
            _, msg_data = mail.fetch(mid, "(BODY.PEEK[])")
            raw = msg_data[0][1].decode("utf-8", "replace")
            import email as email_lib

            msg = email_lib.message_from_string(raw)
            subject = _decode_part(msg.get("Subject", ""))
            sender = parseaddr(msg.get("From", ""))[1]
            haystack = (subject + " " + sender + " " + raw).lower()
            if not any(kw.lower() in haystack for kw in keywords):
                continue
            codes = re.findall(code_pattern, raw)
            if codes:
                mail.logout()
                return {"code": codes[-1], "subject": subject[:120], "from": sender}
        time.sleep(poll_sec)
    mail.logout()
    return None


class MailCodeAdapter(ToolAdapter):
    name = "mail-code"
    description = (
        "IMAP 收取验证码邮件：轮询收件箱按主题关键词匹配，提取验证码。"
        "QQ 邮箱用授权码（非登录密码）。返回 {code, subject, from}。"
    )

    def available(self) -> bool:
        return True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "email": {"type": "string", "description": "收件邮箱（如 404332935@qq.com）"},
                "password": {"type": "string", "description": "邮箱密码或 IMAP 授权码"},
                "host": {"type": "string", "description": "IMAP 主机（缺省按邮箱域自动推断）"},
                "port": {"type": "integer", "default": 993},
                "subject_keywords": {"type": "array", "items": {"type": "string"},
                                      "description": "主题/发件人关键词（缺省通用验证码词表）"},
                "code_pattern": {"type": "string", "default": r"\b[0-9]{6}\b",
                                  "description": "验证码正则（缺省 6 位数字）"},
                "timeout_seconds": {"type": "integer", "default": 120},
            },
            "required": ["email", "password"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        email = str(args["email"]).strip()
        password = str(args["password"])
        host = _host_for(email, args.get("host") or None)
        port = int(args.get("port", 993))
        keywords = tuple(args.get("subject_keywords") or DEFAULT_SUBJECT_KEYWORDS)
        code_pattern = str(args.get("code_pattern", r"\b[0-9]{6}\b"))
        timeout = int(args.get("timeout_seconds", 120))
        try:
            mail = imaplib.IMAP4_SSL(host, port)
            hit = _read_code(mail, email, password, keywords, code_pattern,
                             window=timeout, poll_sec=5.0)
        except imaplib.IMAP4.error as exc:
            return ToolResult(summary=f"IMAP 认证失败: {exc}", data={})
        except OSError as exc:
            return ToolResult(summary=f"IMAP 连接失败（{host}:{port}）: {exc}", data={})
        if hit is None:
            return ToolResult(summary=f"{timeout}s 内未收到匹配验证码邮件", data={})
        evidence = ctx.save_evidence(self.name, json.dumps(hit, ensure_ascii=False))
        ctx.audit.record(self.name, {"email": email, "host": host}, ok=True,
                         note=f"code {hit['code']} from {hit['from'][:40]}")
        return ToolResult(
            summary=f"验证码 {hit['code']}（来自 {hit['from']}）",
            data={"code": hit["code"], "subject": hit["subject"], "from": hit["from"]},
            evidence=evidence,
        )
