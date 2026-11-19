"""hashcat 破解适配器（hashcrack）：哈希 → 明文凭据 → 台账 verified findings。

模式自动识别（JWT/NTLM/NetNTLM/Kerberoast/MD5/bcrypt/sha512crypt...），
默认 rockyou + best64 规则，GPU 优先。破解出明文即产出
valid-credential（verified）——AD 链闭环（kerberoast→破解→psexec）。
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from camty.adapters.base import RunContext, ToolAdapter, ToolResult

# 路径三分类（无个人硬编码）：
# 1) hashcat 二进制：CAMTY_HASHCAT 显式 → find_tool（CAMTY_TOOLS_DIR+PATH）
# 2) best64.rule：hashcat 发行版自带，从二进制所在目录推导 <hashcat>/rules/best64.rule
# 3) rockyou 词表：hashcat 不带（单独分发），CAMTY_WORDLIST 显式配置，缺失时清晰报错

MODES = {
    "jwt": (16500, r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"),
    # 纯 32hex 默认按 md5(0) 处理；AD 场景（secretsdump 产出）显式 mode: ntlm
    "md5": (0, r"^[a-f0-9]{32}$"),
    "ntlm": (1000, r"^[a-f0-9]{32}$"),
    "netntlm": (5600, r".*::.*:.*:.*:.*"),
    "kerberoast": (13100, r"\$krb5tgs\$.*"),
    "asreproast": (18200, r"\$krb5asrep\$.*"),
    "md5": (0, r"^[a-f0-9]{32}$"),
    "sha1": (100, r"^[a-f0-9]{40}$"),
    "sha256": (1400, r"^[a-f0-9]{64}$"),
    "bcrypt": (3200, r"^\$2[aby]\$.*"),
    "sha512crypt": (1800, r"^\$6\$.*"),
    "mysql-sha1": (300, r"^\*[A-F0-9]{40}$"),
}

# ntlm 与 md5 同格式（1000 vs 0 都试）——ntlm 优先按上下文


def detect_mode(hash_line: str) -> tuple[int, str] | None:
    for name, (mode, pattern) in MODES.items():
        if re.search(pattern, hash_line.strip(), re.I if name == "ntlm" else 0):
            return mode, name
    return None


class HashcrackAdapter(ToolAdapter):
    name = "hashcrack"
    description = (
        "哈希破解（hashcat GPU）：JWT/NTLM/NetNTLM/Kerberoast/ASREP/MD5/bcrypt 等，"
        "模式自动识别，默认 rockyou+best64。破解出明文产出 valid-credential findings。"
        "破解类动作，需 operator 确认。"
    )
    requires_confirm = True

    def binary(self) -> str:
        import os

        explicit = os.environ.get("CAMTY_HASHCAT")
        if explicit and Path(explicit).is_file():
            return explicit
        from camty.tools import find_tool

        resolved = find_tool("hashcat") or find_tool("hashcat.exe")
        return resolved or ""

    def available(self) -> bool:
        return bool(self.binary()) and Path(self.binary()).is_file()

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "hashes": {
                    "oneOf": [{"type": "string",
                               "description": "哈希（多行）或 hash 文件路径"},
                              {"type": "array", "items": {}}],
                    "description": "待破解哈希（kerberoast/NTLM/JWT...）",
                },
                "mode": {"type": "string",
                          "description": "强制模式（缺省自动识别）："
                                         "jwt/ntlm/netntlm/kerberoast/asreproast/md5/bcrypt"},
                "wordlist": {"type": "string",
                              "description": "字典路径（缺省读环境变量 CAMTY_WORDLIST；hashcat 不自带词表）"},
                "rules": {"type": "string",
                           "description": "规则文件（缺省用 hashcat 自带 rules/best64.rule，置空禁用）"},
                "max_runtime_seconds": {"type": "integer", "default": 1800},
            },
            "required": ["hashes"],
        }

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        import os

        raw = args.get("hashes", "")
        wl = str(args.get("wordlist") or os.environ.get("CAMTY_WORDLIST", ""))
        rules = str(args.get("rules") or "")  # 缺省：hashcat 自带 best64（下方推导）
        runtime = int(args.get("max_runtime_seconds", 1800))
        if Path(str(raw)).is_file():
            lines = Path(str(raw)).read_text(encoding="utf-8",
                                              errors="replace").splitlines()
        elif isinstance(raw, list):
            lines = [str(x) for x in raw]
        else:
            lines = [l.strip() for l in str(raw).splitlines() if l.strip()]
        lines = [l for l in lines if l and not l.startswith("#")]
        if not lines:
            return ToolResult(summary="无哈希输入", data={"findings": []})
        if not Path(wl).is_file():
            return ToolResult(
                summary=(f"字典未配置或不存在: {wl or '(空)'}——rockyou 不随 hashcat 分发："
                         "设环境变量 CAMTY_WORDLIST=<字典路径> 或传 args.wordlist"),
                data={})

        forced = args.get("mode")
        if forced and forced.lower() in MODES:
            mode = MODES[forced.lower()][0]
            mode_name = forced.lower()
        else:
            detected = detect_mode(lines[0])
            if detected is None:
                return ToolResult(summary=f"无法识别哈希格式（首行 {lines[0][:40]!r}），显式传 mode",
                                  data={"supported": list(MODES)})
            mode, mode_name = detected

        import tempfile

        workdir = Path(tempfile.mkdtemp(prefix="hashcrack-"))
        hash_file = workdir / "hashes.txt"
        out_file = workdir / "cracked.txt"
        hash_file.write_text("\n".join(lines), encoding="utf-8")
        if not rules:
            derived = Path(self.binary()).parent / "rules" / "best64.rule"
            rules = str(derived) if derived.is_file() else ""
        cmd = [self.binary(), "-m", str(mode), "-a", "0", "--potfile-disable",
               "-o", str(out_file), str(hash_file), wl, "--force"]
        if rules and Path(rules).is_file():
            cmd += ["-r", rules]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=runtime + 60,
                              encoding="utf-8", errors="replace")
        cracked = []
        if out_file.is_file():
            for line in out_file.read_text(encoding="utf-8",
                                           errors="replace").splitlines():
                if ":" in line:
                    digest, _, plain = line.partition(":")
                    cracked.append({"hash": digest[:48], "password": plain,
                                    "mode": mode_name})
        findings = [
            {"template": "cracked-credential", "severity": "high",
             "url": c["hash"][:24], "detail": f"{mode_name} 破解: {c['password']}",
             "verified": True}
            for c in cracked
        ]
        status_match = re.search(r"Recovered\.+\s*(\S+)", proc.stdout or "")
        recovered = status_match.group(1) if status_match else f"{len(cracked)}/{len(lines)}"
        evidence = ctx.save_evidence(self.name, json.dumps({
            "mode": mode_name, "n_hashes": len(lines),
            "recovered": recovered, "cracked": cracked,
            "hashcat_tail": (proc.stdout or "")[-600:]}, ensure_ascii=False, indent=1))
        ctx.audit.record(self.name, {"mode": mode_name, "n": len(lines)},
                         ok=len(cracked) > 0, note=f"recovered {recovered}")
        return ToolResult(
            summary=f"{mode_name} × {len(lines)} 条 → 破解 {len(cracked)}（{recovered}）",
            data={"cracked": cracked, "recovered": recovered,
                  "mode": mode_name, "findings": findings},
            evidence=evidence,
        )
