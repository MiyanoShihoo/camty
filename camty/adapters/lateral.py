"""横向移动适配器（impacket 远程执行引擎：wmiexec/atexec/dcomexec/smbexec/psexec）。

engine 参数选引擎，全部单主机命令执行；operator 确认后运行。
"""

from __future__ import annotations

from camty.adapters.base import RunContext, ToolAdapter, ToolResult
from camty.adapters.impacket import run_impacket
from camty.tools import find_tool

ENGINES = ("wmiexec", "atexec", "dcomexec", "smbexec", "psexec")


class LateralMoveAdapter(ToolAdapter):
    name = "lateral-move"
    tool_name = "wmiexec.py"
    description = "以已验证凭据在单台范围内主机上执行命令（impacket 引擎可选：wmiexec/atexec/dcomexec/smbexec/psexec）。需 operator 确认。"
    requires_confirm = True
    requires_finding = True

    def tool_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "domain_user": {"type": "string", "description": "domain\\user"},
                "domain_pass": {"type": "string"},
                "command": {"type": "string", "description": "要执行的命令"},
                "engine": {"type": "string", "enum": list(ENGINES), "default": "wmiexec",
                           "description": "远程执行引擎（默认 wmiexec）"},
                "finding_id": {"type": "string", "description": "台账 verified finding ID（利用门控）"},
            },
            "required": ["host", "domain_user", "domain_pass", "command", "finding_id"],
        }

    def binary_for(self, engine: str) -> str:
        script = find_tool(f"{engine}.py")
        if not script:
            raise RuntimeError(f"引擎脚本未安装: {engine}.py")
        return script

    def run(self, args: dict, ctx: RunContext) -> ToolResult:
        host = str(args["host"]).strip()
        ctx.scope.require(host)
        engine = str(args.get("engine", "wmiexec"))
        if engine not in ENGINES:
            raise RuntimeError(f"未知引擎 {engine}，可选: {', '.join(ENGINES)}")
        script = self.binary_for(engine)
        target = f"{args['domain_user']}:{args['domain_pass']}@{host}"
        code, output = run_impacket(script, [target, args["command"]], timeout=600)
        evidence = ctx.save_evidence(self.name, output)
        ctx.audit.record(
            self.name,
            {"host": host, "user": args["domain_user"], "command": args["command"],
             "engine": engine, "finding_id": args.get("finding_id")},
            ok=code == 0,
        )
        return ToolResult(
            summary=f"{host} 命令执行{'成功' if code == 0 else '失败'}（{engine}，exit={code}）",
            data={"exec_output": output[:4000], "exec_host": host, "engine": engine},
            evidence=evidence,
        )
