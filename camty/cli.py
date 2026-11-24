"""CLI 入口：run / auto / engine（多 agent）/ keys / report / audit。"""

from __future__ import annotations

import argparse
import os
from dataclasses import asdict
from pathlib import Path

from camty import banner
from camty.agent.engine import Engine
from camty.agent.orchestrator import Orchestrator
from camty.agent.runner import AgentRunner, DeterministicRunner
from camty.agent.state import Engagement
from camty.llm.router import KINDS, LLMRouter, ROLES
from camty.notify import push_findings
from camty.report import render_compare_html, write_docx, write_report, write_src_md
from camty.traffic import TrafficProxy


def _apply_vars(eng: Engagement, var_list: list[str]) -> None:
    for kv in var_list:
        key, _, value = kv.partition("=")
        if not key or not value:
            raise SystemExit(f"--var 格式应为 key=value，收到: {kv}")
        eng.context[key.strip()] = value


def _start_traffic(eng: Engagement, port: int) -> TrafficProxy:
    """启动 MITM 记录代理并接管环境代理（urllib/Go 工具/浏览器全走留痕通道）。"""
    cfg = eng.cfg.get("traffic") or {}
    proxy = TrafficProxy(eng, port=int(cfg.get("port", port)),
                         enforce_scope=bool(cfg.get("enforce_scope", True)))
    url = proxy.start()
    for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        os.environ[key] = url
    eng.context["proxy"] = url
    print(f"[traffic] MITM 记录代理已启动 {url}（CA: {eng.dir / 'traffic' / 'ca' / 'ca.crt'}）")
    return proxy


def _stop_traffic(proxy: TrafficProxy | None, eng: Engagement) -> None:
    if proxy is None:
        return
    proxy.stop()
    for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        os.environ.pop(key, None)
    stats = proxy.stats()
    print(f"[traffic] 代理已停止：{stats['requests']} 笔请求，"
          f"主机 {len(stats['hosts'])}（{eng.dir / 'traffic' / 'traffic.jsonl'}）")


def _notify(eng: Engagement) -> None:
    push_findings(eng, [asdict(f) for f in eng.ledger.findings])


def cmd_run(args: argparse.Namespace) -> None:
    eng = Engagement(args.engagement)
    _apply_vars(eng, args.var)
    proxy = _start_traffic(eng, args.traffic_port) if args.traffic else None
    try:
        if args.agent:
            AgentRunner(eng, LLMRouter()).run(args.phase)
        else:
            DeterministicRunner(eng).run(args.phase, dry_run=args.dry_run, rerun=args.rerun)
        eng.save_state()
    finally:
        _stop_traffic(proxy, eng)
    _notify(eng)


def cmd_report(args: argparse.Namespace) -> None:
    eng = Engagement(args.engagement)
    if args.baseline:
        baseline = Engagement(args.baseline)
        out = eng.dir / "compare-report.html"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_compare_html(baseline, eng), encoding="utf-8")
        print(f"复测对比报告: {out}")
    elif args.format == "docx":
        print(f"报告: {write_docx(eng)}")
    elif args.format == "src":
        print(f"SRC 报告: {write_src_md(eng)}")
    else:
        print(f"报告: {write_report(eng)}")


def cmd_auto(args: argparse.Namespace) -> None:
    eng = Engagement(args.engagement)
    _apply_vars(eng, args.var)
    proxy = _start_traffic(eng, args.traffic_port) if args.traffic else None
    ok = False
    try:
        router = LLMRouter() if args.agent else None
        ok = Orchestrator(eng, router=router).run(
            dry_run=args.dry_run, rerun=args.rerun, agent=args.agent, plan=args.plan
        )
    finally:
        _stop_traffic(proxy, eng)
    _notify(eng)
    if not ok:
        raise SystemExit(2)  # 门控停止，非崩溃：退出码区分给 CI/脚本用


def cmd_multi(args: argparse.Namespace) -> None:
    """多目标并行：每交战一个子进程跑 auto，汇总退出码。"""
    import subprocess
    import sys as _sys

    procs = {}
    for yml in args.engagements:
        cmd = [_sys.executable, "-m", "camty", "--no-banner", "auto", yml]
        cmd += ["--agent"] if args.agent else []
        cmd += ["--plan"] if args.plan else []
        cmd += ["--dry-run"] if args.dry_run else []
        procs[yml] = subprocess.Popen(cmd)
    results = {yml: p.wait() for yml, p in procs.items()}
    ok = [y for y, rc in results.items() if rc == 0]
    bad = [y for y, rc in results.items() if rc != 0]
    print(f"[multi] 成功 {len(ok)}：{ok}")
    if bad:
        print(f"[multi] 失败 {len(bad)}（退出码非零）：{bad}")
        raise SystemExit(1)


def cmd_engine(args: argparse.Namespace) -> None:
    eng = Engagement(args.engagement)
    _apply_vars(eng, args.var)
    router = LLMRouter() if args.agent else None
    proxy = _start_traffic(eng, args.traffic_port) if args.traffic else None
    try:
        ok = Engine(eng, router=router, n_workers=args.workers,
                     max_total_steps=args.budget).run()
        eng.save_state()
    finally:
        _stop_traffic(proxy, eng)
    _notify(eng)
    if not ok:
        raise SystemExit(2)


def cmd_repeater(args: argparse.Namespace) -> None:
    """交互式请求重放守护（camty.repeater）。"""
    from camty.repeater import main as repeater_main

    repeater_main(args.engagement, port=args.port)


def cmd_audit(args: argparse.Namespace) -> None:
    eng = Engagement(args.engagement)
    entries = eng.audit.entries()
    ok, bad = eng.audit.verify()
    if ok:
        print(f"审计链完整：{len(entries)} 条记录（{eng.audit.path}）")
    else:
        print(f"审计链断裂：第 {bad} 行被修改/删除/插入（{eng.audit.path}）")
        raise SystemExit(1)


def cmd_retest(args: argparse.Namespace) -> None:
    from camty.agent.retester import run_retest

    eng = Engagement(args.engagement)
    if args.history:
        for rec in eng.db.load_retests(args.finding):
            print(f"{rec['id']:4} {rec['created_ts']} [{rec['verdict']}] "
                  f"{rec['finding_id']}: {rec['summary'][:80]}"
                  + (f"（证据: {rec['evidence']}）" if rec["evidence"] else ""))
        return
    if not args.finding:
        raise SystemExit("复测需要 --finding <F-ID>（--history 模式可省略）")
    result = run_retest(eng, LLMRouter(), args.finding, note=args.note or "")
    print(f"复测结论 [{result['verdict']}]: {result['summary']}")
    if result["evidence"]:
        print(f"证据: {result['evidence']}")
    if result["verdict"] == "fixed":
        print(f"漏洞处置状态已置「已修复」: {result['finding_id']}")
    if result["verdict"] == "inconclusive":
        raise SystemExit(2)  # 未确认：退出码区分给 CI/脚本用


def cmd_ask(args: argparse.Namespace) -> None:
    """侧问：交战进行中向 agent 提问（只读快照问答，不干扰主流程）。"""
    from camty.agent.sidequestion import answer_question

    eng = Engagement(args.engagement)
    print(answer_question(eng, LLMRouter(), args.question))


def cmd_goals(args: argparse.Namespace) -> None:
    """自然语言目标分解：任务描述 → 交战配置（ARTEX goals 语义）。"""
    import json

    from camty.agent.goals import build_engagement, decompose, save_engagement

    decision = decompose(LLMRouter(), args.text)
    print(f"目标资产: root_domain={decision.get('root_domain') or '—'} "
          f"cidrs={decision.get('cidrs') or '—'} "
          f"额外域名={decision.get('extra_domains') or '—'}")
    for c in decision.get("constraints") or []:
        print(f"约束 [{c.get('type', 'deny')}] {c.get('rule', '')}")
    for g in decision.get("goals") or []:
        print(f"目标: {g.get('title', '')}（达成判定: {g.get('done_when', '')}）")
    cfg = build_engagement(decision)
    print(f"场景包: {cfg['pack']} | scope: {cfg['scope']}")
    if args.save:
        path = Path("engagements") / f"{cfg['name']}.yaml"
        out = save_engagement(decision, path)
        print(f"交战配置已保存: {out}")
        print(f"下一步: python -m camty auto {out} --dry-run")
    else:
        print("配置预览（--save 落盘）:")
        print(json.dumps(cfg, ensure_ascii=False, indent=2, default=str))


def cmd_keys(args: argparse.Namespace) -> None:
    router = LLMRouter()
    if args.action == "set":
        models = {}
        for role in ROLES:
            value = getattr(args, f"model_{role}", None)
            if value:
                models[role] = value
        if args.model_default:
            models["default"] = args.model_default
        router.set_provider(args.name, args.kind, args.base_url, args.api_key, models)
        print(f"已保存 provider: {args.name}（{args.kind} @ {args.base_url}）")
    elif args.action == "list":
        if not router.providers:
            print(
                "尚未配置 provider。示例:\n"
                "  # 官方 OpenAI（Responses 原生协议）\n"
                "  python -m camty keys set openai --kind responses --base-url https://api.openai.com/v1 "
                "--api-key sk-xxx --model-decide gpt-4.1\n"
                "  # 官方 Anthropic\n"
                "  python -m camty keys set claude --kind anthropic --base-url https://api.anthropic.com "
                "--api-key sk-xxx --model-decide claude-sonnet-4-20250514\n"
                "  # 第三方 OpenAI 兼容（DeepSeek/Qwen/Moonshot/OpenRouter…）\n"
                "  python -m camty keys set deepseek --kind openai --base-url https://api.deepseek.com/v1 "
                "--api-key sk-xxx --model-recon deepseek-chat --model-decide deepseek-reasoner\n"
                "  # 本地 Ollama（离线交战）\n"
                "  python -m camty keys set local --kind openai --base-url http://127.0.0.1:11434/v1 "
                "--api-key ollama --model-decide qwen2.5:14b\n"
                "密钥加密：设置 CAMTY_MASTER_KEY 环境变量后自动 fernet 加密（需 cryptography）"
            )
            return
        for name, cfg in router.providers.items():
            print(f"{name:12} {cfg.kind:10} {cfg.base_url}  key={cfg.masked_key()}  models={cfg.models}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="camty", description="Camty 红队交战工作台")
    parser.add_argument("--no-banner", action="store_true", help="不显示启动横幅")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="执行交战阶段")
    p_run.add_argument("engagement", help="交战配置 yaml 路径")
    p_run.add_argument("--phase", required=True, help="阶段 ID，如 recon / verify")
    p_run.add_argument("--agent", action="store_true", help="LLM Agent 模式（需先配置 API key）")
    p_run.add_argument("--dry-run", action="store_true", help="链路预演：只检查工具与参数，不执行")
    p_run.add_argument("--rerun", action="store_true", help="清空该阶段断点进度重跑")
    p_run.add_argument("--traffic", action="store_true",
                       help="启动 MITM 记录代理，全部工具流量留痕到 traffic/traffic.jsonl")
    p_run.add_argument("--traffic-port", type=int, default=8899, dest="traffic_port")
    p_run.add_argument("--var", action="append", default=[], metavar="KEY=VALUE",
                        help="注入上下文变量（可多次），如 --var domain_user=test\\a")
    p_run.set_defaults(func=cmd_run)

    p_rep = sub.add_parser("repeater", help="交互式请求重放守护：持久会话/CSRF 跟随/向量批测聚类")
    p_rep.add_argument("engagement", help="交战配置 yaml 路径")
    p_rep.add_argument("--port", type=int, default=8895, help="守护端口（默认 8895）")
    p_rep.set_defaults(func=cmd_repeater)

    p_multi = sub.add_parser(
        "multi", help="多目标并行：每交战一个子进程跑 auto（同参数），汇总结果")
    p_multi.add_argument("engagements", nargs="+", help="交战 yaml 列表")
    p_multi.add_argument("--agent", action="store_true")
    p_multi.add_argument("--plan", action="store_true")
    p_multi.add_argument("--dry-run", action="store_true")
    p_multi.set_defaults(func=cmd_multi)

    p_engine = sub.add_parser(
        "engine", help="多 agent 引擎：planner 生成意图 → N worker 并行执行 → 写回双图 → 重规划")
    p_engine.add_argument("engagement", help="交战配置 yaml 路径")
    p_engine.add_argument("--agent", action="store_true",
                           help="LLM 规划者（缺省用 pack plan: 段做确定性规划）")
    p_engine.add_argument("--workers", type=int, default=4, help="并行 worker 数（默认 4）")
    p_engine.add_argument("--budget", type=int, default=80, dest="budget",
                          help="总步数预算（默认 80）")
    p_engine.add_argument("--traffic", action="store_true", help="MITM 流量留痕")
    p_engine.add_argument("--traffic-port", type=int, default=8899, dest="traffic_port")
    p_engine.add_argument("--var", action="append", default=[], metavar="KEY=VALUE")
    p_engine.set_defaults(func=cmd_engine)

    p_auto = sub.add_parser("auto", help="全自动：按场景包顺序打完整场交战（阶段门控+断点续跑+自动报告）")
    p_auto.add_argument("engagement", help="交战配置 yaml 路径")
    p_auto.add_argument("--agent", action="store_true", help="阶段内由 LLM 决策工具调用（需 API key）")
    p_auto.add_argument("--plan", action="store_true",
                        help="攻击树规划模式：按 pack 的 plan: 依赖图动态选步（证据不足的分支自动剪枝）")
    p_auto.add_argument("--dry-run", action="store_true", help="预演：列出各阶段与门控，不执行")
    p_auto.add_argument("--rerun", action="store_true", help="清空所有阶段断点重跑")
    p_auto.add_argument("--traffic", action="store_true", help="MITM 流量留痕")
    p_auto.add_argument("--traffic-port", type=int, default=8899, dest="traffic_port")
    p_auto.add_argument("--var", action="append", default=[], metavar="KEY=VALUE",
                        help="注入上下文变量（可多次），如 --var domain_user=test\\a")
    p_auto.set_defaults(func=cmd_auto)

    p_report = sub.add_parser("report", help="生成交战报告；给出 baseline 时输出复测对比")
    p_report.add_argument("engagement", help="交战配置 yaml 路径")
    p_report.add_argument("baseline", nargs="?", help="基线交战 yaml（复测对比模式）")
    p_report.add_argument("--format", choices=["html", "docx", "src"], default="html",
                          help="报告格式（docx 需 python-docx；src=平台提交格式）")
    p_report.set_defaults(func=cmd_report)

    p_audit = sub.add_parser("audit", help="校验交战审计哈希链")
    p_audit.add_argument("engagement", help="交战配置 yaml 路径")
    p_audit.set_defaults(func=cmd_audit)

    p_retest = sub.add_parser("retest", help="漏洞复测：独立会话验证台账 finding 当前状态")
    p_retest.add_argument("engagement", help="交战配置 yaml 路径")
    p_retest.add_argument("--finding", help="台账 finding ID，如 F-001（--history 模式可省略）")
    p_retest.add_argument("--note", default="", help="本次复测的补充说明/测试条件")
    p_retest.add_argument("--history", action="store_true",
                          help="只看复测历史，不执行复测")
    p_retest.set_defaults(func=cmd_retest)

    p_goals = sub.add_parser("goals", help="自然语言目标分解：一句话任务 → 交战配置（需 LLM key）")
    p_goals.add_argument("text", help="任务描述，如「对 abc.example.net 做全面 web 渗透，不扫端口」")
    p_goals.add_argument("--save", action="store_true",
                         help="按分解结果落盘 engagements/<name>.yaml（默认只预览）")
    p_goals.set_defaults(func=cmd_goals)

    p_ask = sub.add_parser("ask", help="侧问：交战进行中向 agent 提问（只读快照问答，需 LLM key）")
    p_ask.add_argument("engagement", help="交战配置 yaml 路径")
    p_ask.add_argument("question", help="要问的问题，如「现在的台账里最严重的发现是什么」")
    p_ask.set_defaults(func=cmd_ask)

    p_keys = sub.add_parser("keys", help="LLM provider 管理")
    ks = p_keys.add_subparsers(dest="action", required=True)
    p_set = ks.add_parser("set", help="新增/更新 provider")
    p_set.add_argument("name")
    p_set.add_argument("--kind", default="openai", choices=list(KINDS),
                       help="协议：openai=Chat Completions（官方+全部第三方兼容），"
                            "responses=OpenAI Responses 原生，anthropic=Anthropic 原生")
    p_set.add_argument("--base-url", required=True,
                       help="官方 OpenAI: https://api.openai.com/v1；Anthropic: https://api.anthropic.com；"
                            "第三方: https://api.deepseek.com/v1 等；本地: http://127.0.0.1:11434/v1")
    p_set.add_argument("--api-key", default="", help="留空则读 CAMTY_<NAME>_API_KEY 环境变量")
    for role in ROLES:
        p_set.add_argument(f"--model-{role}", dest=f"model_{role}", help=f"{role} 角色使用的模型")
    p_set.add_argument("--model-default", dest="model_default", help="兜底模型")
    p_set.set_defaults(func=cmd_keys)
    p_list = ks.add_parser("list", help="查看已配置 provider")
    p_list.set_defaults(func=cmd_keys)

    args = parser.parse_args(argv)
    banner.show(args.no_banner)
    args.func(args)
