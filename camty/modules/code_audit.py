"""白盒源码审计：多语言危险模式静态扫描（Go/Python/JS/Java/PHP）。

模式级审计（不做数据流分析）：SQL 拼接、命令执行、硬编码凭据、弱加密、
路径穿越、SSRF 近邻启发（用户输入源与网络/文件/命令 sink 同函数）。
产出结构化 finding（file:line:rule:severity:snippet）供台账。
"""

from __future__ import annotations

import re
from pathlib import Path

SKIP_DIRS = {"node_modules", "vendor", "test", "tests", "__pycache__", ".git", "dist", "build"}
SKIP_SUFFIX = ("_test.go", "_test.py", ".test.js", ".spec.js", ".min.js")  # 测试/压缩文件：假凭据与低价值
MAX_LINE = 600  # 超长行（压缩产物）跳过

# (rule, severity, 语言过滤, 正则, 说明)
RULES: list[tuple[str, str, tuple[str, ...], re.Pattern, str]] = [
    ("sql-concat", "high", ("go",),
     re.compile(r'fmt\.Sprintf\(\s*[f"](?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"]*(?:%s|%v|%d)'),
     "SQL 语句以 Sprintf 拼接参数，疑似注入（大小写敏感：真实拼接用全大写关键字）"),
    ("sql-concat", "high", ("py",),
     re.compile(r'(?:execute|executemany|cursor\.\w+)\(\s*(?:f["\']|[\"\'][^"\']*["\']\s*[%+])', re.I),
     "SQL 与变量拼接/f-string 传入执行"),
    ("sql-concat", "high", ("js", "java",),
     re.compile(r'(?:query|execute)\(\s*[`f"`\']\s*(?:SELECT|INSERT|UPDATE|DELETE)[^`"\']*(?:\$\{|\+)', re.I),
     "SQL 模板字符串/拼接执行"),
    ("sql-concat", "high", ("php",),
     re.compile(r'\$(?:sql|query)\s*=\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*\.\s*\$', re.I),
     "PHP SQL 字符串拼接"),
    ("cmd-exec", "high", ("go",),
     re.compile(r'exec\.Command(?:Context)?\('),
     "外部命令执行点"),
    ("py-eval", "critical", ("py",),
     re.compile(r'\b(?:eval|exec)\(\s*(?!["\'])'),
     "eval/exec 动态执行非字面量"),
    ("cmd-exec", "high", ("js",),
     re.compile(r'child_process\.(?:exec|execSync)\('),
     "Node 命令执行"),
    ("cmd-exec", "high", ("php",),
     re.compile(r'\b(?:system|shell_exec|passthru|popen|proc_open)\s*\('),
     "PHP 命令执行函数"),
    ("hardcoded-cred", "high", ("go", "py", "js", "java", "php"),
     re.compile(r"\b(?:password|passwd|secret|apikey|api_key|api-key|token)[a-z0-9_]*\s*:=\s*[\"'][^\"'\s$]{6,}[\"']"
                r"|\b(?:password|passwd|secret|apikey|api_key|api-key|token)[a-z0-9_]*\s*=[^=!<>]=?\s*[\"'][^\"'\s$]{6,}[\"']"),
     "疑似硬编码凭据（小写变量赋值；导出常量与比较语句已排除，宁缺毋滥）"),
    ("weak-crypto", "medium", ("go", "py", "js", "php"),
     re.compile(r'\b(?:md5|sha1)\s*\(\s*(?:password|passwd|pass|pwd)', re.I),
     "弱哈希用于口令"),
    ("weak-random", "medium", ("go", "py",),
     re.compile(r'\b(?:math\.rand|random\.random|random\.randint)\b[^\n]*(?:token|secret|key|session|password)', re.I),
     "非安全随机数用于凭据/会话"),
    ("path-traversal", "high", ("go",),
     re.compile(r'filepath\.Join\([^\n]*(?:r\.FormValue|r\.URL\.Query\(\)\.Get|c\.Query|c\.Param)', re.I),
     "用户输入直连文件路径（疑似穿越）"),
    ("path-traversal", "high", ("py",),
     re.compile(r'(?:open|send_file|send_from_directory)\([^\n]*(?:request\.args|request\.form|request\.json|request\.data)', re.I),
     "用户输入直连文件打开"),
    ("ssrf-sink", "medium", ("go",),
     re.compile(r'http\.(?:Get|Post)\([^\n]*(?:r\.FormValue|r\.URL\.Query|c\.Query|c\.Param)', re.I),
     "用户输入直接作为请求 URL（SSRF 面）"),
    ("ssrf-sink", "medium", ("py",),
     re.compile(r'requests\.\w+\([^\n]*(?:request\.args|request\.json|request\.form|request\.data)', re.I),
     "用户输入直接作为请求 URL（SSRF 面）"),
    ("ssrf-sink", "medium", ("js",),
     re.compile(r'(?:axios|fetch|got|request)\([^\n]*(?:req\.(?:query|body|params))', re.I),
     "用户输入直接作为请求 URL（SSRF 面）"),
    ("auth-bypass", "medium", ("js",),
     re.compile(r'app\.(?:get|post|put|delete|use)\([^)]*["\'][^"\']*(?:admin|internal|debug|private)[^"\']*["\'][^)]*\)[^\n]*(?<!authware)',
     re.I),
     "admin/internal 路由定义（人工确认鉴权中间件覆盖）"),
]

LANG_BY_EXT = {".go": "go", ".py": "py", ".js": "js", ".mjs": "js",
               ".java": "java", ".php": "php"}
# .ts/.tsx 排除：前端翻译文件与组件代码的安全模式误报率极高（i18n 键名/文案），
# 价值不成比例——前端安全测试由 browser/js-recon 黑盒路径覆盖。


def scan_file(path: Path, lang: str, max_per_rule: int = 20) -> list[dict]:
    """单文件扫描：逐规则逐行匹配，单规则单文件封顶。"""
    findings: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    lines = text.splitlines()
    per_rule: dict[str, int] = {}
    for rule, severity, langs, pattern, desc in RULES:
        if lang not in langs:
            continue
        compiled_line_re = re.compile(pattern.pattern, pattern.flags | re.M) if not pattern.flags & re.M else pattern
        for m in compiled_line_re.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            line = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            if len(line) > MAX_LINE:
                continue
            if per_rule.get(rule, 0) >= max_per_rule:
                break
            # 后处理降级：构建工具命令（go build/git/npm）是开发辅助非攻击面
            if rule == "cmd-exec" and lang == "go" and re.search(
                    r'exec\.Command(?:Context)?\(\s*"(go|git|python3?|node|npm|make|cargo|docker|powershell)"',
                    line):
                severity = "medium"
            per_rule[rule] = per_rule.get(rule, 0) + 1
            findings.append({
                "rule": rule,
                "severity": severity,
                "file": str(path),
                "line": line_no,
                "snippet": line.strip()[:160],
                "detail": desc,
            })
    return findings


def scan_tree(root: str | Path, max_files: int = 4000) -> dict:
    """递归扫描源码树，汇总去重（同文件同行同规则只留一条）。"""
    root_path = Path(root)
    if root_path.is_file():
        ext = root_path.suffix.lower()
        if ext not in LANG_BY_EXT:
            return {"root": str(root), "files": 0, "findings": []}
        findings = scan_file(root_path, LANG_BY_EXT[ext])
        return {"root": str(root), "files": 1, "findings": findings}
    findings, seen, files = [], set(), 0
    for path in sorted(root_path.rglob("*")):
        if files >= max_files:
            break
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.endswith(SKIP_SUFFIX):
            continue
        lang = LANG_BY_EXT.get(path.suffix.lower())
        if not lang:
            continue
        files += 1
        for f in scan_file(path, lang):
            key = (f["file"], f["line"], f["rule"])
            if key not in seen:
                seen.add(key)
                findings.append(f)
    severity_rank = {"critical": 0, "high": 1, "medium": 2}
    findings.sort(key=lambda f: (severity_rank.get(f["severity"], 9), f["file"], f["line"]))
    return {"root": str(root), "files": files, "findings": findings}
