"""IM 推送：新发现推送到 webhook/飞书/钉钉/企微/Telegram。

交战配置:
  notify:
    - type: feishu
      url: https://open.feishu.cn/open-apis/bot/v2/hook/xxx
      min_severity: high        # 只推 high/critical，缺省 high
推失败不抛错（打印 + 返回 False），交战主流程不受影响。
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _rank(severity: str) -> int:
    return SEVERITY_RANK.get(str(severity).lower(), 4)


def _format_text(eng_name: str, findings: list[dict]) -> str:
    lines = [f"[Camty] 交战 {eng_name} 新发现 {len(findings)} 项："]
    for f in findings[:20]:
        chain = f" ← {','.join(f.get('derived_from') or [])}" if f.get("derived_from") else ""
        lines.append(
            f"[{f.get('severity', 'info').upper()}] {f.get('target', '')} "
            f"{f.get('detail', '')}{chain}"
            f"{'（已验证）' if f.get('verified') else ''}"
        )
    return "\n".join(lines)


def _payload(channel: str, text: str) -> tuple[str, dict] | None:
    """返回 (url, json_body)；GET 型（telegram）返回 (url, {})。"""
    if channel == "feishu":
        return None, {"msg_type": "text", "content": {"text": text}}
    if channel == "dingtalk":
        return None, {"msgtype": "text", "text": {"content": text}}
    if channel == "wecom":
        return None, {"msgtype": "text", "text": {"content": text}}
    if channel == "telegram":
        return text, {}
    return None, None  # webhook：POST 纯文本


def push_findings(eng, findings: list[dict]) -> list[tuple[str, bool, str]]:
    """按交战 notify 配置推送。返回 [(渠道, 是否成功, 说明)]。"""
    channels = (eng.cfg.get("notify") or [])
    if not channels or not findings:
        return []
    results = []
    for ch in channels:
        ctype = str(ch.get("type", "webhook")).lower()
        url = str(ch.get("url", "")).strip()
        if not url:
            results.append((ctype, False, "缺 url"))
            continue
        min_rank = _rank(ch.get("min_severity", "high"))
        selected = [f for f in findings if _rank(f.get("severity", "info")) <= min_rank]
        if not selected:
            results.append((ctype, True, "无满足严重度的新发现"))
            continue
        text = _format_text(eng.name, selected)
        try:
            if ctype == "telegram":
                query = urllib.parse.urlencode({"chat_id": ch.get("chat_id", ""), "text": text})
                req = urllib.request.Request(f"{url}?{query}")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp.read()
            else:
                _, body = _payload(ctype, text)
                data = json.dumps(body if body is not None else text, ensure_ascii=False).encode("utf-8")
                headers = {"Content-Type": "application/json" if body is not None
                           else "text/plain; charset=utf-8"}
                req = urllib.request.Request(url, data=data, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp.read()
            results.append((ctype, True, f"推送 {len(selected)} 项"))
            print(f"[notify] {ctype}: 已推送 {len(selected)} 项发现")
        except Exception as exc:  # noqa: BLE001 - 推送失败不拖垮交战
            results.append((ctype, False, str(exc)[:120]))
            print(f"[notify] {ctype}: 推送失败 {exc}")
    return results
