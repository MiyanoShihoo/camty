"""Camty 面板截图：启动 FastAPI → playwright 七页签截图。

输出到 docs/screenshots/（文章配图用）。
跑法：python scripts/take_screenshots.py
"""

import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import camty  # noqa: F401
from camty.adapters.browser import _playwright, _launch_args

HERE = Path(__file__).resolve().parent.parent
OUT = HERE / "docs" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)

# 1) 启动 FastAPI
server = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "camty.api.app:app", "--port", "8090"],
    cwd=str(HERE), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)
print("[server] FastAPI 已启动 :8090")

try:
    with _playwright() as p:
        args, ignore = _launch_args(False)  # 不带 stealth（截图用）
        browser = p.chromium.launch(headless=True, args=args,
                                     ignore_default_args=ignore)
        ctx = browser.new_context(viewport={"width": 1600, "height": 1000})
        page = ctx.new_page()

        # 2) 依次截图七页签
        page.goto("http://127.0.0.1:8090/", timeout=15000)
        page.wait_for_timeout(3000)

        # 仪表盘（默认页签，选 wbssr 交战——数据最多）
        page.select_option("#engSel", "wbssr")
        page.wait_for_timeout(4000)
        page.screenshot(path=str(OUT / "01-dashboard.png"), full_page=False)
        print("[截图] dashboard ✓")

        # 台账
        page.click("nav button[data-tab='ledger']")
        page.wait_for_timeout(2000)
        page.screenshot(path=str(OUT / "02-ledger.png"), full_page=False)
        print("[截图] ledger ✓")

        # 资产图（力导向）
        page.click("nav button[data-tab='assets']")
        page.wait_for_timeout(5000)  # 等力导向布局稳定
        page.screenshot(path=str(OUT / "03-assets-fdg.png"), full_page=False)
        print("[截图] assets-fdg ✓")

        # 探索图
        page.click("nav button[data-tab='graph']")
        page.wait_for_timeout(2000)
        page.screenshot(path=str(OUT / "04-graph.png"), full_page=False)
        print("[截图] graph ✓")

        # 攻击链
        page.click("nav button[data-tab='todo']")
        page.wait_for_timeout(2000)
        page.screenshot(path=str(OUT / "05-todolist.png"), full_page=False)
        print("[截图] todolist ✓")

        # 流量
        page.click("nav button[data-tab='traffic']")
        page.wait_for_timeout(2000)
        page.screenshot(path=str(OUT / "06-traffic.png"), full_page=False)
        print("[截图] traffic ✓")

        # 过程
        page.click("nav button[data-tab='activity']")
        page.wait_for_timeout(2000)
        page.screenshot(path=str(OUT / "07-activity.png"), full_page=False)
        print("[截图] activity ✓")

        # 3) 全页截图（README banner 用）
        page.click("nav button[data-tab='dash']")
        page.wait_for_timeout(2000)
        page.screenshot(path=str(OUT / "08-dashboard-full.png"), full_page=True)
        print("[截图] full-page ✓")

        browser.close()
finally:
    server.terminate()
    print("[server] 已停止")

# 列出产出
for f in sorted(OUT.glob("*.png")):
    print(f"  {f.name}  {f.stat().st_size // 1024}KB")
