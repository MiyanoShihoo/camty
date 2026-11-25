"""tests 进程级状态隔离兜底（R3 测试隔离批次，autouse）。

背景：test_scope_enforcement 曾在设 http_proxy 后调用全局
urllib.request.urlopen——urlopen 首次调用会把当时的代理 env 焊进进程级
urllib.request._opener 缓存，事后 env pop 救不回来；Windows 因
proxy_bypass('127.0.0.1')=True 掩盖了问题，Linux/CI 上表现为连带红。

本 fixture 不替代各测试自己的恢复语义（saved/finally 恢复仍应保留），
只做进程级兜底三件事：
  1) 每个测试开工前快照完整 env；
  2) 收尾先整体恢复 env 快照（clear+update，连被删除的变量也复原）；
  3) 断言代理四变量与开工前一致（不一致则将该测试标红），最后把
     urllib.request._opener 显式清 None，防止任何残留的全局 opener
     （含被焊进代理的）影响后续测试。
"""

import os
import urllib.request

import pytest

_PROXY_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")


@pytest.fixture(autouse=True)
def _isolate_process_state(request):
    # 1) env 快照：开工前记录完整进程环境
    saved = dict(os.environ)
    saved_proxy = {k: saved.get(k) for k in _PROXY_VARS}
    yield
    # 2/3) 收尾：先检测代理四变量是否泄漏（必须在恢复前采样），
    # 再整体恢复快照，最后清 _opener——顺序保证即使判红，
    # 泄漏也不会带进下一个测试。
    leaked = [k for k in _PROXY_VARS if os.environ.get(k) != saved_proxy[k]]
    os.environ.clear()
    os.environ.update(saved)
    # urllib.request._opener 是私有属性，仅测试兜底用途：urlopen 首次
    # 调用会把代理 env 焊进该全局缓存，env 恢复救不回来，必须显式清空。
    urllib.request._opener = None
    if leaked:
        pytest.fail(
            f"测试 {request.node.name} 结束后代理环境变量 {leaked} "
            f"与开工前不一致（泄漏未恢复）；env 已由 conftest 兜底复原，"
            f"但该测试应自行恢复其修改的环境变量。"
        )
