# [开源] Camty — 把渗透测试变成一条可审计的流水线

**GitHub**: https://github.com/MiyanoShihoo/camty

## 一句话

渗透测试的每一步——侦察、验证、利用、横向、报告——自动执行，每步产出自动进证据台账，报告是自然产物而非事后拼凑。

## 为什么造它

打完一次渗透，写报告时发现：工具输出散落在 5 个终端 tab、截图存了 30 张但不知道哪张对应哪个测试、扫描时发现了个洞但忘了上下文。**信息有了，证据链没建立。**

Camty 从"证据链优先"出发：每个动作先过 scope 白名单，再落审计哈希链，产出进带血缘的台账。利用级动作必须引用已验证发现的 ID，否则引擎直接拒绝——不是提示，是拒绝。

## 长什么样

- **41 个适配器**：subfinder → httpx → js-recon（前端端点测绘）→ nuclei → inj-probe（多载体注入七变体）→ authz-probe（A/B 双账号越权矩阵）→ impacket 全家桶 → C2 三件套
- **多 Agent 引擎**：LLM 规划者读台账+资产覆盖度 → 生成攻击链 → N 个 worker 并行执行 → 写回双图 → 重规划。LLM 挂了自动降级确定性模式继续跑
- **对抗层**：全流量 Chrome TLS 指纹伪装、浏览器 stealth 三态、注入七变体混淆、MITM 流量解密留痕
- **面板**：七页签（力导向资产覆盖图 / 流量逐条回放 / 攻击链 / 探索图 / 审批队列），跑动中随时注入转向指令
- **产出**：HTML / docx / SRC 提交格式三态报告 + IM 推送（飞书/钉钉/企微/TG）

## 快速上手

```bash
git clone https://github.com/MiyanoShihoo/camty.git && cd camty
pip install -r requirements.txt
python -m pytest tests/ -q    # 245 项自检

# 写一个 yaml 授权配置，然后：
python -m camty auto engagements/my-target.yaml      # 全自动
python -m camty engine engagements/my-target.yaml --agent --budget 30  # LLM 引擎
python -m camty report engagements/my-target.yaml --format html       # 出报告
```

## 诚实的边界

它不会自动找洞。它自动化的是"过程"——范围管控、证据归档、台账维护、报告生成。找洞仍然需要方法论，但 Camty 保证你的经验不散落在终端 scrollback 里。

已用两个真实目标验证过（Go+GORM 站点、个人诗歌站）：25+ 条攻击线全排后能清晰输出"测过了、没找到"的证据支撑结论——这和找到洞是同一种能力。

Apache 2.0 开源，仅供授权测试使用。欢迎 star / issue / PR。

---

详细架构文章见先知社区（链接稍后补充）。
