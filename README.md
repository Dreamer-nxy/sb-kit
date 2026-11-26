# sb-kit

面向自用 VPS 的**纯 `sing-box` + `tcpfit` 精简部署与管理工具**。

## 设计原则

- **纯 `sing-box` 单内核**：无 Web 面板、无 Nginx/Caddy、无二维码（仅输出纯净节点链接），自动适配 `sing-box 1.13` 与 `1.14+`（`acme` / `certificate_provider`）。
- **低指纹防探测**：`VLESS-Reality` 默认 `443`（可自由修改）+ 分区并发测速与四重实时 SNI 体检 + 随机 16 位 `short_id` + `max_time_difference: 5m`。
- **自动 BBR / TCP 调优**：内置锁定版本的 `Kylin010/tcpfit v0.5.9`（强校 SHA-256 + 强制 `TCPFIT_NO_TELEMETRY=1` 禁用遥测），按机房地区自动匹配参考 RTT、小内存自动 1G Swap 兜底、支持 33 项出厂快照一键回滚。
- **零暴力侵入**：不做全量 `apt upgrade`、不关系统防火墙、不 `kill -9` 冲突端口、不改时区/DNS；装机检测到旧配置先自动冷备份到 `/var/backups/sb-kit/`。
- **最小权限与可信供应链**：官方 Release 二进制强校 **SHA-256**（禁用 `--no-check-certificate`）；专用非 `root` 用户 `sing-box` + `CAP_NET_BIND_SERVICE` + `ProtectSystem=strict` 运行；`error` 级日志 + `logrotate`。

## 支持协议（单 `sing-box` 进程）

| 协议 | 用途 | 域名要求 | 说明 |
|---|---|---|---|
| `vless-reality` | 主力节点（默认） | 免域名 | Vision 流控，默认 `443` 可调，四重 SNI 体检 |
| `hy2` | 晚高峰 / 丢包线路 | 推荐灰云子域名 | 原生 ACME 正规证书；端口跳跃可选自定义区间 |
| `naive` | 强隐蔽 HTTPS (H2/H3) | 必须灰云子域名 | `sing-box` 原生 QUIC BBR + 正规证书 |
| `anytls` | 轻量抗审查新协议 | 推荐灰云子域名 | `sing-box 1.12+` 原生支持 |
| `ss2022` | 中转 / 家宽落地 | 免域名 | `2022-blake3-aes-256-gcm` + 可选 `nftables` IP 白名单 |
| `socks` | 指纹浏览器专用 | 免域名 | 随机高端口 + 强账密 + 可选 IP 白名单，附 `ip:port:user:pass` 格式 |

## 私有仓库部署方式

### 方式一（最推荐，目标 VPS 不留任何 GitHub Token）

在本地 Mac 仓库目录直接运行 `deploy.sh`，自动打包推送到 VPS 并打开可视化菜单：

```bash
./deploy.sh root@1.2.3.4:22
# 指定非 22 SSH 端口：
./deploy.sh root@1.2.3.4:50222
# 直接一行无交互一键安装（443 VLESS-REALITY + 自动 BBR 调优）：
./deploy.sh root@1.2.3.4:50222 install --proto vless-reality --port 443 --bw 500 --sni auto --non-interactive
```

### 方式二（在 VPS 上使用只读 Fine-grained PAT 拉取）

在 GitHub 生成仅授权当前私有仓库 `Contents: Read-only` 的 Fine-grained Token，在目标机执行：

```bash
git clone https://<YOUR_READONLY_PAT>@github.com/<YOU>/sb-kit.git /tmp/sb-kit
bash /tmp/sb-kit/sbctl.sh
rm -rf /tmp/sb-kit
```

> **安全红线**：本仓库仅存放脚本和模板，严禁提交任何服务器 IP、密码、UUID、私钥或 API Token。

## 常用命令（装完直接敲 `sbctl` 进可视化菜单）

```bash
sbctl                                               # 打开终端可视化交互菜单
sbctl install --proto vless-reality --port 443      # 一键安装（含自动 BBR 调优）
sbctl install --no-tune --proto vless-reality       # 已有业务机跳过 BBR 调优
sbctl add hy2 --port 8443 --domain hy.example.com   # 添加 Hysteria2（Cloudflare 灰云 A 记录）
sbctl add naive --port 8443 --domain nv.example.com # 添加 Naive
sbctl add socks --whitelist 1.2.3.4                 # 添加指纹浏览器 Socks5（仅放行白名单 IP）
sbctl modify                                        # 交互修改节点（改端口/换 SNI/重置账密/改白名单）
sbctl links                                         # 导出全部纯链接（无二维码）
sbctl yaml                                          # 按需导出 Clash/Mihomo proxies YAML 片段
sbctl tune --rollback                               # 一键回滚 BBR/TCP 调优
sbctl audit                                         # 一键安全与 Reality 回落巡检
sbctl update                                        # 仅升级 sing-box 核心（不覆盖配置）
```
