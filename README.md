# sb-kit

面向自用 VPS 的**纯 `sing-box` + `tcpfit` 精简部署与管理工具**。

## 设计原则

- **纯 `sing-box` 单内核**：无 Web 面板、无 Nginx/Caddy、无二维码（仅输出纯净节点链接），自动适配 `sing-box 1.13` 与 `1.14+`（`acme` / `certificate_provider`），并内置 `sbctl regen` 支持跨版本一键重建入站配置。
- **低指纹防探测**：`VLESS-Reality` 默认 `443`（可自由修改）+ 分区并发测速与四重实时 SNI 体检 + 随机 16 位 `short_id` + `max_time_difference: 5m`；各协议默认端口彼此错开避免冲突。
- **自动 BBR / TCP 调优**：内置锁定版本的 `Kylin010/tcpfit v0.5.9`（每次强校 SHA-256 + 强制 `TCPFIT_NO_TELEMETRY=1` 禁用遥测），按机房地区自动匹配参考 RTT、小内存自动 1G Swap 兜底、支持 33 项出厂快照一键回滚。
- **统一 `nftables` 防护 + 零暴力侵入**：白名单（IPv4/IPv6/CIDR）与 Hysteria2 端口跳跃（IPv4/IPv6）统一使用独立 `nftables` 表且先上白名单再启动服务；不做全量 `apt upgrade`、不关系统防火墙、不 `kill -9` 冲突端口、不改时区/DNS；装机检测到旧配置先自动冷备份到 `/var/backups/sb-kit/`。
- **最小权限与可信供应链**：官方 Release 二进制强校 **SHA-256**，升级核心失败自动回滚旧二进制；专用非 `root` 用户 `sing-box` + `CAP_NET_BIND_SERVICE` + `ProtectSystem=strict` / `ProtectHome` / `ProtectKernel*` 沙盒；以 `sing-box` 用户身份跑 `sing-box check`；`flock` 防并发竞争；`error` 级日志 + `logrotate`。

## 支持协议（单 `sing-box` 进程，默认端口互不冲突）

| 协议 | 默认端口 | 用途 | 域名要求 | 说明 |
|---|---|---|---|---|
| `vless-reality` | `TCP 443` | 主力节点（默认） | 免域名 | Vision 流控，默认 `443` 可调，四重 SNI 体检 |
| `hy2` | `UDP 8443` | 晚高峰 / 丢包线路 | 推荐灰云子域名 | 原生 ACME 正规证书；支持 `masquerade` 伪装与自定义 `nftables` 端口跳跃 |
| `naive` | `TCP+UDP 9443` | 强隐蔽 HTTPS (H2/H3) | 必须灰云子域名 | `sing-box` 原生 QUIC BBR + 正规证书 |
| `anytls` | `TCP 10443` | 轻量抗审查新协议 | 推荐灰云子域名 | `sing-box 1.12+` 原生支持 |
| `ss2022` | `随机高端口` | 中转 / 家宽落地 | 免域名 | `2022-blake3-aes-256-gcm`（SIP002 链接）+ 可选 IPv4/IPv6 `nftables` 白名单 |
| `socks` | `随机高端口` | 指纹浏览器专用 | 免域名 | 强账密 + 可选 IPv4/IPv6 白名单，附 `ip:port:user:pass` 格式 |

## 私有仓库部署方式

### 方式一（最推荐，目标 VPS 不留任何 GitHub Token）

在本地 Mac 仓库目录直接运行 `deploy.sh`，自动打包推送、同步更新远端 `/usr/local/bin/sbctl` 并打开可视化菜单：

```bash
./deploy.sh root@1.2.3.4:22
# 仅同步更新远端 sbctl 到最新版本：
./deploy.sh root@1.2.3.4:50222 sync
# 直接一行无交互一键安装（443 VLESS-REALITY + 自动 BBR 调优）：
./deploy.sh root@1.2.3.4:50222 install --proto vless-reality --port 443 --bw 500 --sni auto --non-interactive
```

### 方式二（在 VPS 上使用只读 Fine-grained PAT 拉取）

```bash
git clone https://<YOUR_READONLY_PAT>@github.com/<YOU>/sb-kit.git /tmp/sb-kit
bash /tmp/sb-kit/sbctl.sh
rm -rf /tmp/sb-kit
```

> **安全红线**：本仓库仅存放脚本和模板，严禁提交任何服务器 IP、密码、UUID、私钥或 API Token。Cloudflare DNS-01 Token 请通过环境变量 `SB_CF_TOKEN` 或交互隐藏提示传入，避免出现在命令行中。

## 常用命令（装完直接敲 `sbctl` 进可视化菜单）

```bash
sbctl                                               # 打开终端可视化交互菜单
sbctl --version                                     # 查看 sb-kit 与 sing-box 版本
sbctl install --proto vless-reality --port 443      # 一键安装（含自动 BBR 调优）
sbctl install --no-tune --proto vless-reality       # 已有业务机跳过 BBR 调优
sbctl add hy2 --domain hy.example.com --masquerade https://www.debian.org
SB_CF_TOKEN=xxx sbctl add naive --domain nv.example.com
sbctl add socks --whitelist "1.2.3.4,2001:db8::1"   # 指纹浏览器 Socks5（IPv4/IPv6 白名单）
sbctl modify                                        # 交互修改节点（端口/SNI/密钥/白名单/跳跃/伪装）
sbctl links                                         # 导出全部纯链接（无二维码）
sbctl yaml                                          # 按需导出 Clash/Mihomo proxies YAML 片段
sbctl tune --rollback                               # 一键回滚 BBR/TCP 调优
sbctl audit                                         # 一键安全与 Reality 回落巡检
sbctl update                                        # 仅升级 sing-box 核心（失败自动回滚）
sbctl regen                                         # 跨版本升级后按新语法从 meta 重建全部配置
```
