# sb-kit

面向自用 VPS 的**纯 `sing-box` + `tcpfit` 精简部署与管理工具**。
适用系统：`Debian 11+ / Ubuntu 20.04+`（`systemd` + `glibc`，`amd64 / arm64`）。

## 一键安装

在全新的 Debian 或 Ubuntu VPS 上，以 **root** 身份粘贴以下命令。请确认 TCP 443 空闲，并在 VPS 的入站防火墙或云安全组放行该端口。

```bash
(command -v git >/dev/null || (apt-get update && apt-get install -y git ca-certificates)) && git clone --depth 1 --branch main https://github.com/Dreamer-nxy/sb-kit.git /root/sb-kit && bash /root/sb-kit/sbctl.sh install --proto vless-reality --port 443 --sni auto --no-tune --non-interactive
```

命令通过公开 HTTPS 拉取代码，自动创建 VLESS-REALITY 节点并启动 sing-box。安装时自动选择 SNI，保留系统当前的 TCP 和 BBR 设置。完成后用 `sb i` 查看节点链接，用 `sb` 打开管理菜单。若已有其他程序占用 `sb`，安装器会显示它的路径并退出。

## 常用命令

输入 `sb` 打开数字菜单。日常管理也可以直接用四个单词的首字母。

| 操作 | 快捷命令 | 完整写法 |
|---|---|---|
| 添加节点，按提示选协议 | `sb a` | `sb add` |
| 修改节点 | `sb c` | `sb change` |
| 查看节点和连接链接 | `sb i` | `sb info` |
| 删除节点 | `sb d` | `sb del` |

知道协议时可以直接输入 `sb a r`（REALITY）、`sb a hy`（Hysteria2）、`sb a ss`（Shadowsocks 2022）或 `sb a socks`。要给 Clash / Mihomo 导出代理配置片段，用 `sb clash`。

服务状态用 `sb s`（`sb status`），重启用 `sb r`（`sb restart`）。命令命名参考了 [233boy/sing-box 的快捷命令](https://github.com/233boy/sing-box/blob/6082f1bf70ed4550a5fbd5c9fe147ba5228189d5/src/help.sh)。

### 回国阻断与名单

| 想做什么 | 命令 |
|---|---|
| 看回国阻断状态 | `sb cn` |
| 开启或关闭 | `sb cn on`、`sb cn off` |
| 立即更新规则集 | `sb cn update` |
| 放行域名 | `sb allow example.cn` |
| 拦截域名 | `sb block example.com` |

单独输入 `sb allow` 或 `sb block` 可查看对应名单。删条目时在域名前加 `del`，例如 `sb allow del example.cn`。

其他维护命令见 `sb h`（`sb help`）。用 `sb v` 查看版本，`sb u` 升级 sing-box 核心，`sb check` 巡检服务与配置。需要回滚 TCP 调优时用 `sb bbr reset`。

## 设计原则

- **纯 `sing-box` 单内核**：无 Web 面板、无 Nginx/Caddy、无二维码（仅输出纯净节点链接），自动适配 `sing-box 1.13` 与 `1.14+`（`acme` / `certificate_provider`），并内置 `sb rebuild` 支持跨版本一键重建入站配置。
- **低指纹防探测**：`VLESS-Reality` 默认 `443`（可自由修改）+ 分区并发测速与四重实时 SNI 体检 + 随机 16 位 `short_id` + `max_time_difference: 5m`；各协议默认端口彼此错开避免冲突。
- **精准回国阻断开关（参照杜甫 `v2fly` 方案）**：开/关二选一。开启后基于 `SagerNet/sing-geosite` 21 个细分类（影音/网盘/社交/银行证券/PT）+ 24 条显式补充域名精准拦截，内置指纹浏览器/飞书/1688/TikTok 放行名单（不碰 `geosite:cn`/`geoip:cn`），支持自定义 `allow`/`block` 名单、事务校验回滚与每周日自动更新定时器（`sbkit-rules-update.timer`）。
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

## 更新已安装的管理工具

在 VPS 上运行以下命令，更新源码、`sb` 和配套脚本。正在运行的 sing-box 会继续使用原配置。

```bash
cd /root/sb-kit && git pull --ff-only && bash ./sbctl.sh sync
```

如果 v0.2.2 已启用 `geoip-cn`，同步后用 `sb cn` 确认当前策略。运行 `sb cn update` 可迁移到新版域名分类策略，运行 `sb cn off` 可关闭旧策略。新版将 21 个规则文件固定到同一个上游 Git 提交，`sb cn` 会显示完整 SHA。停服期间的定时更新在下次启动时生效。

从 v0.2.0 升级时，先同步管理工具，再运行 `sb rebuild` 重建节点。重建会校验全部节点，将原有 SOCKS 和 SS2022 白名单加到 sing-box 的启动依赖中。服务启动失败时会恢复上一套配置。

接管已有 sing-box 实例时，安装器先备份原配置、核心和服务状态。卸载会检查托管标记，保留手工文件，并按接管记录恢复原实例。早期版本留下的空标记缺少原实例归属记录，可在 `/var/backups/sb-kit/` 查阅历史备份。
