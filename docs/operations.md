# Tailgate 运维

入口与客户端配置见 [README](../README.md)。以下命令在 Windows 管理员 PowerShell 中执行；自定义数据目录时每次使用同一个 `--data-dir`。

## 安装后验收

1. 在 Windows 执行 `tailgate.exe host test --all`，确认主机、延迟、SSH 指纹与系统版本。
2. 在 Mac 打开 Windows 的局域网网页，登录、刷新详情、操作终端并确认终端退出后远端进程结束。
3. 配置 Claude Code / Codex，先调用 `list_hosts`，再执行 `run_command` 的 `hostname` 或 `uname -a`。
4. 在网页审计中检查 AI Token 名称、网页用户名、实际 Mac IP、主机和命令结果。
5. 执行 `install`、`start`、`status`，重新验证网页与 MCP。主动 `stop` 后确认服务保持停止；再次 `start` 恢复。
6. 在计划的 Windows 验收环境测试服务异常恢复、DPAPI、Tailscale 路由、HTTPS 信任和防火墙来源限制。

源码测试与交叉编译通过只说明本地验证范围；生产主机的账号、sudo/systemd 权限和网络连通性需要上述实际检查。记录来源见 [validation.md](validation.md)。

## 日常检查

```powershell
C:\Tailgate\tailgate.exe status
C:\Tailgate\tailgate.exe host test --all
Get-Content C:\ProgramData\Tailgate\logs\tailgate.log -Tail 50
```

运行日志为 JSON；单文件超过 10 MB 轮转，最多 5 份备份，备份保留 30 天并 gzip。操作审计存于 SQLite，默认 90 天；它和运行日志有不同用途，排障先查看失败动作与运行日志中的存储/连接错误。

主机状态为每 15 秒缓存。首次 CPU 为空是正常现象；`last_success` 和 `collected_at` 可判断指标年龄。主机离线时旧数据保留，不能据此判断当前负载。systemd 不可用与“没有失败服务”是不同状态。

## 配置修改

| 修改项 | 生效方式 |
|---|---|
| 主机新增/删除、SSH 地址/账号/密码/标签、sudo 注入 | 热加载；相应池连接会更新 |
| MCP Token 创建/撤销、来源 CIDR | 后续请求热加载 |
| 网页用户/密码 | 数据库立即生效；删除用户后会话不可继续使用 |
| 监听地址、MCP 路径、TLS | 重启 |
| SSH 超时、输出上限、并发、keepalive、TOFU 策略 | 重启 |
| 采集间隔、审计保留时间/队列大小 | 重启 |

修改 `config.yaml` 前备份；YAML 错误会保留最后有效配置并写日志。收窄网段时保留实际管理设备来源，避免把当前管理客户端排除。变更监听端口后重新执行 `firewall` 核对打印命令，Windows 旧规则不会自动删除。

## 升级与备份

```powershell
C:\Tailgate\tailgate.exe stop
Copy-Item C:\ProgramData\Tailgate D:\Backups\Tailgate-20261004 -Recurse
# 将新的 tailgate.exe 放回已注册的固定路径
C:\Tailgate\tailgate.exe version
C:\Tailgate\tailgate.exe start
C:\Tailgate\tailgate.exe status
```

先正常停止再复制整个数据目录，使 SQLite、WAL、配置、known_hosts 和 TLS 处于一致状态。备份含密码密文、网页账号、会话和私钥，备份目录也应限制为 Administrators/SYSTEM。确认备份成功、固定 exe 路径未变，再启动并完成网页/MCP 验证。

恢复到**同一台 Windows**可在停止服务后恢复数据目录；恢复旧版本前确认它能读取当前配置和数据库 schema。本项目未承诺跨版本数据库降级迁移。

换一台 Windows 时，DPAPI 密文无法解密；先在新机器初始化、迁入主机元数据和需要保留的数据，再逐台 `host set-password NAME` 或在网页重新录入密码。Mac/Linux 的 AES-GCM 密文与 Windows DPAPI 不互通；开发密钥也不是 Windows 迁移密钥。重新验证指纹、Token、网页用户与证书。

## Token 与用户

为 Claude Code、Codex 和不同使用者创建不同名称 Token，便于审计和撤销。Token 只展示一次，丢失后撤销并重建，服务端不能恢复明文。

```powershell
C:\Tailgate\tailgate.exe token create mac-codex
C:\Tailgate\tailgate.exe token list
C:\Tailgate\tailgate.exe token revoke mac-codex
C:\Tailgate\tailgate.exe user passwd admin
```

管理员网页可创建普通用户或管理员；CLI `user add` 创建管理员。所有使用者共享配置中的远端账号权限，只有网页管理权限按角色区分。

## SSH 指纹变更

服务重装、更换主机或 SSH host key 更新后，连接会以 `host_key_changed` 拒绝。先在受信任的目标服务器控制台核对新指纹，例如读取 `/etc/ssh/ssh_host_ed25519_key.pub` 的 SHA-256 指纹；在网页设置选择该主机，测试连接，再核对显示的指纹并明确确认。

确认请求会携带刚显示的预期指纹，服务端重新连接核对后更新。不要用删除全部 `known_hosts` 代替单主机确认；首次 TOFU 连接也应核对目标身份。

## HTTPS 证书续换

自动证书有效期三年，重启复用原证书。过期证书会导致启动失败，需要更换；IP/访问域名不在 SAN 中时也需要更换。

在停止服务后，将 `tls/server.crt` 与 `tls/server.key` 一起移到受保护的备份目录，保持 `auto_self_signed: true`，再启动生成新证书。核对新证书 SAN 与 SHA-256 指纹，通过可信方式分发公钥证书，更新 Mac 系统信任以及 CLI 的 CA 文件，然后验证网页、MCP 与 WebSocket。旧信任证书可在确认所有客户端完成更换后移除。

使用自行签发的证书时，配置 `auto_self_signed: false`、`cert_file` 和 `key_file`；相对路径以数据目录为基准。证书和私钥必须匹配，包含实际访问名称并处于有效期。TLS 最低 1.2。客户端不要关闭证书验证。

## 退出与故障处理

正常停止先拒绝新 HTTP 连接，关闭终端和日志 WebSocket，再等待已执行请求；HTTP 排空最多 `max_command_timeout + 15s`，随后关闭 SSH 并刷盘审计。手动 Windows 服务停止预算为 `max_command_timeout + 45s`，默认最长约 645 秒；Windows 关机/重启仍受操作系统统一服务停止期限限制，不能保证长命令排空。

审计写入失败后拒绝新操作，防止继续执行却没有记录。检查磁盘空间、数据库/目录权限、日志错误，修复后重启；不要删除数据库来恢复可用性。强制结束进程或断电可能损失尚未刷盘的审计。

异常运行结束会先完成资源清理，再以非零退出触发 SCM 恢复：5 秒后重启，恢复计数 24 小时重置。主动 `stop` 保持停止。失败重复出现时先 `stop`，查运行日志和 Windows 服务事件，再修复配置、证书或存储。

## 本地集成验证

```sh
./scripts/integration.sh
```

脚本需要 Docker Compose 支持 `up --wait`，启动两台仅监听 loopback 的 SSH fixture，运行带 `integration` 标签的测试，并在退出时清理容器。也可按 README 手动启动和测试。fixture 的固定密码仅用于开发；Alpine 没有 systemd，因此真实 Ubuntu unit 行为需要目标环境补验。
