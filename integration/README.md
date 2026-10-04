# 真实 SSH 集成测试

这组测试通过两个真实 OpenSSH 服务端验证 Tailgate 的 SSH、官方 MCP HTTP 客户端、状态采集、Web 认证及 WebSocket 通道。测试用 Go 的 `integration` build tag 隔离，普通 `go test ./...` 不需要 Docker。

准备 Go（版本与主项目 `go.mod` 一致）、Docker Engine，以及支持 `docker compose up --wait` 的 Docker Compose。首次构建需要访问容器镜像与 Alpine 软件源。

在项目根目录执行：

```sh
./scripts/integration.sh
```

脚本构建两个测试容器、等待 SSH 就绪、运行全部测试，并在结束时清理本组容器、网络及镜像声明的匿名测试卷。Compose 不使用用户目录挂载或持久命名卷。也可以手动执行，便于保留容器排查问题：

```sh
docker compose up -d --build --wait
go test -tags=integration -count=1 ./...
go test -race -tags=integration -count=1 ./...
docker compose down --volumes --remove-orphans
```

Compose 项目名称固定为 `tailgate-integration`，端口仅绑定本机：

| 主机 | 地址 | SSH 账号 | 说明 |
|---|---|---|---|
| ssh-one | `127.0.0.1:19721` | alice | 独立测试密码，sudo 需要密码 |
| ssh-two | `127.0.0.1:19722` | bob | 不同测试密码，sudo 需要密码 |

密码只用于本地隔离测试，明文列在 Compose 与测试代码中。测试运行时写入 Tailgate 配置的 SSH 密码仍经过加密，MCP token 只存哈希。不要把这些测试账号或密码用于实际服务器。

测试镜像固定为 `linuxserver/openssh-server` 的 SHA-256 digest；额外安装 GNU coreutils、findutils、grep、procps，以匹配 Ubuntu 的 `find -printf`、NUL 分隔文件查找、`df` 和 `ps` 参数。镜像底层为 Alpine，没有 systemd，因此 `journal`、`service_status` 验证的是“工具返回结构化远端失败”，状态页同时显示 `failed_services_available: false`，避免将不可用的 systemd 误报为零故障。

| 验证项 | 预期行为 |
|---|---|
| SSH 登录与执行 | 两台主机使用不同账号、密码；环境前缀生效；stdout、stderr、退出码分别返回 |
| 有界输出 | 大输出保留头尾；合并输出不超过字节上限；非 UTF-8 安全转换 |
| 超时取消 | 返回明确超时；远端 `sleep` 进程消失；后续命令仍可执行 |
| sudo | 完成真实密码挑战；读取测试密码文件的输出变成 `[REDACTED]`；密码不进入审计 |
| 官方 MCP 客户端 | 通过 Streamable HTTP 调用全部 10 个工具；标签选出的两台主机并行执行 |
| 文件工具 | 行偏移、总行数、正则过滤、目录元数据、隐藏文件、文件名中的引号、换行和 shell 字符正确处理；查找错误透传，字节截断返回明确错误 |
| 状态采集 | 两次 `/proc/stat` 差值得到 CPU 使用率；内存、磁盘等字段有效；离线时保留最后成功指标 |
| Web 会话 | 登录校验 Origin；Cookie 为 HttpOnly/SameSite=Strict；写操作拒绝缺少 CSRF 的请求；退出使会话失效 |
| 网页终端 | 真实 PTY shell 可执行命令、调整窗口；关闭 WebSocket 后远端 shell 消失 |
| 日志跟踪 | 收到初始内容和追加内容；关闭 WebSocket 后远端 `tail -F` 消失 |
| 审计 | MCP token 名与客户端 IP 正确；终端和日志会话有开始/结束记录；不含 SSH/Web 密码或 token 明文 |

离线测试会暂时停止本组 `ssh-two` 容器，并在检查后恢复。它不会操作其他 Compose 项目，也不会执行数据库或已有服务清理。

实际验证日期：2026-10-04（北京时间）。这组测试验证本地容器中的真实 SSH 与 Tailgate 通道；Windows DPAPI、服务注册、Windows 防火墙及实际 Tailscale 网络仍应在目标 Windows 机器上完成部署验收。
