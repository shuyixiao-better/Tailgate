# 交付验收清单

此文件记录本项目需求与验证方式；实际执行结果在 `docs/validation.md`。

| 阶段 | 内容 | 验证 |
|---|---|---|
| M1 | YAML 校验、密码保护、SQLite 用户与会话、CLI、SSH 连接池 | 单元测试、SSH 协议测试、Go 构建、Windows 交叉构建 |
| M2 | 官方 MCP SDK、十个工具、token 认证、异步审计 | 官方 SDK HTTP 测试客户端、认证隔离与参数转义测试 |
| M3 | 状态采集、Web 登录与 CSRF、终端与日志 WebSocket、设置、审计 | REST/登录/来源校验测试、状态 fixture、浏览器检查 |
| M4 | Windows 服务、TLS、轮转日志、防火墙、文档与脚本 | vet、staticcheck、race、两个 SSH 容器的 integration 测试、exe 构建 |

Windows 服务注册、开机启动、DPAPI 运行和真实 Tailscale 路由需要在 Windows 部署端验证。Mac 上交叉构建不等于这些运行验证。
