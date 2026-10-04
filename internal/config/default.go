package config

// DefaultYAML is also the annotated configuration distributed with the project.
const DefaultYAML = `# Tailgate 配置。使用 CLI 或网页设置写入密码和 token，禁止保存明文。
# 修改 hosts 后自动热加载；监听地址、TLS 等服务参数修改后需重启。
server:
  listen: "0.0.0.0:8722" # 建议改为 Windows 的局域网 IP，避免监听不需要的网络。
  allowed_cidrs: # 直接校验来源 IP，不信任 X-Forwarded-For；添加实际局域网网段。
    - "192.168.0.0/16"
    - "10.0.0.0/8"
    - "127.0.0.1/32"
    - "::1/128"
  tls:
    enabled: false # 局域网中也建议启用 HTTPS。
    auto_self_signed: true # 首次启用时在数据目录 tls/ 内生成证书。
    # cert_file: "C:/ProgramData/Tailgate/tls/server.crt"
    # key_file: "C:/ProgramData/Tailgate/tls/server.key"
mcp:
  enabled: true
  path: "/mcp" # Streamable HTTP 端点。
  tokens: [] # CLI 创建；只保存 SHA-256 哈希，明文只在生成时显示一次。
ssh:
  connect_timeout: 10s
  keepalive_interval: 30s
  default_command_timeout: 60s
  max_command_timeout: 600s
  max_output_bytes: 262144 # 输出超过上限时保留首尾并标记截断。
  max_sessions_per_host: 8 # 超出的请求排队，受请求超时控制。
  host_key_policy: "tofu" # 首次信任；指纹变化必须由管理员明确确认。
monitor:
  interval: 15s # 缓存采集结果，供 Web 和 MCP 共用。
audit:
  retention_days: 90 # 定期清理超过此天数的审计记录。
  queue_size: 1024 # 异步写入队列容量；退出时刷新。
hosts: [] # 使用 tailgate host add 或网页设置添加主机。
# 主机结构示例（password_enc 由 Tailgate 加密写入）：
# - name: web-01
#   address: 100.101.102.103
#   port: 22
#   username: ubuntu
#   password_enc: "base64-of-dpapi-blob"
#   sudo_password_inject: true
#   tags: [web, prod]
#   description: 主站前端
`
