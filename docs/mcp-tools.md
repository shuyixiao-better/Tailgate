# MCP 工具参考

Tailgate 使用官方 Go MCP SDK、Streamable HTTP、Bearer Token。默认端点为 `http://WINDOWS-LAN-IP:8722/mcp`；HTTPS 启用后更换协议。初始化/发现结果包含英文服务器指令与全部工具的 JSON Schema。

先调用 `list_hosts` 取得主机名称。下面的 JSON 请求表示 `tools/call` 中的 `name` 与 `arguments`；结果示例表示 `structuredContent`，SDK 也提供相同 JSON 的文本内容用于兼容客户端。

## 通用规则

- `host` 使用配置中的名称，不使用任意 IP。多主机工具使用 `hosts` 或 `tag`，二选一。
- 参数类型严格校验；缺失必填项、未知字段、NUL 和越界数值会返回结构化错误，并留下审计记录。
- 除 `run_command.command` 与 `run_command_multi.command` 作为原始命令外，文件路径、unit、过滤表达式等均按单个 POSIX shell 参数安全转义。
- 命令环境固定 `LANG=C.UTF-8`、`TERM=dumb`、`PAGER=cat`、`SYSTEMD_PAGER=cat`，不请求 PTY。使用会退出的非交互命令。
- 默认单命令超时 60 秒，允许范围由配置决定，默认最大 600 秒。MCP 工具的超时参数越界时拒绝请求。计时包含排队、连接及执行。
- stdout 和 stderr 共享输出预算，默认 262,144 字节。超出后保留首尾并标注截断；非 UTF-8 字节安全替换。`output_bytes` 表示原始输出大小，不代表返回 JSON 大小。
- 正常结束的远端进程即使 `exit_code != 0` 也可作为结果返回；AI 应检查退出码、stderr 与具体工具内容，不把 MCP 成功响应等同于命令成功。
- 每次调用记录来源 `mcp`、Token 名称、实际客户端 IP、主机、命令、退出码、耗时和有限输出摘要。
- 目标 Ubuntu 使用标准 `/bin/bash`、GNU findutils/coreutils、GNU grep 和 awk；状态采集还使用 procps。精简镜像需要补齐工具，systemd/journal 功能需要目标实际运行 systemd。

## 1. `list_hosts`

列出配置主机及最近缓存的状态；适合作为会话第一步。

| 参数 | 类型 | 必填 / 默认 | 含义 |
|---|---|---|---|
| `tag` | string | 可选 | 只列出含此标签的主机 |

```json
{"name":"list_hosts","arguments":{"tag":"prod"}}
```

```json
{
  "hosts": [
    {
      "name": "web-01",
      "address": "100.101.102.103",
      "port": 22,
      "username": "ubuntu",
      "tags": ["web", "prod"],
      "description": "主站前端",
      "online": true,
      "status": {
        "host": "web-01",
        "online": true,
        "cpu_usage_percent": 12.4,
        "ssh_latency_ms": 23,
        "last_success": "2026-10-04T02:00:00Z"
      }
    }
  ]
}
```

主机 `status` 实际返回 `host_overview` 的完整缓存；此处只展示部分字段。空匹配为 `{"hosts":[]}`。

## 2. `host_overview`

读取完整状态缓存，或者强制进行一次采集。

| 参数 | 类型 | 必填 / 默认 | 含义 |
|---|---|---|---|
| `host` | string | 必填 | 配置主机名称 |
| `refresh` | boolean | 可选，false | 立即采集，绕过缓存 |

```json
{"name":"host_overview","arguments":{"host":"web-01","refresh":true}}
```

```json
{
  "host": "web-01",
  "online": true,
  "ssh_latency_ms": 23,
  "collected_at": "2026-10-04T02:00:00Z",
  "last_success": "2026-10-04T02:00:00Z",
  "last_error": "",
  "hostname": "web-server",
  "os_version": "Ubuntu 24.04 LTS",
  "kernel": "6.8.0-xx-generic",
  "uptime_seconds": 90061,
  "cpu_cores": 4,
  "load": [0.21, 0.31, 0.28],
  "cpu_usage_percent": 12.4,
  "memory": {"total_bytes":8589934592,"available_bytes":6442450944,"used_bytes":2147483648,"used_percent":25},
  "swap": {"total_bytes":2147483648,"free_bytes":2147483648,"used_bytes":0,"used_percent":0},
  "disks": [{"filesystem":"/dev/sda1","type":"ext4","mountpoint":"/","total_bytes":107374182400,"used_bytes":21474836480,"available_bytes":85899345920,"used_percent":20}],
  "failed_services": [],
  "failed_services_available": true,
  "top_cpu": [{"pid":1234,"command":"nginx","cpu_percent":1.2,"memory_percent":0.3}],
  "top_memory": [{"pid":1234,"command":"nginx","cpu_percent":1.2,"memory_percent":0.3}],
  "partial": false,
  "warnings": []
}
```

初次 CPU 差值样本为 `null`。无 systemd 或无法读取服务信息时 `failed_services_available:false`；此时空数组不表示零失败。某指标不可用时为空/null，`partial` 与 `warnings` 说明缺项。连接失败后 `online:false`，保留最近成功指标与 `last_success`，并更新 `last_error`。

## 3. `run_command`

以 SSH 账号权限执行原始命令。修改/删除/重启等操作前，应先向用户说明意图。

| 参数 | 类型 | 必填 / 默认 | 含义 |
|---|---|---|---|
| `host` | string | 必填 | 主机名称 |
| `command` | string | 必填 | 原始 Linux shell 命令 |
| `timeout_sec` | integer | 可选，默认配置值 | 正整数，默认不超过 600 |
| `workdir` | string | 可选 | 先切换到此目录；目录安全转义 |

```json
{"name":"run_command","arguments":{"host":"web-01","command":"printf 'hello\n'; uname -s","timeout_sec":20,"workdir":"/tmp"}}
```

```json
{"stdout":"hello\nLinux\n","stderr":"","exit_code":0,"duration_ms":47,"truncated":false,"output_bytes":12,"stdout_bytes":12,"stderr_bytes":0}
```

启用主机的 `sudo_password_inject` 且命令以 `sudo ` 开头时，改用 `sudo -S -p ''`，密码只通过 stdin 提供；密码不进入命令或审计，回显也会被清理。不会自动处理带前导空格、包装 shell、不同 sudo 密码或 OTP 提示。

## 4. `run_command_multi`

并行执行同一命令，分别返回每台主机结果。单台失败不会掩盖其他主机结果。

| 参数 | 类型 | 必填 / 默认 | 含义 |
|---|---|---|---|
| `hosts` | string[] | 与 `tag` 二选一 | 主机名称数组，去除重复名称 |
| `tag` | string | 与 `hosts` 二选一 | 选择含此标签的主机 |
| `command` | string | 必填 | 原始命令 |
| `timeout_sec` | integer | 可选 | 每台命令超时秒数 |

```json
{"name":"run_command_multi","arguments":{"hosts":["web-01","db-01"],"command":"hostname","timeout_sec":15}}
```

```json
{
  "results": {
    "web-01": {"stdout":"web-server\n","stderr":"","exit_code":0,"duration_ms":28,"truncated":false,"output_bytes":11,"stdout_bytes":11,"stderr_bytes":0},
    "db-01": {"error":{"code":"connection_failed","message":"SSH connection failed","host":"db-01"},"result":{"stdout":"","stderr":"","exit_code":-1,"duration_ms":10000,"truncated":false,"output_bytes":0,"stdout_bytes":0,"stderr_bytes":0}}
  }
}
```

外层调用与每台子调用均审计。标签无匹配、空列表或同时传入 `hosts` 与 `tag` 会返回 `invalid_arguments`。

## 5. `read_file`

按行读取文本区间，并统计完整文件行数。

| 参数 | 类型 | 必填 / 默认 | 含义 |
|---|---|---|---|
| `host` | string | 必填 | 主机名称 |
| `path` | string | 必填 | 文本文件路径 |
| `offset_line` | integer | 可选，1 | 起始行，从 1 计数；上限 1,000,000,000 |
| `max_lines` | integer | 可选，500 | 1–10,000 行；仍受输出字节上限约束 |

```json
{"name":"read_file","arguments":{"host":"web-01","path":"/etc/os-release","offset_line":1,"max_lines":2}}
```

```json
{"content":"PRETTY_NAME=\"Ubuntu 24.04 LTS\"\nNAME=\"Ubuntu\"\n","total_lines":12,"truncated":false,"output_bytes":67}
```

统计行数需扫描文件；读取超大日志优先使用 `tail_log`，避免不必要的全文件扫描。

## 6. `tail_log`

读取日志末尾，再对这段内容进行 grep 过滤，返回有限结果。

| 参数 | 类型 | 必填 / 默认 | 含义 |
|---|---|---|---|
| `host` | string | 必填 | 主机名称 |
| `path` | string | 必填 | 日志文件路径 |
| `lines` | integer | 可选，200 | 1–10,000 |
| `grep` | string | 可选 | `grep -E` 正则 |
| `ignore_case` | boolean | 可选，false | 不区分大小写 |

```json
{"name":"tail_log","arguments":{"host":"web-01","path":"/var/log/nginx/error.log","lines":100,"grep":"error|failed","ignore_case":true}}
```

```json
{"stdout":"2026/10/04 10:00:00 [error] upstream connection failed\n","stderr":"","exit_code":0,"duration_ms":31,"truncated":false,"output_bytes":55,"stdout_bytes":55,"stderr_bytes":0}
```

`grep` 没有匹配通常退出码为 1；不要将其当作 SSH 认证失败。实时 `tail -F` 属于网页日志功能，不提供给此 MCP 工具。

## 7. `journal`

封装有行数上限的 `journalctl --no-pager`。

| 参数 | 类型 | 必填 / 默认 | 含义 |
|---|---|---|---|
| `host` | string | 必填 | 主机名称 |
| `unit` | string | 可选 | systemd unit，例如 `nginx.service` |
| `since` / `until` | string | 可选 | journalctl 接受的时间描述 |
| `priority` | string | 可选 | 例如 `err`、`warning`、`0..3` |
| `lines` | integer | 可选，200 | 1–10,000 |
| `grep` | string | 可选 | journalctl 的消息正则过滤 |

```json
{"name":"journal","arguments":{"host":"web-01","unit":"nginx.service","since":"1 hour ago","priority":"warning","lines":50}}
```

```json
{"stdout":"Oct 04 10:00:00 web-server nginx[1234]: upstream unavailable\n","stderr":"","exit_code":0,"duration_ms":39,"truncated":false,"output_bytes":61,"stdout_bytes":61,"stderr_bytes":0}
```

无 journalctl 或账号没有读取权限时检查 stderr 与退出码。

## 8. `service_status`

组合 `systemctl status` 与该 unit 最近日志（50 条），不会改变服务。

| 参数 | 类型 | 必填 / 默认 | 含义 |
|---|---|---|---|
| `host` | string | 必填 | 主机名称 |
| `unit` | string | 必填 | systemd unit |

```json
{"name":"service_status","arguments":{"host":"web-01","unit":"nginx.service"}}
```

```json
{"stdout":"● nginx.service - A high performance web server\n     Active: active (running)\nOct 04 10:00:00 web-server systemd[1]: Started nginx.service.\n","stderr":"","exit_code":0,"duration_ms":46,"truncated":false,"output_bytes":142,"stdout_bytes":142,"stderr_bytes":0}
```

组合命令的最终退出码不单独代表服务状态；以 stdout 中的 `Active:`、错误和日志判断。

## 9. `list_dir`

列出目录的直接子项，包括名称、类型、大小、修改时间与权限。使用 Ubuntu GNU `find` 的 NUL 分隔输出，避免空格影响字段解析。

| 参数 | 类型 | 必填 / 默认 | 含义 |
|---|---|---|---|
| `host` | string | 必填 | 主机名称 |
| `path` | string | 必填 | 目录路径 |
| `all` | boolean | 可选，false | 包含点号开头的隐藏文件 |

```json
{"name":"list_dir","arguments":{"host":"web-01","path":"/var/log/nginx","all":false}}
```

```json
{"entries":[{"name":"access.log","type":"f","size":1024,"modified_unix":"1791079200.0000000000","permissions":"640"}],"truncated":false}
```

类型为 GNU find 的标识，如 `f` 普通文件、`d` 目录、`l` 符号链接。`modified_unix` 为包含小数的 Unix 秒数字符串；权限为八进制文本。

目录输出超过字节预算时返回 `output_truncated`；NUL 分隔记录不完整或字段非法时返回 `invalid_remote_output`，不把首尾截断内容拼成目录项。大目录应先缩小查询范围；只有完整、有效的输出才能成为 `entries`。

## 10. `search_files`

递归按文件名 glob 查找普通文件，可按内容正则进一步筛选。

| 参数 | 类型 | 必填 / 默认 | 含义 |
|---|---|---|---|
| `host` | string | 必填 | 主机名称 |
| `path` | string | 必填 | 搜索根目录 |
| `pattern` | string | 必填 | 文件名 glob，例如 `*.log` |
| `content_grep` | string | 可选 | 内容 `grep -E` 正则 |
| `max_results` | integer | 可选，100 | 返回的路径数量上限，1–10,000；不限制目录树遍历量 |

```json
{"name":"search_files","arguments":{"host":"web-01","path":"/var/log","pattern":"*.log","content_grep":"upstream failed","max_results":20}}
```

```json
{"paths":["/var/log/nginx/error.log"],"truncated":false,"stderr":"","exit_code":0}
```

`max_results` 限制返回数量，达到数量后仍读取生产端输出，使 find/grep 的错误不被截断管道掩盖；它不会限制实际遍历的目录树或内容扫描量。搜索时间受命令超时约束，应从小目录开始。Bash 管道保留 find/grep 的非零错误状态并返回 `remote_command_failed`；内容正则无匹配可正常返回空路径。

达到 `max_results` 不会设置 `truncated`，不能用它判断目录树中是否还有更多匹配。若返回的路径文本超过字节预算，返回 `output_truncated`，不会把截断标记或路径片段当成结果；此时缩小目录、文件名过滤或返回数量。

此工具按换行返回路径，包含换行字符的罕见文件名不能无歧义展示。

## 错误格式

HTTP 入口错误返回相应 HTTP 状态及 JSON：

```json
{"error":{"code":"unauthorized","message":"A valid MCP bearer token is required"}}
```

工具业务错误为 MCP `isError:true`，同时返回结构化与文本错误：

```json
{
  "isError": true,
  "structuredContent": {
    "error": {"code":"host_not_found","message":"unknown host","host":"missing-host"}
  },
  "content": [{"type":"text","text":"{\"error\":{\"code\":\"host_not_found\",\"message\":\"unknown host\",\"host\":\"missing-host\"}}"}]
}
```

| 错误码 | 含义 / 建议 |
|---|---|
| `unauthorized`（HTTP 401） | Token 不存在、错误或已撤销 |
| `source_denied` / `origin_denied`（HTTP 403） | 来源 CIDR / Origin 不允许 |
| `not_found`（HTTP 404） | MCP 被禁用 |
| `invalid_arguments` | 参数 schema、必填值、NUL 或范围错误 |
| `host_not_found` | 使用 `list_hosts` 中实际名称 |
| `connection_failed` / `session_failed` / `command_failed` | 检查 SSH 连通性、会话和远端进程状态 |
| `pool_closed` | 网关正在关闭，稍后重新连接 |
| `authentication_failed` | 检查 SSH 账号、密码与服务器认证配置 |
| `host_key_changed` | 拒绝继续；管理员核对新指纹后确认 |
| `secret_decryption_failed` | 密文损坏、换机器或开发密钥缺失 |
| `timeout` / `cancelled` | 排队、连接或命令超时/取消；避免无限命令 |
| `remote_command_failed` | 文件/目录命令失败，或文件搜索 find/grep 报错 |
| `output_truncated` | 目录列表或文件搜索的结构化输出超过字节预算；缩小查询范围/数量 |
| `invalid_remote_output` | NUL 记录不完整/字段非法，或文件读取结果缺少合法行数标记 |
| `audit_unavailable` | 审计异常，操作被拒绝或完成审计失败；管理员修复存储 |
| `operation_failed` | 其他失败；查看运行日志与审计 |
| `tool_not_found` | 使用 `tools/list` 返回的工具名称 |

SDK 仍会按协议返回 JSON-RPC 错误处理无效报文或不支持的方法；不要假定所有网络、协议错误都是工具结果。
