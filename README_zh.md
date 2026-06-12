# srvgov-cli

[English](README.md) | [中文](README_zh.md)

面向 AI agent 和操作人员的受治理远程服务器命令执行 CLI。`srvgov` 将
fail-closed 命令分类、R0-R3 授权、严格 TOFU SSH 主机密钥固定、输出脱敏和
结构化审计串成一条执行链。

## 安装

```bash
npm install -g srvgov-cli
# 或
go install github.com/JiangHe12/srvgov-cli@latest
```

GitHub Releases 提供 Linux、macOS、Windows 的 amd64/arm64 二进制。npm
安装会下载匹配平台的产物，并默认校验 SHA-256。

## 快速开始

```bash
srvgov ctx set dev --server ssh://alice@example.com:22 --identity-file ~/.ssh/id_ed25519 -o json
srvgov ctx use dev -o json
srvgov status -o json
srvgov ports -o json
srvgov logs --unit sshd --since "1 hour ago" --lines 50 -o json
srvgov svc status sshd -o json
srvgov file stat /etc/hosts -o json
srvgov docker list -o json
srvgov exec --dry-run "uptime" -o json
srvgov exec "uptime" -o json
srvgov audit query --limit 20 -o json
```

自动化和 AI agent 始终使用 `-o json`。

## 治理模型

| 风险 | 含义 | 授权 |
|---|---|---|
| R0 | 已知只读命令 | 可直接执行，仍审计 |
| R1 | 已知良性变更 | `--reason` + `--yes` |
| R2 | 未知或已升档命令 | `--reason` + 非空 `--ticket` + `--yes` |
| R3 | 破坏性、提权、动态或解析不确定命令 | `--reason` + `--ticket` + `--allow-destructive` + `--yes` |

protected context 会将 R1 升为 R2、R2 升为 R3。AI agent 绝不能自动填写
`--ticket`、`--allow-destructive` 或高风险 `--yes`。影响面必须来自
`exec --dry-run` 的分类结果，不能靠模型猜。

## Context

```bash
srvgov ctx set prod \
  --server ssh://deploy@example.com:22 \
  --identity-file ~/.ssh/id_ed25519 \
  --auth-method private-key,agent,password \
  --env production \
  --protected \
  -o json

srvgov ctx use prod -o json
srvgov ctx current -o json
srvgov ctx list -o json
srvgov ctx delete old-host -o json
srvgov ctx role set prod --target-operator alice --role writer -o json
srvgov ctx role list prod -o json
srvgov ctx export prod > prod.ctx.yaml
srvgov ctx import -f prod.ctx.yaml --rename prod-copy --yes -o json
srvgov ctx migrate-credentials --to encrypted-file --context prod -o json
```

Context 输出不会包含 password、私钥内容、私钥口令或 identity-file 路径。

可移植 context export 使用 `srvgov.io/ctx-export/v1`。默认脱敏字面量
password 和 SSH identity passphrase；credstore 引用原样保留。
`--include-credentials` 仅限 plain-yaml context。

## 动手前先观察

三个可观测命令把常见只读 SSH 输出转换成稳定 JSON:

```bash
srvgov status -o json
srvgov ports -o json
srvgov status --targets web-a,web-b --concurrency 5 -o json
srvgov logs --unit nginx --since "30 minutes ago" --priority warning --lines 100 -o json
srvgov logs --file /var/log/nginx/error.log --grep "upstream" --lines 100 -o json
```

每条底层远端命令都独立经过与 `exec` 相同的分类、有效风险、授权、SSH、脱敏和
审计流程，绝不使用 shell 操作符拼接。`ports` 从 `ss` 降级到 `netstat`；
unit 日志在 journalctl 不可用时降级到 `systemctl status`。命令不会自动添加
`sudo`，拿不到 PID/process 时字段留空。日志文本、进程名、构造命令、调用方
输出和审计记录都会脱敏。

### 舰队扇出

`status`、`ports`、`exec` 支持逗号分隔的 context 名：

```bash
srvgov status --targets web-a,web-b,web-c --concurrency 5 -o json
srvgov ports --targets web-a,web-b,web-c -o json
srvgov exec --targets web-a,web-b,web-c "uptime" -o json
srvgov exec --targets web-a,web-b,web-c --dry-run "systemctl restart nginx" -o json
srvgov exec --targets web-a,web-b,web-c "systemctl restart nginx" \
  --reason "restart reviewed service" --ticket OPS-123 --yes -o json
```

`status` 和 `ports` 仍严格限定为 R0。`exec` 使用两阶段 authorize-all：
先按目标名排序，逐台完成分类和强制非交互授权，任何目标的 ticket、RBAC、
确认或 allow flag 不满足都会整批拒绝，保证零部分写入。全体通过后才并发执行，
并在每台 SSH 前再次授权。dry-run 不授权、不连接，返回逐台真实 base/effective
风险以及 `maxEffectiveRiskTier`。目标会去重并排序，每台独立审计；远端执行
失败不会中止其余目标，但完整结果输出后整体返回退出码 7。`--targets` 与
`--context` 互斥。

## 服务管控

`svc` 只暴露固定服务操作白名单。unit 名始终按 shell 字面量处理，每条构造出的
`systemctl` 命令都经过与 `exec` 相同的分类和授权链。

```bash
# R0 读取，仍审计
srvgov svc status nginx -o json

# R2 变更：reason、ticket 和确认必须由人提供
srvgov svc restart nginx \
  --reason "apply reviewed configuration" --ticket OPS-123 --yes -o json
```

可用动作仅为 `status`、`start`、`stop`、`restart`、`reload`、`enable` 和
`disable`，每次只允许一个 unit。protected context 会把服务变更从 R2 升为
R3，并额外要求人提供 `--allow-destructive`。`svc` 不暴露电源、isolate、
mask 或任意 systemctl 子命令。

## 文件操作

文件读取是结构化 R0 操作，并且仍会审计：

```bash
srvgov file read /etc/hosts --max-bytes 1048576 -o json
srvgov file stat /etc/hosts -o json
srvgov file list /var/log -o json
```

写入使用 `tee -- '<path>'`，内容通过 SSH stdin 流式传输。普通路径为 R2；
SSH 授权文件、shell dotfile、crontab 等敏感路径为 R3。

```bash
printf '%s\n' 'enabled=true' | srvgov file write /tmp/app.conf \
  --reason "update reviewed configuration" --ticket OPS-123 --yes -o json

srvgov file write /tmp/app.conf --content "enabled=true" \
  --reason "update reviewed configuration" --ticket OPS-123 --yes -o json
```

未提供 `--content` 时，stdin 就是文件内容，授权前必须显式给出 `--yes`。
提供 `--content` 后绝不读取 stdin，仍可正常使用交互确认。写入输出和审计都不会
包含文件内容；审计只记录脱敏路径、字节数和 SHA-256。本版本使用直接、非原子
覆盖，不实现临时文件加 rename。`file` 不使用 SFTP，也不会自动添加 `sudo`。

## Docker 治理

Docker 读取提供稳定且脱敏的结构化输出：

```bash
srvgov docker list -o json
srvgov docker inspect api -o json
srvgov docker logs api --tail 100 -o json
```

`docker list`、`inspect`、`logs` 都是审计的 R0 操作。inspect 在远端只投影
固定安全字段，不请求容器环境变量，也不返回完整 inspect 文档。logs 默认 100
行，`--tail` 允许 1 到 10000。

生命周期变更为 R2，需要人类授权：

```bash
srvgov docker restart api \
  --reason "restart after reviewed deployment" --ticket OPS-123 --yes -o json
```

固定白名单仅包含 `ps`/`list`、`inspect`、`logs`、`start`、`stop`、
`restart` 和 `rm`，每次一个容器。绝不暴露 Docker run、create、exec、
build、copy、compose 或 prune。protected context 会把生命周期动作升到
R3，并要求人提供 `--allow-destructive`。容器标识始终 shell 引用。

## 受治理执行

预览不会连接 SSH，也不会执行命令:

```bash
srvgov exec --dry-run "touch /tmp/deploy-ready" -o json
```

按返回的风险档执行:

```bash
# R0
srvgov exec "systemctl status nginx" -o json

# R1
srvgov exec "touch /tmp/deploy-ready" \
  --reason "mark deployment ready" --yes -o json

# R2
srvgov exec "custom-maintenance-command" \
  --reason "scheduled maintenance" --ticket OPS-123 --yes -o json

# R3
srvgov exec "rm -rf /tmp/old-release" \
  --reason "remove failed release" \
  --ticket OPS-123 --allow-destructive --yes -o json
```

命令以非 PTY 方式运行。command、stdout、stderr 在返回调用方和写审计前都会
脱敏。远端非零退出仍返回结构化结果，并以 7 (`BACKEND_ERROR`) 退出。

## SSH 信任与凭据

首次连接未知 `host:port` 时，公钥固定到 `~/.srvgov/known_hosts`。后续密钥
不匹配，或已知地址突然出现未固定的新密钥类型，都会被拒绝。合法轮换需要人工
核验并清理旧 pin；不存在跳过校验的开关。

认证顺序为私钥、SSH agent、password，并受 context 的 `--auth-method` 控制。
password 和私钥口令可使用 opskit-core credstore 引用。SSH 传输层不记录凭据
或原始命令输出。

## 审计与诊断

```bash
srvgov capabilities -o json
srvgov audit query -o json
srvgov audit query --type authorization.denied --status denied -o json
srvgov audit verify --strict -o json
srvgov audit prune --keep-last 20 -o json
srvgov doctor -o json
srvgov version -o json
srvgov --version
```

默认审计日志位于 `~/.srvgov/audit.log`，记录有效风险、授权状态、目标、脱敏后
的命令/输出、远端退出码和错误信息。

`capabilities` 会如实报告当前命令面、`srvgov.io/context/v1`、
`srvgov.io/audit/v1`、R0-R3 授权规则、`--allow-destructive`、JSONL 审计、
reader/writer/admin RBAC、dry-run、严格 TOFU 和脱敏能力。

## AI Skill

```bash
srvgov install claude --skills
srvgov install codex --skills
srvgov install /custom/skills/path --skills
```

## 从源码构建

```bash
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal
golangci-lint run --timeout=5m
go vet -tags=integration ./...
```

## 贡献、安全、许可证

见 [CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md) 和
[LICENSE](LICENSE)。
