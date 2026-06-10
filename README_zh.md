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
srvgov exec --dry-run "uptime" -o json
srvgov exec "uptime" -o json
srvgov audit --limit 20 -o json
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
