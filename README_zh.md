<div align="center">

# srvgov-cli

**面向人类与 AI 智能体的「带治理」SSH 远程服务器操作命令行。**

在远程机器上执行命令、控制服务、改文件、管容器——每条命令都做风险分级、可预览、经严格 TOFU 绑定的 SSH 执行、输出脱敏、全程审计。安全到可以跨整个机群批量执行,也安全到可以交给 AI。

[![npm version](https://img.shields.io/npm/v/srvgov-cli.svg)](https://www.npmjs.com/package/srvgov-cli)
[![CI](https://github.com/JiangHe12/srvgov-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/JiangHe12/srvgov-cli/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/srvgov-cli.svg)](LICENSE)
[![signed](https://img.shields.io/badge/release-cosign%20%2B%20npm%20provenance-blue.svg)](#-供应链可信与校验)

[English](README.md) · [简体中文](README_zh.md)

</div>

---

## 🧭 这是什么?(先看这里)

SSH 登上生产服务器敲命令,既强大又可怕:一个敲错目录的 `rm -rf`、一次停错服务的 `systemctl stop`,没有预览、没有第二双眼睛、往往也没有记录。把裸 shell 交给自动化脚本或 AI 智能体,风险更是成倍放大。

**srvgov-cli 给每一个远程操作都套上护栏。** 把它想成站在你和服务器之间的一位谨慎 SRE:

- 🧠 **执行前先给命令分级**——一个结构感知的分类器读取*整条*命令行(管道、重定向、`sudo`、命令替换)并判定风险档;未知或含糊?fail-closed 到更高档。
- 🛡️ **危险越大,门槛越高**——读取直接跑;良性变更需理由 + 确认;破坏性或特权命令需变更工单**外加**明确的「允许破坏」标志。
- 👀 **优先结构化观测**——`status`、`ports`、`logs`、`file`、`svc`、`docker` 给你安全、固定形状的读取,而非手搓 shell。
- 🔒 **严格 TOFU 绑定主机密钥**——已知主机的密钥变更或新类型一律硬失败,绝不静默接受。
- 🛰️ **安全地跨机群批量执行**——按名字或标签选目标;每个目标在**任何** SSH 开始前都先授权,且各自独立审计。
- 🤖 **可放心交给 AI 智能体**——它能自由观测、预览,但**无法**伪造破坏性操作所需的人类审批。

输出经过脱敏,每个操作都进防篡改审计日志。

---

## ✨ 功能一览

| | |
|---|---|
| ⌨️ **受治理 `exec`** | 执行一条 shell 命令;fail-closed、结构感知的分类器设定其风险档与所需授权。 |
| 👀 **结构化观测** | `status`、`ports`、`logs`、`file read/stat/list`、`svc status`、`docker list/inspect/logs`——审计型 R0 读取,脱敏,绝不加 `sudo`。 |
| 🔧 **固定动词控制** | `svc start/stop/restart/reload/enable/disable`、`file write`、`docker start/stop/restart/rm`——不暴露任意 `systemctl`/`docker` 面。 |
| 🚦 **R0–R3 治理** | 每条命令风险分级;受保护上下文整体升一档;AI 调用者永远无法自我授权。 |
| 🛰️ **机群 fanout** | `--targets a,b,c` 或 `--selector key=value`(标签匹配);读取封顶 R0;写入在任何 SSH 前先授权**所有**目标。 |
| 🔒 **严格 TOFU SSH** | 主机密钥首次使用时绑定;密钥变更则拒绝、等待人工复核。非 PTY 执行。 |
| 👥 **RBAC 与上下文** | 每个上下文的 `reader` / `writer` / `admin` 角色;可移植的上下文导出/导入;凭证后端。 |
| 🧹 **处处脱敏** | 密钥在输出**和**审计写入前都被抹除;`file write` 只审计路径指纹、字节数与内容 SHA-256,绝不记录原始路径或内容。 |
| 📜 **防篡改审计** | 每个操作(含被拒)都哈希链;`audit verify` 检测篡改。 |
| 🔏 **可信供应链** | 二进制经 **cosign 签名**、npm 带 **provenance**、安装器校验 **SHA-256**。 |

---

## 📦 安装

```bash
npm install -g srvgov-cli
```

这会装一个很小的启动器;首次运行时,它会从已签名的 [GitHub Release](https://github.com/JiangHe12/srvgov-cli/releases) 下载对应你 OS/架构的预编译二进制,并在使用前**校验 SHA-256**。安装器需要 Node.js ≥ 14(CLI 本身是自包含的 Go 二进制)。

<details>
<summary>其它安装方式</summary>

- **直接下载**——从 [Releases 页面](https://github.com/JiangHe12/srvgov-cli/releases)取二进制,用 cosign 签名的 `checksums.txt` 校验,放进 `PATH` 并重命名为 `srvgov`。
- **从源码**——`go install github.com/JiangHe12/srvgov-cli@latest`(Go 1.25+)。

```bash
srvgov version
srvgov doctor -o json
```

</details>

---

## 🚀 快速上手(60 秒)

```bash
# 1. 定义服务器上下文(SSH 目标、密钥、标签)——主机密钥在首次连接时绑定
srvgov ctx set prod --server ssh://deploy@example.com:22 \
  --identity-file ~/.ssh/id_ed25519 --env production --label env=prod --label role=web --protected \
  --ticket OPS-123 --yes --allow-context-change
srvgov ctx use prod --ticket OPS-123 --yes --allow-context-change

# 2. 用结构化读取观测——免费(R0)且被审计
srvgov status -o json
srvgov logs --unit nginx --since "30 minutes ago" --lines 100 -o json

# 3. 运行前先预览命令风险——dry-run 只分类,不连 SSH
srvgov exec --dry-run "systemctl restart nginx" -o json

# 4. 直接跑一个读取(R0)
srvgov exec "uptime" -o json

# 5. 做一次受治理变更——重启服务是 R2:需理由 + 工单 + 确认
srvgov svc restart nginx --reason "apply reviewed config" --ticket OPS-123 --yes -o json
```

> 💡 **提示:** 创建生产上下文时加 `--protected`,之后 srvgov 会把该上下文里每个变更升一档(R2 → R3,额外需要 `--allow-destructive`)。

---

## 🔐 治理模型(最重要的部分)

一个结构感知的分类器读取**整条**命令并判定风险档。分类器的判定(而非你的意图)是权威的,且 fail-closed(未知/含糊 → 更高档)。

| 档位 | 涵盖范围 | 你必须提供 |
|:---:|---|---|
| **R0** | 已知只读命令与结构化观测(`status`、`ports`、`logs`、`file read`、`svc status`、`docker inspect`) | 无——但仍会被审计 |
| **R1** | 已知良性变更 | `--reason` **加** `--yes` |
| **R2** | 未知 / 升级命令;`svc` 生命周期;`docker start/stop/restart`;`file write` | `--reason`、非空 `--ticket`、**加** `--yes` |
| **R3** | 破坏性、特权、动态、或解析不确定的命令;`docker rm`;确认执行的 `audit prune` | 以上**再加**该操作专属的 `--allow-*` 标志 |

上下文创建/替换/切换/导入/凭据迁移、上下文删除以及角色分配/移除始终是 R3
治理控制变更。它们都需要 `--ticket`、`--yes`,并分别精确要求
`--allow-context-change`、`--allow-context-delete` 或
`--allow-role-change`。已有目标按变更前策略授权;新目标使用已持久化的
current context 策略;没有 current context 的首次引导仍必须提供完整 R3
输入。上下文切换按切换前已持久化的 current policy 授权;只有此前不存在
current 时,首次切换才使用所选目标的策略。
确认执行的审计清理同样固定为 R3。它按已持久化的 current context 策略
授权，并要求 `--confirm`、`--yes`、非空 `--ticket` 与精确的
`--allow-audit-prune`。

**受保护上下文把每个变更升一档**(R1→R2,R2→R3)。三条原则保证安全——尤其对自动化:

1. **风险与影响来自工具,而非猜测。** 用 `exec --dry-run` 取分类与所需授权;srvgov 宁可 fail-closed 也不猜。
2. **主机信任是严格的。** SSH 主机密钥首次使用时绑定(TOFU);已知主机的密钥变更或新类型一律拒绝、等待人工复核——没有不安全旁路。
3. **🤖 AI 智能体绝不能伪造 `--ticket`、任何 `--allow-*` 标志或高风险 `--yes`。** 它们是*人类*授权输入;智能体应上报「这步需要审批 X」然后停下。

---

## 📚 命令参考

`srvgov <命令> [标志]`。加 `-o json` 得机器可读输出,任意命令加 `--help` 看完整标志,`srvgov capabilities -o json` 看完整受治理命令面。

<details open>
<summary><b>exec</b> — 一条受治理命令</summary>

```bash
srvgov exec --dry-run "systemctl restart nginx" -o json   # 仅分类;不连 SSH、不产生审计事件
srvgov exec "uptime" -o json                               # R0
srvgov exec "touch /tmp/ready" --reason "标记就绪" --yes -o json                            # R1
srvgov exec "custom-maint" --reason "维护" --ticket OPS-123 --yes -o json                   # R2
srvgov exec "rm -rf /tmp/old" --reason "清理" --ticket OPS-123 --allow-destructive --yes -o json  # R3
```
</details>

<details>
<summary><b>观测</b> — 结构化 R0 读取(脱敏,绝不 <code>sudo</code>)</summary>

```bash
srvgov status -o json
srvgov ports  -o json
srvgov logs --unit nginx --since "30 minutes ago" --priority warning --lines 100 -o json
srvgov logs --file /var/log/nginx/error.log --grep "upstream" --lines 100 -o json
srvgov file read /etc/hosts --max-bytes 1048576 -o json
srvgov file stat /etc/hosts -o json
srvgov file list /var/log -o json
srvgov svc status nginx -o json
srvgov docker list -o json
srvgov docker inspect api -o json          # 固定安全字段子集;排除 Env
srvgov docker logs api --tail 100 -o json
```
</details>

<details>
<summary><b>控制</b> — 固定动词(R2 变更在受保护上下文升为 R3;<code>docker rm</code> 始终为 R3)</summary>

```bash
# systemd(一个字面 unit;无任意子命令)
srvgov svc restart nginx --reason "apply reviewed config" --ticket OPS-123 --yes -o json
#   动词:start | stop | restart | reload | enable | disable

# 文件写入(无 SFTP;审计只记路径指纹 + 字节数 + 内容 SHA-256)
srvgov file write /tmp/app.conf --content "enabled=true" --reason "update config" --ticket OPS-123 --yes -o json
#   不带 --content 时,仅在授权后读取 stdin,且 --yes 强制必需
#   两种形式都受 --max-bytes 限制(默认 1 MiB,硬上限 16 MiB)

# docker 容器生命周期(固定为 start | stop | restart | rm)
# 普通上下文中的 start/stop/restart 为 R2
srvgov docker restart api --reason "restart after deploy" --ticket OPS-123 --yes -o json
# rm 即使在普通上下文中也是破坏性 R3
srvgov docker rm retired-api --reason "remove retired container" --ticket OPS-123 --allow-destructive --yes -o json
```

敏感路径或受保护上下文会把普通 R2 写入/生命周期操作升到 R3,额外需要 `--allow-destructive`;`docker rm` 在所有上下文中本来就是 R3。`svc` 与 `docker` 动词**有意不**暴露任意 `systemctl` 或 `docker run/exec/build/compose/prune` 面——若人类明确需要固定集合之外的操作,用 `exec --dry-run`。
</details>

<details>
<summary><b>机群 fanout</b> — <code>--targets</code> / <code>--selector</code></summary>

```bash
srvgov status --targets web-a,web-b,web-c --concurrency 5 -o json
srvgov logs --selector env=prod,role=web --unit nginx --lines 100 -o json
srvgov exec --selector env=prod,role=web --dry-run "systemctl restart nginx" -o json
srvgov svc restart nginx --targets web-a,web-b --reason "rollout" --ticket OPS-123 --yes -o json
srvgov file stat /etc/hosts --targets web-a,web-b -o json
```

- `--selector key=value,key2=value2` 按上下文标签 AND 匹配。`--targets`、`--selector`、`--context` 不能组合使用。
- `status` / `ports` / `logs` 对所有目标有硬性 **R0 上限**(含回退命令)。
- 多目标 `exec` / `svc` / `file` / `docker` **在变更前先授权每个目标**;人类提供的理由/工单/确认/allow 标志会被复用,但对每个目标的有效风险、工单模式、RBAC **独立重新校验**。`file write` 会先执行并审计 R0 元数据探测,绑定并分类每个规范化父目录。
- 用 `--dry-run` 查看解析出的目标集与每个目标的 `maxEffectiveRiskTier`。dry-run 绝不授权或变更;为防止 symlink 导致风险低报,`file write --dry-run` 只会连接并审计必要的 R0 父目录探测,其他 dry-run 不连接也不审计。结果按目标排序,远程失败相互隔离。
</details>

<details>
<summary><b>上下文、角色、审计与诊断</b></summary>

```bash
# 上下文(标签是非密元数据;每次 ctx set 会替换该上下文的标签集)
srvgov ctx set <name> --server ssh://user@host:22 --identity-file <key> \
  [--password <secret> --credential-backend <keychain|encrypted-file>] \
  [--env <e>] [--label k=v] [--protected] --ticket OPS-123 --yes --allow-context-change
srvgov ctx use <name> --ticket OPS-123 --yes --allow-context-change
srvgov ctx list|current
srvgov ctx delete <name> --ticket OPS-123 --yes --allow-context-delete
srvgov ctx export <name> -o json     # 绝不导出明文密码/私钥口令
srvgov ctx import -f ctx.yaml [--rename <new>] --ticket OPS-123 --yes --allow-context-change -o json
srvgov ctx migrate-credentials --to encrypted-file [--context <name>] \
  --ticket OPS-123 --yes --allow-context-change -o json

# RBAC(写路径):reader → R0,writer → R2,admin → R3
srvgov ctx role set <ctx> --target-operator 'alice@ops-host' --role writer \
  --ticket OPS-123 --yes --allow-role-change -o json
srvgov ctx role unset <ctx> --target-operator 'alice@ops-host' \
  --ticket OPS-123 --yes --allow-role-change -o json
srvgov ctx role list <ctx> -o json

# 审计(防篡改;读取时再次脱敏)
srvgov audit query [--limit 50] [--type authorization.denied] [--status denied] -o json
srvgov audit verify -o json
srvgov audit prune (--before <30d|YYYY-MM-DD> | --keep-last <n>) -o json
srvgov audit prune (--before <30d|YYYY-MM-DD> | --keep-last <n>) \
  --confirm --ticket OPS-123 --allow-audit-prune --yes -o json

# 预览无需授权。确认清理会在审计锁内重新绑定完整轮转文件集合；删除已认证
# 轮转日志前，v2 checkpoint 必须先持久推进。清理的 intent/outcome 写入同目录
# sibling `.<audit-base>-control`，绝不写回清理目标或污染其轮转命名空间。

# 诊断与生态
srvgov doctor -o json
srvgov capabilities -o json
srvgov completion bash|zsh|fish|powershell
srvgov install <agent> --skills      # 安装 srvgov AI 技能(claude、codex …)
srvgov version
```

`plain-yaml` 后端会拒绝新的明文密码和私钥口令。使用 `keychain` 或
`encrypted-file` 时，`ctx set` 会把秘密写入对应后端，配置文件只保存
credstore 引用。旧配置中的内联明文为兼容迁移而继续可读，应尽快执行
`ctx migrate-credentials`。导出绝不输出明文（`--include-credentials` 已禁用），导入只接受
已脱敏凭据或现有 credstore 引用。

旧版 `srvgov.io/context/v1` 文件仍可通过内存转换读取。读取不会改写文件；
下一次经授权的上下文变更会把它原子升级为当前格式。

若审计日志已加密，请在执行 `audit query` 或 `audit verify` 前设置
`SRVGOV_AUDIT_PRIVATE_KEY`。密钥从环境读取，绝不会回显。

RBAC 键必须与审计事件记录的可信 `OS-user@hostname` 身份完全一致。启用新策略前
应人工复核并迁移旧的自由格式角色键;无法匹配可信身份的角色条目不能为自己的
修复授权。
</details>

---

## 🛡️ 安全模型

- **严格 TOFU 主机密钥绑定**——首次绑定会在 stderr 报告地址、密钥类型与指纹，保持 JSON stdout 可供机器解析；已知主机的密钥变更或新类型为硬失败,需人工重新绑定。无不安全旁路。
- **fail-closed、结构感知分类**——分类器检查管道、重定向、链式、替换与特权;未知或含糊命令升档,绝不降档。
- **可信本机身份**——授权与审计身份从本机 OS 账号加 hostname 推导。已弃用的全局 `--operator` 身份标志与 `SRVGOV_OPERATOR` 会被忽略(`audit query --operator` 仍是读取筛选条件)。这无法区分运行在同一 OS 账号下的 AI 进程和人工进程;若必须区分,应使用单独受保护的操作员账号或外部签名审批边界。
- **读取审计失败关闭**——受治理的 R0 读取会在访问后端前持久化 `intent`，并在释放任何结果前持久化 `outcome`。任一必需记录无法持久化时，读取返回 `LOCAL_IO_ERROR`，且不释放后端输出。
- **两阶段变更审计**——最终校验和授权通过后,每个本地或远程变更都在首个副作用前持久化 `intent`,结束后持久化 `outcome`;两者共享随机 `mutationId`。机群 fanout 还会记录一对批次事件,并为每个目标各记一对事件。
- **提交状态感知的审计恢复**——审计记录使用带认证的 v2 envelope。明确未提交的 `intent` 会阻止变更；明确未提交的 `outcome` 才进入私有持久 replay spool 并返回 `AUDIT_INCOMPLETE`，已知提交的结果绝不再次排队。提交状态不确定时，记录会原子隔离为 `.indeterminate`，禁止自动重放，必须人工核对；已经开始的并发变更仍会把自己的 outcome 安全排在 marker 之后，但不会再次尝试审计 append。崩溃恢复仍可能是至少一次语义，消费方应按 `(mutationId, phase)` 去重。
- **输出前与审计前均脱敏**——密钥绝不到达你的终端或审计日志。`file write` 只审计路径指纹、字节数与内容 SHA-256——绝不记录原始路径或文件内容。
- **变更明细仅留指纹**——工单、理由、命令、目标、文件路径、输出和后端错误消息都不会以原文持久化;仅保存带域分隔的 SHA-256 指纹和字节数用于关联。
- **有边界的取消语义**——运行中的 SSH 命令被取消或达到 context deadline 时，srvgov 会先发送 `SIGTERM`，再关闭 session。标准 OpenSSH 会把该请求施加到 session 进程组，从而停止普通 shell 及其子进程。忽略 `SIGTERM` 或主动脱离到另一个 session/进程组的命令、拒绝 SSH signal request 的 forced-command 配置，以及不提供兼容进程组信号语义的服务器，不在此保证范围内。
- **非 PTY 执行**、有界 SSH 捕获、无 SFTP——stdout 与 stderr 各自封顶
  16 MiB + 1 字节。文件写入在授权后先完整读入有界本地缓冲区,在目标端
  核对长度与 SHA-256,再从同目录私有临时文件原子重命名。既有普通文件
  保留 owner/group/mode；GNU 属性复制可用时还保留 ACL/xattr；新文件仅
  owner 可访问。符号链接和非普通文件会被拒绝。
- **变更结果明确**——远程变更已完成但捕获输出超出上限时，srvgov 返回
  `PARTIAL_FAILURE`；命令发出后的传输失败视为结果不确定。两种情况都应先
  核验目标状态，再决定是否重试。

---

## 🤖 给 AI 智能体

- 先跑 `srvgov capabilities -o json` 了解受治理命令面;处处用 `-o json`。
- 风险与所需授权取自 `exec --dry-run`(及各命令的 `--dry-run`),**绝不**靠自己推理。
- **绝不自我填入 `--ticket`、任何 `--allow-*` 标志或高风险 `--yes`**——把所需人类审批上报,然后停下。用 `--non-interactive` 让缺失的授权被返回,而非弹出提示。

```bash
srvgov install claude --skills     # 也支持:codex、opencode、copilot、cursor、windsurf、aider、cc-switch
```

---

## 🔏 供应链可信与校验

- **已验证发布标签**——仅当 signed annotated tag 经 GitHub 验证，且精确匹配 `package.json`、`CHANGELOG.md` 与最新拉取的 `origin/main` 时才开始发布；CI 与真实 OpenSSH 集成会在该标签提交上重跑。
- **签名二进制**——每个发布产物都用 [cosign](https://github.com/sigstore/cosign) 无密钥(OIDC)签名;签名的 `checksums.txt` 覆盖全平台。
- **npm provenance**——由 CI 经 OpenID Connect 发布,带 [provenance 溯源声明](https://docs.npmjs.com/generating-provenance-statements),将包与本仓库及工作流关联。
- **校验式安装**——npm postinstall 只信任受 npm provenance 绑定、嵌入 `package.json` 的六个平台 SHA-256 摘要。镜像只能提供二进制字节,不能提供校验数据;校验后的文件会先 fsync,再原子替换旧文件,且不存在跳过校验的开关。
- **认证审计**——`srvgov audit verify` 校验 v2 envelope，并在 JSON 及人类可读输出中报告认证/旧版/加密计数、完整性、序列、checkpoint、截断、锁、逐文件时间顺序和 quarantine 状态；`--strict` 会在任一问题出现时失败。

---

## 🏗️ 从源码构建与贡献

```bash
git clone https://github.com/JiangHe12/srvgov-cli && cd srvgov-cli
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal      # 必须无输出
golangci-lint run --timeout=5m
go vet -tags=integration ./...
npm pack --dry-run
```

`integration.yml` 工作流会在 race detector 下对固定摘要的临时 OpenSSH
容器运行 integration-tagged 测试，覆盖 SSH 取消/超时及远程文件
read/stat/list/原子写核心链路，并验证大小与摘要拒绝。它支持 nightly、手动触发，
也是发布门禁。真实 systemd 服务操作和外部多操作系统 VM 仍是明确的手动验证边界；
CI 设置 `SRVGOV_IT_REQUIRED=1`，因此缺少 fixture 变量时会失败而不是跳过；
本地未设置该标志时仍会跳过。该测试套件绝不连接生产主机。

详见 [CONTRIBUTING.md](CONTRIBUTING.md) 与安全策略 [SECURITY.md](SECURITY.md)。

srvgov-cli 构建于共享治理引擎 [`opskit-core`](https://github.com/JiangHe12/opskit-core) 之上,是面向 AI 智能体的 **opskit** 治理型 CLI 家族的一员——同族还有 [`dbgov-cli`](https://www.npmjs.com/package/dbgov-cli)(数据库)、[`cfgov-cli`](https://www.npmjs.com/package/cfgov-cli)(配置 & Sentinel 规则)与 [`mqgov-cli`](https://www.npmjs.com/package/mqgov-cli)(消息中间件)。

---

## 📄 许可证

[MIT](LICENSE) © JiangHe12
