<div align="center">

# srvgov-cli

**Governed remote-server operations over SSH for humans _and_ AI agents.**

Run commands, control services, edit files, and manage containers on remote machines — every command is classified for risk, previewable, runs over strict TOFU-pinned SSH, is redacted, and is audited. Safe enough to fan out across a fleet, and safe enough to hand to an AI.

[![npm version](https://img.shields.io/npm/v/srvgov-cli.svg)](https://www.npmjs.com/package/srvgov-cli)
[![CI](https://github.com/JiangHe12/srvgov-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/JiangHe12/srvgov-cli/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/srvgov-cli.svg)](LICENSE)
[![signed](https://img.shields.io/badge/release-cosign%20%2B%20npm%20provenance-blue.svg)](#-trust--verification)

[English](README.md) · [简体中文](README_zh.md)

</div>

---

## 🧭 What is this? (read me first)

SSH-ing into a production server and running commands is powerful and terrifying in equal measure: one `rm -rf` in the wrong directory, one `systemctl stop` of the wrong service, and there's no preview, no second opinion, and often no record. Giving a raw shell to an automation script or an AI agent multiplies the risk.

**srvgov-cli wraps every remote operation in guardrails.** Think of it as a careful SRE standing between you and the server:

- 🧠 **Classifies the command before running it** — a structure-aware classifier reads the *whole* command line (pipes, redirects, `sudo`, substitutions) and assigns a risk level. Unknown or ambiguous? It fails closed to a higher tier.
- 🛡️ **Scales the friction to the danger** — a read just runs; a benign change needs a reason and a confirmation; a destructive or privileged command needs a change ticket *and* an explicit "allow destructive" flag.
- 👀 **Prefers structured observation** — `status`, `ports`, `logs`, `file`, `svc`, and `docker` give you safe, fixed-shape reads instead of hand-rolled shell.
- 🔒 **Pins host keys with strict TOFU** — a changed or new-type key for a known host is a hard failure, never a silent accept.
- 🛰️ **Fans out across a fleet safely** — target many servers by name or label; every target is authorized *before any* SSH starts, and each is audited separately.
- 🤖 **Is safe to hand to an AI agent** — it can observe and preview freely, but **cannot** invent the human approvals destructive actions require.

Output is redacted and every action lands in a tamper-evident audit log.

---

## ✨ Features

| | |
|---|---|
| ⌨️ **Governed `exec`** | run one shell command; a fail-closed, structure-aware classifier sets its risk tier and required authorization. |
| 👀 **Structured observation** | `status`, `ports`, `logs`, `file read/stat/list`, `svc status`, `docker list/inspect/logs` — audited R0 reads, redacted, no `sudo`. |
| 🔧 **Fixed-verb control** | `svc start/stop/restart/reload/enable/disable`, `file write`, `docker start/stop/restart/rm` — no arbitrary `systemctl`/`docker` surface. |
| 🚦 **R0–R3 governance** | every command risk-classified; protected contexts escalate one tier; AI callers can never self-authorize. |
| 🛰️ **Fleet fanout** | `--targets a,b,c` or `--selector key=value` (label match); reads are capped at R0; writes authorize **all** targets before any SSH. |
| 🔒 **Strict TOFU SSH** | host keys pinned on first use; a changed key is rejected pending manual review. Non-PTY execution. |
| 👥 **RBAC & contexts** | per-context `reader` / `writer` / `admin` roles; portable context export/import; credential backends. |
| 🧹 **Redaction everywhere** | secrets scrubbed from output **and** before audit persistence; file writes audit only path + bytes + SHA-256, never content. |
| 📜 **Tamper-evident audit** | every action (including denials) hash-chained; `audit verify` detects tampering. |
| 🔏 **Trusted supply chain** | **cosign-signed** binaries, npm **provenance**, and a **SHA-256**-verified installer. |

---

## 📦 Install

```bash
npm install -g srvgov-cli
```

This installs a tiny launcher; on first run it downloads the right pre-built binary for your OS/arch from the signed [GitHub Release](https://github.com/JiangHe12/srvgov-cli/releases) and **verifies its SHA-256** before use. Requires Node.js ≥ 14 for the installer (the CLI itself is a self-contained Go binary).

<details>
<summary>Other ways to install</summary>

- **Direct download** — grab the binary from the [Releases page](https://github.com/JiangHe12/srvgov-cli/releases), verify it against the cosign-signed `checksums.txt`, put it on your `PATH`, and rename it to `srvgov`.
- **From source** — `go install github.com/JiangHe12/srvgov-cli@latest` (Go 1.22+).

```bash
srvgov version
srvgov doctor -o json
```

</details>

---

## 🚀 Quick start (60 seconds)

```bash
# 1. Define a server context (SSH target, key, labels) — host key is pinned on first connect
srvgov ctx set prod --server ssh://deploy@example.com:22 \
  --identity-file ~/.ssh/id_ed25519 --env production --label env=prod --label role=web --protected
srvgov ctx use prod

# 2. Observe with structured reads — these are free (R0) and audited
srvgov status -o json
srvgov logs --unit nginx --since "30 minutes ago" --lines 100 -o json

# 3. Preview any command's risk before running it — dry-run only classifies, no SSH
srvgov exec --dry-run "systemctl restart nginx" -o json

# 4. Run a read (R0) directly
srvgov exec "uptime" -o json

# 5. Make a governed change — a service restart is R2: needs reason + ticket + confirmation
srvgov svc restart nginx --reason "apply reviewed config" --ticket OPS-123 --yes -o json
```

> 💡 **Tip:** create production contexts with `--protected`. srvgov then raises every change one risk tier in that context (R2 → R3, additionally requiring `--allow-destructive`).

---

## 🔐 The governance model (the important part)

A structure-aware classifier reads the **whole** command and assigns a risk tier. The classifier's verdict — not your intention — is authoritative, and it fails closed (unknown/ambiguous → higher tier).

| Tier | What it covers | What you must provide |
|:---:|---|---|
| **R0** | Known read-only commands & structured observation (`status`, `ports`, `logs`, `file read`, `svc status`, `docker inspect`) | Nothing — but it's still audited |
| **R1** | Known benign changes | `--reason` **and** `--yes` |
| **R2** | Unknown / elevated commands; `svc` & `docker` lifecycle; `file write` | `--reason`, a non-empty `--ticket`, **and** `--yes` |
| **R3** | Destructive, privileged, dynamic, or parser-uncertain commands | the above **plus** `--allow-destructive` |

**Protected contexts raise every change one tier** (R1→R2, R2→R3). Three rules keep this safe — especially for automation:

1. **Risk & impact come from the tool, not a guess.** Use `exec --dry-run` to get the classification and required authorization. srvgov fails closed rather than guessing.
2. **Host trust is strict.** SSH host keys are pinned on first use (TOFU); a changed or new-type key for a known host is rejected pending manual review — there is no insecure bypass.
3. **🤖 AI agents must never invent `--ticket`, `--allow-destructive`, or a high-risk `--yes`.** Those are *human* authorization inputs. An agent should surface "this needs approval X" and stop.

---

## 📚 Command reference

`srvgov <command> [flags]`. Add `-o json` for machine-readable output, `--help` on any command for its full flags, and `srvgov capabilities -o json` for the full governed surface.

<details open>
<summary><b>exec</b> — one governed command</summary>

```bash
srvgov exec --dry-run "systemctl restart nginx" -o json   # classify only; no SSH, no audit event
srvgov exec "uptime" -o json                               # R0
srvgov exec "touch /tmp/ready" --reason "mark ready" --yes -o json                         # R1
srvgov exec "custom-maint" --reason "maintenance" --ticket OPS-123 --yes -o json           # R2
srvgov exec "rm -rf /tmp/old" --reason "cleanup" --ticket OPS-123 --allow-destructive --yes -o json  # R3
```
</details>

<details>
<summary><b>Observe</b> — structured R0 reads (redacted, never <code>sudo</code>)</summary>

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
srvgov docker inspect api -o json          # fixed safe field subset; excludes Env
srvgov docker logs api --tail 100 -o json
```
</details>

<details>
<summary><b>Control</b> — fixed verbs (R2, or R3 in protected contexts)</summary>

```bash
# systemd (one literal unit; no arbitrary subcommands)
srvgov svc restart nginx --reason "apply reviewed config" --ticket OPS-123 --yes -o json
#   verbs: start | stop | restart | reload | enable | disable

# file write (no SFTP; audit stores path + bytes + SHA-256, never content)
srvgov file write /tmp/app.conf --content "enabled=true" --reason "update config" --ticket OPS-123 --yes -o json
#   without --content, stdin is streamed as the file body and --yes is mandatory

# docker container lifecycle (fixed to start | stop | restart | rm)
srvgov docker restart api --reason "restart after deploy" --ticket OPS-123 --yes -o json
```

Sensitive paths or protected contexts raise writes/lifecycle to R3 and additionally require `--allow-destructive`. The `svc` and `docker` verbs intentionally do **not** expose arbitrary `systemctl` or `docker run/exec/build/compose/prune` surface — use `exec --dry-run` if a human explicitly needs something outside the fixed set.
</details>

<details>
<summary><b>Fleet fanout</b> — <code>--targets</code> / <code>--selector</code></summary>

```bash
srvgov status --targets web-a,web-b,web-c --concurrency 5 -o json
srvgov logs --selector env=prod,role=web --unit nginx --lines 100 -o json
srvgov exec --selector env=prod,role=web --dry-run "systemctl restart nginx" -o json
srvgov svc restart nginx --targets web-a,web-b --reason "rollout" --ticket OPS-123 --yes -o json
srvgov file stat /etc/hosts --targets web-a,web-b -o json
```

- `--selector key=value,key2=value2` AND-matches context labels. `--targets`, `--selector`, and `--context` cannot be combined.
- `status` / `ports` / `logs` have a hard **R0 ceiling** across all targets (including fallbacks).
- Multi-target `exec` / `svc` / `file` / `docker` **authorize every target first** and start no SSH unless all targets pass; human reason/ticket/confirmation/allow flags are reused but **re-validated independently** against each target's effective risk, ticket pattern, and RBAC.
- Use `--dry-run` to inspect the resolved target set and each target's `maxEffectiveRiskTier` — dry-run never connects, authorizes, or audits. Results are target-sorted, failures isolated, each target audited separately.
</details>

<details>
<summary><b>Contexts, roles, audit & diagnostics</b></summary>

```bash
# Contexts (labels are non-secret; each ctx set replaces the label set)
srvgov ctx set <name> --server ssh://user@host:22 --identity-file <key> [--env <e>] [--label k=v] [--protected]
srvgov ctx use|list|current|delete
srvgov ctx export <name> [--include-credentials] -o json     # redacts password/passphrase by default
srvgov ctx import -f ctx.yaml [--rename <new>] --yes -o json
srvgov ctx migrate-credentials --to encrypted-file [--context <name>] -o json

# RBAC (write paths): reader → R0, writer → R2, admin → R3
srvgov ctx role set <ctx> --target-operator alice --role writer -o json
srvgov ctx role list <ctx> -o json

# Audit (tamper-evident; output re-redacted on read)
srvgov audit query [--limit 50] [--type authorization.denied] [--status denied] -o json
srvgov audit verify -o json
srvgov audit prune (--before <30d|YYYY-MM-DD> | --keep-last <n>) [--confirm] -o json

# Diagnostics & ecosystem
srvgov doctor -o json
srvgov capabilities -o json
srvgov completion bash|zsh|fish|powershell
srvgov install <agent> --skills      # install the srvgov AI skill (claude, codex, …)
srvgov version
```
</details>

---

## 🛡️ Security model

- **Strict TOFU host-key pinning** — keys pinned on first connect; a changed or new-type key for a known host is a hard failure requiring manual re-pin. No insecure bypass.
- **Fail-closed, structure-aware classification** — the classifier inspects pipes, redirects, chaining, substitutions, and privilege; unknown or ambiguous commands escalate, never downgrade.
- **Redaction before output and before audit** — secrets never reach your terminal or the audit log. `file write` audits only path, byte count, and SHA-256 — never file content.
- **Non-PTY execution**, bounded reads, and no SFTP — the attack surface is deliberately small.

---

## 🤖 For AI agents

- Run `srvgov capabilities -o json` first to learn the governed surface; use `-o json` everywhere.
- Get risk and required authorization from `exec --dry-run` (and each command's `--dry-run`), **never** from your own reasoning.
- **Never self-fill `--ticket`, `--allow-destructive`, or a high-risk `--yes`** — surface the required human approval and stop. Use `--non-interactive` so missing authorization is returned, not prompted.

```bash
srvgov install claude --skills     # also: codex, opencode, copilot, cursor, windsurf, aider, cc-switch
```

---

## 🔏 Trust & verification

- **Signed binaries** — every release artifact is signed with [cosign](https://github.com/sigstore/cosign) (keyless / OIDC); a signed `checksums.txt` covers all platforms.
- **npm provenance** — published from CI via OpenID Connect with [provenance attestations](https://docs.npmjs.com/generating-provenance-statements) tying the package to this repo and workflow.
- **Verified installs** — the npm postinstall checks the binary's SHA-256 against the signed `checksums.txt` before installing.
- **Tamper-evident audit** — `srvgov audit verify` re-walks the log and reports any gap or modification.

---

## 🏗️ Build from source & contribute

```bash
git clone https://github.com/JiangHe12/srvgov-cli && cd srvgov-cli
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal      # must print nothing
golangci-lint run --timeout=5m
go vet -tags=integration ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and the security policy in [SECURITY.md](SECURITY.md).

srvgov-cli is built on the shared [`opskit-core`](https://github.com/JiangHe12/opskit-core) governance engine and is part of the **opskit** family of governed CLIs for AI agents — alongside [`cfgov-cli`](https://www.npmjs.com/package/cfgov-cli) (config & Sentinel rules) and [`dbgov-cli`](https://www.npmjs.com/package/dbgov-cli) (databases).

---

## 📄 License

[MIT](LICENSE) © JiangHe12
