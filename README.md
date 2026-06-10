# srvgov-cli

[English](README.md) | [中文](README_zh.md)

Governed remote server command execution for AI agents and operators. `srvgov`
combines fail-closed command classification, R0-R3 authorization, strict TOFU
SSH host-key pinning, output redaction, and structured audit records.

## Install

```bash
npm install -g srvgov-cli
# or
go install github.com/JiangHe12/srvgov-cli@latest
```

GitHub Releases provide Linux, macOS, and Windows binaries for amd64 and arm64.
The npm package downloads the matching release binary and verifies SHA-256
checksums by default.

## Quickstart

```bash
srvgov ctx set dev --server ssh://alice@example.com:22 --identity-file ~/.ssh/id_ed25519 -o json
srvgov ctx use dev -o json
srvgov exec --dry-run "uptime" -o json
srvgov exec "uptime" -o json
srvgov audit --limit 20 -o json
```

Use `-o json` for automation and AI agents.

## Governance Model

| Risk | Meaning | Authorization |
|---|---|---|
| R0 | known read-only command | free to run, still audited |
| R1 | known benign change | `--reason` and `--yes` |
| R2 | unknown or elevated command | `--reason`, non-empty `--ticket`, and `--yes` |
| R3 | destructive, privileged, dynamic, or parser-uncertain command | `--reason`, `--ticket`, `--allow-destructive`, and `--yes` |

Protected contexts raise R1 to R2 and R2 to R3. AI agents must never auto-fill
`--ticket`, `--allow-destructive`, or high-risk `--yes`. Use `exec --dry-run`
to obtain the classifier's risk and required authorization; do not guess impact.

## Contexts

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

Context output never includes passwords, private-key contents, passphrases, or
identity-file paths.

Portable context export uses `srvgov.io/ctx-export/v1`. Literal password and
SSH identity passphrase values are redacted by default; credstore references are
preserved. `--include-credentials` is limited to plain-yaml contexts.

## Governed Execution

Preview without connecting or executing:

```bash
srvgov exec --dry-run "touch /tmp/deploy-ready" -o json
```

Execute according to the reported tier:

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

Commands run without a PTY. stdout, stderr, command text, and audit fields are
redacted before output or persistence. A remote non-zero exit returns structured
output and process exit code 7 (`BACKEND_ERROR`).

## SSH Trust And Credentials

The first connection to an unknown `host:port` pins its SSH public key in
`~/.srvgov/known_hosts`. Later key mismatches, including an unpinned key type
for an already known address, are rejected. Host-key rotation requires manual
review and removal of the old pin; there is no insecure bypass.

Authentication order is private key, SSH agent, then password, subject to the
context's `--auth-method` preference. Passwords and key passphrases may use
opskit-core credential-store references. Credentials and raw SSH output are not
logged by the transport.

## Audit And Diagnostics

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

Audit records live at `~/.srvgov/audit.log` by default and include effective
risk, authorization status, target, redacted command/output, exit code, and
error details.

`capabilities` reports the current command surface, `srvgov.io/context/v1`,
`srvgov.io/audit/v1`, R0-R3 authorization rules, `--allow-destructive`, JSONL
audit, RBAC reader/writer/admin, dry-run, strict TOFU, and redaction.

## AI Skill

```bash
srvgov install claude --skills
srvgov install codex --skills
srvgov install /custom/skills/path --skills
```

## Build

```bash
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal
golangci-lint run --timeout=5m
go vet -tags=integration ./...
```

## Contributing, Security, License

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[LICENSE](LICENSE).
