---
name: srvgov-cli
description: Governed remote server command execution via SSH with R0-R3 authorization, strict TOFU, redaction, and audit.
allowed-tools: Bash(srvgov:*), Bash(srvgov-cli:*)
---

# srvgov-cli

`srvgov` is a governed SSH command runner for AI agents and operators. It
classifies a complete shell command, applies the active context's governance,
executes without a PTY over strict TOFU SSH, redacts output, and appends an
audit event.

**Always use `-o json` for agent-consumed output.**

## Governance Rules

| Risk | Meaning | Required authorization |
|---|---|---|
| R0 | known read-only command | none; execution is still audited |
| R1 | known benign change | `--reason` and `--yes` |
| R2 | unknown or elevated command | `--reason`, non-empty `--ticket`, and `--yes` |
| R3 | destructive, privileged, dynamic, or parser-uncertain command | `--reason`, `--ticket`, `--allow-destructive`, and `--yes` |

Protected contexts raise R1 to R2 and R2 to R3. The command classifier and
effective risk reported by srvgov are authoritative.

Never auto-supply `--ticket`, `--allow-destructive`, or high-risk `--yes`.
These values must come from the human operator. Use `exec --dry-run` to obtain
risk and required authorization; impact must come from CLI output, never model guesses.

## Context Setup

Create and select a context:

```bash
srvgov ctx set prod --server ssh://deploy@example.com:22 --identity-file ~/.ssh/id_ed25519 --env production --protected -o json
srvgov ctx use prod -o json
srvgov ctx current -o json
```

Inspect or delete contexts:

```bash
srvgov ctx list -o json
srvgov ctx delete old-host -o json
```

Portable contexts and local RBAC:

Use `ctx role`, `ctx export`, `ctx import`, and `ctx migrate-credentials` for
local governance operations.

```bash
srvgov ctx role set prod --target-operator alice --role writer -o json
srvgov ctx role list prod -o json
srvgov ctx role unset prod --target-operator alice -o json
srvgov ctx export prod > prod.ctx.yaml
srvgov ctx import -f prod.ctx.yaml --rename prod-copy --yes -o json
srvgov ctx migrate-credentials --to encrypted-file --context prod -o json
```

`ctx export` redacts literal password and SSH identity passphrase by default.
Credstore references are preserved. `--include-credentials` is only for
plain-yaml contexts and must not be used unless the human operator asks for it.

Passwords and private-key passphrases may be stored through the configured
credential backend. Do not place credentials in command text.

## Observe Before Acting

Prefer structured observation before constructing an action:

```bash
srvgov status -o json
srvgov ports -o json
srvgov logs --unit nginx --since "30 minutes ago" --priority warning --lines 100 -o json
srvgov logs --file /var/log/nginx/error.log --grep "upstream" --lines 100 -o json
```

These commands use the same authoritative cmdclass and authorization path as
`exec`, audit R0 reads, never add `sudo`, and redact structured fields. Treat
missing PID/process fields as a permission-limited observation, not permission
to retry with privilege escalation. Use returned status, ports, and logs as the
observe step in observe→act→verify.

## Service Control

Use the fixed `svc` verbs instead of constructing raw systemctl actions:

```bash
srvgov svc status nginx -o json
srvgov svc restart nginx --reason "apply reviewed configuration" --ticket OPS-123 --yes -o json
```

`svc status` is an audited R0 read. `start`, `stop`, `restart`, `reload`,
`enable`, and `disable` are classified by cmdclass as R2 and require a
human-supplied reason, ticket, and confirmation. A protected context raises
them to R3 and also requires a human-supplied `--allow-destructive`. Never
synthesize these authorization values. `svc` accepts one literal unit and
does not expose arbitrary, power, isolate, or mask systemctl subcommands.

## File Operations

Use governed structured reads before changing a file:

```bash
srvgov file read /etc/hosts --max-bytes 1048576 -o json
srvgov file stat /etc/hosts -o json
srvgov file list /var/log -o json
```

These are audited R0 commands. Returned content and structured fields are
redacted. Reads are bounded; do not raise `--max-bytes` without a concrete need.

For a human-authorized write:

```bash
srvgov file write /tmp/app.conf --content "enabled=true" \
  --reason "update reviewed configuration" --ticket OPS-123 --yes -o json
```

Ordinary writes are R2. Sensitive paths or protected contexts raise them to R3
and require human-supplied `--allow-destructive`. Never synthesize reason,
ticket, confirmation, or allow flags. Without `--content`, stdin is streamed as
file content and explicit `--yes` is mandatory; with `--content`, stdin is
never read. Writes are non-atomic in this release. Audit stores only path,
bytes written, and SHA-256, never content. The command does not use SFTP.

## Preview Before Execution

Always preview a command whose impact is not already established:

```bash
srvgov exec --dry-run "systemctl status nginx" -o json
srvgov exec --dry-run "touch /tmp/deploy-ready" -o json
srvgov exec --dry-run "rm -rf /tmp/old-release" -o json
```

Dry-run classifies only. It does not connect to SSH, execute the command, or
create an execution audit event.

## Execute

R0:

```bash
srvgov exec "uptime" -o json
```

R1 after explicit human confirmation:

```bash
srvgov exec "touch /tmp/deploy-ready" --reason "mark deployment ready" --yes -o json
```

R2 after a human supplies the ticket:

```bash
srvgov exec "custom-maintenance-command" --reason "scheduled maintenance" --ticket OPS-123 --yes -o json
```

R3 after a human supplies both ticket and destructive allow flag:

```bash
srvgov exec "rm -rf /tmp/old-release" --reason "remove failed release" --ticket OPS-123 --allow-destructive --yes -o json
```

Use `--context <name>` to override the current context. Automation should use
`--non-interactive`; missing authorization must be returned to the operator,
not synthesized by the agent.

## Audit And Diagnostics

Use `capabilities`, `audit verify`, and `audit prune` for self-description and
audit maintenance.

```bash
srvgov capabilities -o json
srvgov audit query --limit 50 -o json
srvgov audit query --type authorization.denied --status denied -o json
srvgov audit verify -o json
srvgov audit prune --keep-last 20 -o json
srvgov doctor -o json
srvgov version -o json
```

Audit query output is redacted again before being returned. SSH host keys are
pinned by strict trust on first use. A changed key or a new key type for an
already known host is rejected and requires manual pin review.
