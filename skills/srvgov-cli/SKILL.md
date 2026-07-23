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

Governed R0 reads are fail-closed around audit persistence: an `intent` must be
durable before backend access, and an `outcome` must be durable before any
result is released. If either append fails, return `LOCAL_IO_ERROR` and withhold
backend output.

Protected contexts raise R1 to R2 and R2 to R3. The command classifier and
effective risk reported by srvgov are authoritative.

Context create/replace/selection/import/credential migration, context deletion,
and role assignment/removal are always R3 control changes. They require `--ticket`,
`--yes`, and respectively `--allow-context-change`,
`--allow-context-delete`, or `--allow-role-change`. Existing targets use their
pre-change policy. New targets use the persisted current context's policy; an
empty bootstrap still requires the complete R3 authorization. Context
selection uses the old persisted current policy; only a first selection with no
current context uses the selected target's policy.

Confirmed `audit prune` is also fixed R3. It uses the persisted current-context
policy and requires human-supplied `--confirm`, `--yes`, `--ticket`, and exact
`--allow-audit-prune`. Preview runs before authorization and never deletes.

Never auto-supply `--ticket`, `--allow-destructive`,
`--allow-context-change`, `--allow-context-delete`, `--allow-role-change`,
`--allow-audit-prune`, or high-risk `--yes`.
These values must come from the human operator. Use `exec --dry-run` to obtain
risk and required authorization; impact must come from CLI output, never model guesses.

Authorization and audit identity are derived from the local OS account plus
hostname. The global `--operator` identity input and `SRVGOV_OPERATOR` are
deprecated compatibility inputs and are ignored (`audit query --operator`
remains a read filter). This boundary cannot distinguish an AI process from a
human process under the same OS account; use a separately protected operator
account or an external signed approval boundary when that distinction matters.

## Context Setup

Create and select a context:

```bash
srvgov ctx set prod --server ssh://deploy@example.com:22 \
  --identity-file ~/.ssh/id_ed25519 --env production \
  --label env=prod --label role=web --protected \
  --ticket OPS-123 --yes --allow-context-change -o json
srvgov ctx use prod --ticket OPS-123 --yes --allow-context-change -o json
srvgov ctx current -o json
```

Inspect or delete contexts:

```bash
srvgov ctx list -o json
srvgov ctx delete old-host \
  --ticket OPS-123 --yes --allow-context-delete -o json
```

Portable contexts and local RBAC:

Use `ctx role`, `ctx export`, `ctx import`, and `ctx migrate-credentials` for
local governance operations.

```bash
srvgov ctx role set prod --target-operator 'alice@ops-host' --role writer \
  --ticket OPS-123 --yes --allow-role-change -o json
srvgov ctx role list prod -o json
srvgov ctx role unset prod --target-operator 'alice@ops-host' \
  --ticket OPS-123 --yes --allow-role-change -o json
srvgov ctx export prod > prod.ctx.yaml
srvgov ctx import -f prod.ctx.yaml --rename prod-copy \
  --ticket OPS-123 --yes --allow-context-change -o json
srvgov ctx migrate-credentials --to encrypted-file --context prod \
  --ticket OPS-123 --yes --allow-context-change -o json
```

Role keys must exactly match the trusted `OS-user@hostname` identity shown in
audit events. Older free-form role keys require human-reviewed migration; a
non-matching role cannot authorize its own repair.

`ctx export` never emits a literal password or SSH identity passphrase.
Credstore references are preserved, and `--include-credentials` is disabled.
`ctx import` accepts only redacted credentials or existing credstore
references.

Context labels are non-secret metadata. A `ctx set` call replaces that
context's label set with the `--label key=value` flags supplied in the call.

Literal passwords and private-key passphrases require `keychain` or
`encrypted-file`; `ctx set` stores them there and persists only credstore
references. Legacy inline credentials remain readable for migration
compatibility and should be moved with `ctx migrate-credentials`. Do not place
credentials in remote command text.

Legacy `srvgov.io/context/v1` files are translated in memory for reads. Reads
do not rewrite them; the next human-authorized context mutation upgrades the
file atomically to the current format.

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

### Fleet fanout

Use `--targets` for governed execution across named contexts:

```bash
srvgov status --targets web-a,web-b,web-c --concurrency 5 -o json
srvgov ports --targets web-a,web-b,web-c -o json
srvgov logs --targets web-a,web-b,web-c --unit nginx --lines 100 -o json
srvgov logs --selector env=prod,role=web --unit nginx --lines 100 -o json
srvgov exec --targets web-a,web-b,web-c "uptime" -o json
srvgov exec --targets web-a,web-b,web-c --dry-run "systemctl restart nginx" -o json
srvgov exec --selector env=prod,role=web --dry-run "systemctl restart nginx" -o json
srvgov svc restart nginx --targets web-a,web-b,web-c --dry-run -o json
srvgov file stat /etc/hosts --targets web-a,web-b,web-c -o json
srvgov docker restart api --targets web-a,web-b,web-c --dry-run -o json
```

`--selector key=value,key2=value2` resolves targets by AND-matching context
labels. `--targets`, `--selector`, and `--context` cannot be combined.
`status`, `ports`, and `logs` have a hard effective-risk ceiling of R0,
including fallback commands. Multi-target `exec`, `svc`, `file`, and `docker`
authorize every target non-interactively before mutation. Human-supplied
reason, ticket, confirmation, and allow flags are reused but validated
independently against every context's effective risk, ticket pattern, and
RBAC. Never synthesize those values. Use each command's `--dry-run` to inspect
the resolved target set, every target's effective risk, and
`maxEffectiveRiskTier`. Dry-run never authorizes or mutates. To prevent
symlink-based risk under-reporting, `file write --dry-run` connects only for
audited R0 metadata probes that bind each canonical parent directory; other
dry-runs do not connect or audit. Results are target-sorted and remote failures
are isolated.

Remote stdout and stderr are bounded. If a mutation completes but captured
output exceeds the bound, the command returns `PARTIAL_FAILURE`; a transport
failure after dispatch is an uncertain result. Verify target state before any
retry rather than assuming the mutation did not happen.

## Service Control

Use the fixed `svc` verbs instead of constructing raw systemctl actions:

```bash
srvgov svc status nginx -o json
srvgov svc restart nginx --reason "apply reviewed configuration" --ticket OPS-123 --yes -o json
srvgov svc restart nginx --targets web-a,web-b --reason "apply reviewed configuration" --ticket OPS-123 --yes -o json
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
srvgov file stat /etc/hosts --targets web-a,web-b -o json
```

These are audited R0 commands. Returned content and structured fields are
redacted. Reads are bounded; do not raise `--max-bytes` without a concrete need.

For a human-authorized write:

```bash
srvgov file write /tmp/app.conf --content "enabled=true" \
  --reason "update reviewed configuration" --ticket OPS-123 --yes -o json
srvgov file write /tmp/app.conf --content "enabled=true" --targets web-a,web-b \
  --reason "update reviewed configuration" --ticket OPS-123 --yes -o json
```

Ordinary writes are R2. Sensitive paths or protected contexts raise them to R3
and require human-supplied `--allow-destructive`. Never synthesize reason,
ticket, confirmation, or allow flags. Without `--content`, stdin is read only
after authorization and explicit `--yes` is mandatory; with `--content`, stdin
is never read. Both forms are bounded by `--max-bytes` (1 MiB by default,
16 MiB hard maximum). The target verifies exact length and SHA-256 before a
same-directory atomic rename; symlinks and non-regular targets are rejected.
Audit stores only a path fingerprint, byte count, and content SHA-256, never
the raw path or content. The command does not use SFTP.

## Docker Governance

Use structured reads before a container lifecycle change:

```bash
srvgov docker list -o json
srvgov docker inspect api -o json
srvgov docker logs api --tail 100 -o json
srvgov docker inspect api --targets web-a,web-b -o json
```

These are audited R0 operations. Inspect returns only the fixed safe field
subset and excludes Env. Logs are bounded to 1-10000 lines and redacted.

Lifecycle operations are fixed to start, stop, restart, and rm:

```bash
srvgov docker restart api \
  --reason "restart after reviewed deployment" --ticket OPS-123 --yes -o json
srvgov docker restart api --targets web-a,web-b \
  --reason "restart after reviewed deployment" --ticket OPS-123 --yes -o json
srvgov docker rm retired-api \
  --reason "remove retired container" --ticket OPS-123 --allow-destructive --yes -o json
```

`start`, `stop`, and `restart` are R2, or R3 in protected contexts. `rm` is
destructive R3 in every context and always requires a human-supplied
`--allow-destructive` in addition to the ticket, reason, and confirmation.
Never synthesize `--ticket`, `--yes`, or `--allow-destructive`. The Docker verb
does not expose run, create, exec, build, copy, compose, or prune. Use
`exec --dry-run` if a human explicitly requests an operation outside the fixed
Docker surface.

## Preview Before Execution

Always preview a command whose impact is not already established:

```bash
srvgov exec --dry-run "systemctl status nginx" -o json
srvgov exec --dry-run "touch /tmp/deploy-ready" -o json
srvgov exec --dry-run "rm -rf /tmp/old-release" -o json
```

The `exec` dry-run classifies only. It does not connect to SSH, execute the
command, or create an execution audit event.

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
srvgov audit prune --keep-last 20 --confirm --ticket OPS-123 --allow-audit-prune --yes -o json
srvgov doctor -o json
srvgov version -o json
```

Audit query output is redacted again before being returned. For encrypted
audit logs, set `SRVGOV_AUDIT_PRIVATE_KEY` before `audit query` or `audit
verify`; the key is read from the environment and never echoed. SSH host keys
are pinned by strict trust on first use. The first pin is reported on stderr
with the address, key type, and fingerprint so JSON stdout remains clean. A
changed key or a new key type for an already known host is rejected and
requires manual pin review.
Confirmed pruning is checkpoint-aware. The full previewed rotation set is
rebound under the audit lock, and the authenticated v2 checkpoint is durably
advanced before selected rotations are deleted. Any candidate drift or
integrity problem fails closed before deletion. Prune intent/outcome evidence
uses the same-directory sibling `.<audit-base>-control`; it never writes into
the prune target or its rotation namespace.

Every mutation records an `intent` after final validation and authorization but
before its first side effect, then an `outcome` with the same `mutationId`.
Fanout records a batch pair plus one pair per target. Raw tickets, reasons,
commands, targets, file paths, output, file content, and backend error text are
not persisted; audit records contain domain-separated fingerprints and lengths.

Audit records use authenticated v2 envelopes and report their durable commit
state. A known-not-committed intent blocks the mutation. A known-not-committed
outcome enters a private durable spool and returns `AUDIT_INCOMPLETE`; a known
committed outcome is never queued again. An indeterminate append is atomically
renamed to `.indeterminate`, blocks subsequent automatic replay, and requires
manual reconciliation. A mutation that already started still queues its own
outcome after that marker without making another audit append. Crash recovery
can still be at-least-once, so audit consumers deduplicate by
`(mutationId, phase)`.
