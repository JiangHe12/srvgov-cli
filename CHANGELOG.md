# Changelog

## [Unreleased]

## v0.7.0

### Added

- Added authorize-all `--targets` and bounded `--concurrency` fanout to every
  `svc`, `file`, and `docker` action, including per-target risk/audit handling
  and no-connect multi-target dry-run previews.
- File-write fanout authorizes every target before reading or sending content,
  then uses independent readers and SHA-256 audit trackers per target.

## v0.6.4

### Security

- Upgraded to opskit-core v1.0.5 to consume shared opaque token, URL credential,
  Bearer authorization, and session identifier value redaction.

## v0.6.3

### Changed

- Replaced the local redaction implementation with the byte-equivalent shared
  `github.com/JiangHe12/opskit-core/redact` package from opskit-core v1.0.4.

## v0.6.2

### Fixed

- Expanded structured and command-line redaction with fail-safe `*_key`
  recognition for vendor credentials, explicit preservation of common benign
  database key metadata, and coverage for cookies and session IDs.
- Missing `--reason` denials now write `authorization.denied` audit events
  across regular, stdin, and fanout execution paths while preserving the
  original usage exit code when audit persistence fails.
- Authorization errors for a missing reason now report the complete flag set
  required by the effective R1-R3 tier.
- Server status omits virtual and duplicate Docker filesystems, retaining only
  unique `/dev/*` block devices.
- Docker logs now request timestamps and return the same structured
  line-and-metadata shape as the general logs command, with graceful fallback
  for malformed timestamps.

## v0.6.1

### Fixed

- Audit path resolution and append failures now emit a stderr warning without
  replacing the governed command's original result or exit code, including
  fanout and file-write execution paths.

## v0.6.0

### Added

- Two-phase authorize-all execution for governed `exec --targets` writes.
- Multi-target dry-run reports each target's base/effective risk and the
  aggregate maximum effective risk.

### Security

- Every target is classified and non-interactively authorized in sorted order
  before any SSH execution begins. The first denial rejects the whole batch,
  writes an `authorization.denied` event for that target, and guarantees zero
  partial writes.
- Ticket patterns, RBAC, protected-context escalation, confirmation, and R3
  allow flags are evaluated independently by `safety.Authorize` for every
  target. Execution then re-authorizes each target immediately before SSH.
- Concurrent audit appends are serialized in-process before entering the core
  cross-process file lock, preventing dropped per-target records on Windows.
- `status` and `ports` fanout remain strictly R0-only.

## v0.5.0

### Added

- Bounded, continue-on-error fanout for `status`, `ports`, and `exec` across
  comma-separated context names with deterministic target-sorted results.
- Stable per-target JSON results and aggregate success/failure summaries.

### Security

- Fanout is limited to commands whose effective risk is R0 for every target.
  The entire operation is rejected before SSH if any target exceeds R0.
- Every target reuses the existing classify, authorize, SSH, redaction, and
  audit path; no multi-target authorization or write fanout exists in v1.
- Target names are normalized, deduplicated, sorted, and resolved before work
  starts. `--targets` and `--context` are mutually exclusive.

## v0.4.0

### Added

- Governed Docker container list, inspect, and bounded logs with stable,
  redacted structured output.
- Fixed-whitelist Docker start, stop, restart, and remove lifecycle actions.

### Security

- Docker risk comes only from cmdclass: reads are R0, lifecycle changes are
  R2, and run/create/exec/build/copy/import/export/prune-class operations are
  R3, including grouped forms such as `docker system prune`.
- Docker identifiers are shell-quoted and never considered when classifying
  the action, so a container named `run` or `prune` remains a lifecycle R2.
- Inspect uses a remote fixed-field projection and never requests container
  environment variables or returns the full inspect document.
- Leading Docker global options fail closed as R3. The governed Docker verb
  exposes no run, create, exec, build, copy, or prune operation.

## v0.3.0

### Added

- Governed `svc status` with machine-readable systemd service state.
- Fixed-whitelist `svc start`, `stop`, `restart`, `reload`, `enable`, and
  `disable` actions with structured output.
- Governed `file read`, `file stat`, and `file list` R0 operations with
  structured, redacted output and bounded reads.
- Governed `file write` through SSH stdin with R2 authorization and R3
  escalation for sensitive paths or protected contexts.

### Security

- Every service and file operation uses the shared command classifier,
  effective-risk, authorization, SSH, redaction, and audit path; cmdclass is the
  sole risk source (no SFTP or alternate write path).
- Service unit names and file paths are shell-quoted; unit names are never
  interpreted as systemctl subcommands.
- Destructive systemctl power, sleep, run-level, root-switch, and mask
  subcommands are classified R3; parser-uncertain leading options fail closed.
- File content from stdin requires explicit `--yes`; `--content` takes
  deterministic precedence and never reads stdin.
- Write audit records contain only redacted path, bytes written, and SHA-256;
  tee output is discarded and content is never returned or persisted.

### Notes

- File writes use direct `tee` replacement and are not atomic. Temporary-file
  plus rename semantics are reserved for a future release.

## v0.2.0

### Added

- Governed `status` observations with structured hostname, uptime, load, CPU,
  memory, disk, and kernel fields.
- Governed `ports` observations with `ss` to `netstat` fallback and structured
  listening socket fields.
- Governed `logs` observations for systemd journal or file tails with native
  filtering, structured metadata, and field-level redaction.

### Security

- Every observation command uses the same cmdclass, effective-risk,
  authorization, SSH, redaction, and audit flow as `exec`.
- Free-text observation arguments are shell-quoted; probes are never joined
  with shell pipelines or command chaining.
- `ss -K` and `ss --kill` remain destructive R3 operations.

## v0.1.1

### Fixed

- Force LF line endings for Go and release text files so Windows lint checkout
  does not turn gofmt-clean files into CRLF-formatted files.

## v0.1.0

_First public release._

### Added

- Server context management for SSH host, port, username, authentication
  preference, protected environment metadata, and credential-store references.
- Strict TOFU SSH transport with non-PTY execution, host-key pinning, key-change
  rejection, private-key/agent/password authentication, and structured output.
- Fail-closed command classification using the opskit R0-R3 risk model.
- Governed `exec` flow through effective risk, reason enforcement,
  `safety.Authorize`, redaction, and append-only audit.
- `audit`, `doctor`, `version`, and embedded AI Skill installation commands.
- Static `capabilities` command for AI self-description.
- Audit maintenance commands: `audit query`, `audit verify`, and `audit prune`.
- Context RBAC role management via `ctx role set/list/unset`.
- Portable context `ctx export/import` with password and identity-passphrase redaction.
- Credential migration for SSH password and identity passphrase into secure backends.
- Multi-platform GitHub release, cosign signatures, checksums, and npm package.

### Security

- Dangerous, dynamic, privileged, and parser-uncertain commands fail closed.
- Host-key changes and untrusted key-type changes are hard failures.
- Commands and SSH output are redacted before caller output and audit storage.
- AI callers cannot self-authorize tickets or destructive allow flags.
