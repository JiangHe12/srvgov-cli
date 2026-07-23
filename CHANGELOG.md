# Changelog

## [Unreleased]

## v0.10.4

### Fixed

- Updated `opskit-core/v2` to v2.0.3. A strict-TOFU first-use pin that committed
  before a later durability error is now reported exactly once even when the
  governed read outcome cannot be persisted. Remote command or file output
  remains withheld on audit failure.
- Restored Node.js 14 compatibility in the npm installer without changing its
  provenance or atomic-install checks.

## v0.10.3

### Security

- Hardened `curl` and `wget` command classification around request methods,
  output targets, protocol selection, and explicit or implicit configuration.
  `curl` must begin with `-q` or `--disable` to prove that startup config is
  disabled; unknown or ambiguous forms fail closed at the highest applicable
  risk tier.
- Made governed R0 reads audit fail-closed: intent is durable before backend
  access and the correlated outcome is durable before output is released.
  Context export now enforces target RBAC and protected-context policy, and
  denied or incomplete reads release no result.
- Updated `opskit-core/v2` to v2.0.2, inheriting owner-only, no-follow atomic
  handling for context, credential, and TOFU trust stores plus fail-closed
  multi-document and conflicting trust-record validation.
- Deferred bounded, redacted TOFU notifications until the required read-audit
  outcome is durable. Log parsing now uses an explicit 16 MiB line bound,
  propagates scanner failures, and rejects unsupported output formats before
  command execution or output.
- Bound npm installs to the six platform digests embedded in the
  provenance-covered package manifest. Release and npm publication now verify
  the exact signed bundle against the GitHub Actions OIDC identity, with Cosign
  upgraded to v2.6.4.

## v0.10.2

### Security

- Upgraded `golang.org/x/text` to `v0.39.0`, removing the dependency version affected by `GO-2026-5970`; no reachable vulnerable symbol was found in srvgov-cli.

### Fixed

- Release checksum aggregation now merges matrix artifacts without Unix binary/directory name collisions, verifies all six per-platform checksum files, and fails unless the global manifest contains exactly six binaries. The v0.10.1 per-platform checksums and Cosign signatures remain valid, but its global manifest omitted the four Unix binaries.

## v0.10.1

### Changed

- Release builds now require a GitHub-verified signed annotated tag whose version matches `package.json`, an exact literal `CHANGELOG.md` heading, and freshly fetched `origin/main`; the complete CI/vulnerability gate and race-enabled integration tests rerun on that tag commit against a digest-pinned live OpenSSH container. Required fixtures fail closed instead of skipping. The real-backend suite covers SSH cancellation/deadlines and the core remote file read/stat/list/atomic-write paths, including size and digest rejection.

### Fixed

- Sent SSH `SIGTERM` before closing a canceled command session so standard OpenSSH terminates the session process group instead of leaving its ordinary shell and children running. Explicitly detached or signal-ignoring commands, forced-command configurations, and servers without compatible signaling remain documented boundaries.
- Prevented concurrent SSH calls from racing while normalizing a shared authentication-method slice.
- Sent literal tab delimiters to remote GNU `stat`, allowing real file metadata output to be parsed correctly.

## v0.10.0

### Added

- Added two-phase mutation auditing for local and remote changes, including per-target fanout records, correlated outcomes, and commit-aware durable replay for definitely uncommitted outcomes.

### Changed

- **BREAKING**: Context and role changes plus confirmed audit pruning are fixed R3 governance operations requiring their precise `--allow-*` flags.
- Updated to `opskit-core/v2` v2.0.0. Audit verification now authenticates v2 envelopes, while confirmed pruning binds the exact rotation set and advances its checkpoint before deletion.

### Fixed

- Hardened command classification around shell expansion, redirection, ambiguous syntax, and mutating command options so uncertain input escalates instead of being treated as read-only.
- Applied bounded timeouts to SSH dialing, handshake, session setup, and agent operations.
- Remote file writes are now size- and digest-bound, reject symlink and non-regular targets, detect target replacement, and commit through a private same-directory temporary file and atomic rename.

### Security

- Strict TOFU now reports first host-key pins on stderr while continuing to reject changed keys. Output and audit persistence redact commands, targets, paths, tickets, reasons, content, and backend error text in favor of fingerprints and bounded metadata.

## v0.9.2

### Changed

- Updated opskit-core to v1.1.4.

## v0.9.1

### Changed

- Internal: release version injection now uses `main.version`, `main.commit`, and `main.built` for family workflow consistency.

## v0.9.0

### Changed

- **BREAKING**: `apiVersion` changed from `srvgov.io/v1` to `srvgov-cli.io/v1` for family namespace alignment. Context and audit namespaces now use `srvgov-cli.io/*`; legacy context config and ctx export documents using `srvgov.io/*` remain readable and are migrated on use.

## v0.8.8

### Changed

- Installer environment variables now prefer the family-standard `SRVGOV_DOWNLOAD_MIRROR` and `SRVGOV_SKIP_VERIFY` names; deprecated `SRVGOV_CLI_DOWNLOAD_MIRROR` and `SRVGOV_CLI_SKIP_VERIFY` remain supported.

## v0.8.7

### Changed

- `capabilities -o json` now reports `contextApiVersions` and `auditApiVersions` arrays for family schema alignment.

## v0.8.6

### Added

- Global flags: `--debug`, `--trace`, `--no-color`.

## v0.8.5

### Fixed

- Error output now respects `-o json` and emits the standard JSON envelope.

## v0.8.4

### Changed

- Aligned root `--version` output with the family format by using the full CLI
  name.

## v0.8.3

### Changed

- Aligned `version` output with the family format: table output is a single
  line and JSON exposes `built` with `unknown` build metadata defaults.

## v0.8.2

### Changed

- Wrapped all `-o json` command output in the family-standard
  `{apiVersion, kind, success, data}` envelope.

## v0.8.1

### Changed

- Migrated SSH host-key trust-on-first-use pinning to the shared
  `opskit-core/trust` package (opskit-core v1.1.0). Host-key pinning behavior,
  the on-disk `known_hosts` format, error messages, and exit codes are
  unchanged; this replaces the duplicated local trust store with the shared
  engine implementation.

## v0.8.0

### Added

- Added context labels with `ctx set --label key=value`, portable
  export/import round-trip, and `ctx list/current` display.
- Added fanout `--selector key=value,key2=value2` target selection across
  read-only and governed fanout commands.
- Added R0-capped multi-target `logs` fanout with per-target audit and
  continue-on-error aggregation.

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
