# Changelog

## [Unreleased]

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
