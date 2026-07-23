# srvgov-cli Agent Guide

This file is the contributor and AI-agent guide for this repository.
`CLAUDE.md` and `AGENTS.md` are kept identical; edit both together.

## Project Summary

srvgov is a governed remote server command execution CLI for AI agents. It
provides SSH contexts, fail-closed command classification, R0-R3 authorization,
strict TOFU host-key pinning, non-PTY execution, redaction, and audit. It is
built on the shared `opskit-core` governance engine.

## Working Discipline

- Make the smallest change that solves the task and match surrounding style.
- Do not weaken governance, redaction, SSH trust, or authorization.
- Do not modify `opskit-core`; consume its published APIs.
- A change is complete only after all Build & Verify gates pass.

## Build & Verify

```bash
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal   # must print nothing
golangci-lint run --timeout=5m
go vet -tags=integration ./...
npm pack --dry-run
```

A real-backend integration suite (`//go:build integration`, env-gated on
`SRVGOV_IT_SSH_*`, skipped by default) exercises `internal/sshexec` plus the
core file read/stat/list/atomic-write paths under the race detector against a
digest-pinned ephemeral OpenSSH container. `integration.yml` runs nightly, on
manual dispatch, and as a release gate, but not on push/PR. The workflow sets
`SRVGOV_IT_REQUIRED=1`, so missing fixture variables fail instead of silently
skipping; local runs without that flag still skip. Real systemd and external
multi-OS VM checks remain manual and must never target production. Cancellation
sends SSH `SIGTERM` before closing the transport; standard OpenSSH applies it to
the session process group. Commands that detach into another session/process
group or ignore `SIGTERM`, forced commands that reject signal requests, and
servers without compatible signaling remain explicit boundaries.

## Governance Rules

- R0 is free but audited. R1 needs `--reason` and `--yes`. R2 also needs a
  non-empty `--ticket`. R3 also needs `--allow-destructive`.
- Governed R0 reads persist an intent before backend access and an outcome
  before result release. A required audit failure returns `LOCAL_IO_ERROR` and
  withholds backend output.
- Context create/replace/selection/import/credential migration, context
  deletion, and role changes are always R3 and require their precise
  `--allow-context-change`, `--allow-context-delete`, or
  `--allow-role-change` flag.
- Confirmed audit pruning is fixed R3 and requires the persisted
  current-context policy, a ticket, confirmation, and exact
  `--allow-audit-prune`. Preview precedes authorization and never deletes.
  The full previewed rotation set is rebound under the audit lock; v2
  checkpoint advancement must commit before authenticated rotations are
  deleted. Intent/outcome evidence uses sibling `.<audit-base>-control`, never
  the prune target or its rotation namespace.
- Authorization and audit identity come from the local OS account plus
  hostname; `--operator` and `SRVGOV_OPERATOR` are ignored.
- Every mutation must persist an `intent` after final validation and
  authorization but before its first side effect, then an `outcome` with the
  same `mutationId`. Fanout also records a batch pair and a pair per target.
- Append handling must consume opskit-core/v2 commit state. Known-not-committed
  intent appends block the mutation; only known-not-committed outcomes enter
  the durable replay spool. Known-committed records are never queued again.
  Indeterminate spool replays are atomically renamed to `.indeterminate` and
  block automatic replay pending manual reconciliation. Already-started
  mutations still queue their outcome after the marker without another append.
  Crash recovery remains at-least-once, so consumers deduplicate by
  `(mutationId, phase)`.
- Mutation audit stores fingerprints and lengths, never raw ticket, reason,
  command, target, file path, output, file content, or backend error text.
- Protected contexts raise R1 to R2 and R2 to R3.
- `cmdclass` is the only command-risk source and must remain fail-closed.
- Authorization must go through `opskit-core/safety`.
- AI agents never auto-fill tickets, allow flags, or high-risk confirmation.
- Impact comes from `exec --dry-run`, never model guesses.
- Fanout may select contexts by explicit names or labels, but read-only R0 caps
  and authorize-all write governance must not be bypassed.
- Redaction applies before caller output and before audit persistence.
- SSH host-key mismatches are hard failures; never add an insecure bypass.

## Code Conventions

- `cmd/` uses `apperrors.New`; bare `fmt.Errorf` and `errors.New` are forbidden.
- Reuse opskit-core for context, credential, safety, audit, printing, telemetry,
  errors, and lock behavior.
- Add focused table-driven and adversarial tests for security-sensitive changes.
- Do not weaken production behavior for tests.

## Repository Layout

- `cmd/` - Cobra commands and output contracts
- `internal/` - command classification, redaction, contexts, SSH, and audit
- `skills/srvgov-cli/` - embedded AI Skill
- `.github/workflows/` - CI, release, and scheduled security scanning
- `bin/` and `scripts/` - npm shim and release-binary installer

## Release & Versioning

Release only when explicitly authorized. To cut version `X.Y.Z`:

1. Set `package.json` version to `X.Y.Z`.
2. Add an exact `## vX.Y.Z` heading to `CHANGELOG.md`.
3. Run Build & Verify. `npm pack --dry-run` must list exactly `LICENSE`,
   `README.md`, `package.json`, `bin/srvgov-cli.js`, and `scripts/install.js`.
4. Create a signed annotated tag `vX.Y.Z` that GitHub reports as verified, then
   push it. The tag must match `package.json` and an exact `## vX.Y.Z`
   changelog heading. The workflow verifies this metadata, runs unit and live
   OpenSSH integration gates, builds six platform artifacts, injects
   `main.version/commit/built`, signs with cosign, publishes checksums and a
   GitHub Release, then publishes npm through OIDC.
5. Never publish or edit release artifacts manually.
