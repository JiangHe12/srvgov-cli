# Security Policy

## Supported Versions

Security fixes target the latest release. Upgrade to the newest version when a
security update is published.

## Reporting A Vulnerability

Report vulnerabilities privately through GitHub Security Advisories:

<https://github.com/JiangHe12/srvgov-cli/security/advisories/new>

Do not publish exploit details before a coordinated fix is available. Include
the affected version, platform, impact, reproduction steps, and suggested
mitigation when possible.

## Trust Boundary

`srvgov-cli` trusts the current OS user, owner-controlled files under
`~/.srvgov`, explicitly configured credential backends, and release artifacts
from the canonical GitHub repository. It does not trust remote SSH servers,
remote command output, changed host keys, npm mirrors, or model-generated
authorization values.

## Governance

- Command classification is fail-closed and structure-aware.
- Unknown commands have an R2 floor; parse uncertainty is R3.
- R1 requires a reason and confirmation, R2 adds a ticket, and R3 adds
  `--allow-destructive`.
- Protected contexts raise effective risk.
- AI agents must not synthesize tickets, allow flags, or high-risk confirmation.
- Denied and failed operations are audited.

## SSH And TOFU

- SSH runs without a PTY.
- Host keys are pinned by address in `~/.srvgov/known_hosts`.
- Changed keys and new key types for known addresses are rejected.
- There is no insecure host-key bypass.
- Key rotation requires manual review and pin removal.

## Credentials And Redaction

- Prefer private keys, SSH agent, keychain, or encrypted credential storage.
- Do not place passwords, tokens, private keys, or passphrases in command text.
- Private-key blocks, AWS access key IDs, JWTs, and recognized password/token/
  secret assignments are redacted before caller output and audit persistence.
- Audit query applies redaction again to protect against legacy records.
- Protect context, known-hosts, and audit files with owner-only access.

## Supply Chain

Release binaries are built by GitHub Actions, signed with cosign, and published
with SHA-256 checksums. npm installation verifies the canonical checksums unless
the operator explicitly sets `SRVGOV_CLI_SKIP_VERIFY=1`. Avoid untrusted mirrors
and never disable verification in production automation.
