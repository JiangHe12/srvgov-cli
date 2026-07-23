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
- R1 requires a reason and confirmation, and R2 adds a ticket. R3 additionally
  requires the operation-specific allow flag: `--allow-destructive` for remote
  destructive changes, `--allow-context-change` for context create/replace/
  selection/import/credential migration, `--allow-context-delete` for context
  deletion, `--allow-role-change` for role changes, or
  `--allow-audit-prune` for confirmed audit pruning.
- Protected contexts raise effective risk.
- AI agents must not synthesize tickets, allow flags, or high-risk confirmation.
- Denied and failed operations are audited.

## SSH And TOFU

- SSH runs without a PTY.
- Host keys are pinned by address in `~/.srvgov/known_hosts`.
- A first pin is reported on stderr with its address, key type, and fingerprint;
  JSON stdout remains machine-readable.
- Changed keys and new key types for known addresses are rejected.
- There is no insecure host-key bypass.
- Key rotation requires manual review and pin removal.

## Credentials And Redaction

- Prefer private keys, SSH agent, keychain, or encrypted credential storage.
- Do not place passwords, tokens, private keys, or passphrases in command text.
- Private-key blocks, AWS access key IDs, JWTs, and recognized password/token/
  secret assignments are redacted before caller output and audit persistence.
- Audit query applies redaction again to protect against legacy records.
- Mutation audit stores fingerprints and lengths instead of raw tickets,
  reasons, commands, targets, paths, output, or backend errors. File writes
  record a path fingerprint, byte count, and content SHA-256, never raw content.
- Encrypted `audit query` and `audit verify` read the private key from
  `SRVGOV_AUDIT_PRIVATE_KEY`; the key is never echoed.
- Protect context, known-hosts, and audit files with owner-only access.

## Supply Chain

Release binaries are built and signed by GitHub Actions. Before GitHub Release
and npm publication, the workflow verifies `checksums.txt` and all six binary
signatures against this repository's exact `release.yml` identity, release ref,
and GitHub Actions OIDC issuer. The npm package embeds those six verified
digests in `package.json`, covered by npm provenance. The installer trusts only
that package-bound manifest; mirrors can supply bytes but cannot replace
verification data. There is no verification bypass, and a failed install leaves
the previous binary unchanged.
