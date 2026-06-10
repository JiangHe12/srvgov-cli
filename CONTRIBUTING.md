# Contributing

Thank you for contributing. This is a security-sensitive CLI, so changes should
be small, tested, and straightforward to review.

## Development

Run all gates before submitting changes:

```bash
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal   # must print nothing
golangci-lint run --timeout=5m
go vet -tags=integration ./...
npm pack --dry-run
```

Do not commit credentials, context files, SSH private keys, host-key pins,
audit logs, or downloaded release binaries.

## Pull Requests

- Keep one behavioral topic per PR.
- Add adversarial tests for classifiers, redaction, SSH trust, or authorization.
- Update both READMEs and the changelog for user-facing changes.
- Never weaken governance, host-key verification, redaction, or authorization
  to make a test pass.

## Releases

Maintainers release from `main` with `v*` tags. Do not create tags or publish
packages unless explicitly authorized.
