# AGENTS.md

## Purpose

This repository contains `snmp-proxy`, a stateless Go service that exposes an authenticated JSON API for SNMP read operations and can receive/forward traps and informs.

Use `SPEC.md` as the source of truth for intended behavior. Keep `README.md` and `HOWTO.md` aligned when user-facing behavior or examples change.

## Repository Map

- `cmd/snmp-proxy/` - process entry point and startup wiring
- `internal/gateway/` - service implementation, including config, HTTP handlers, SNMP execution, TLS bootstrap, metrics, validation, and trap forwarding
- `README.md` - quickstart and high-level usage
- `HOWTO.md` - request examples by operation type
- `SPEC.md` - full behavioral and configuration contract
- `Dockerfile` - production container build

## Working Principles

- Prefer small, focused changes that fit the existing package layout.
- Preserve the service's contract-first design. If behavior changes, update tests and the relevant documentation in the same change.
- Keep the service stateless. Do not introduce persistence, schedulers, or background coordination without an explicit requirement.
- Treat config, auth, TLS material, SNMP communities, SNMPv3 passphrases, and webhook credentials as sensitive data. Do not log or return secrets.
- Maintain the current failure model: validated requests return structured per-target/per-operation results, and downstream SNMP failures do not become transport-level HTTP failures.
- Keep target execution concurrent but operations for one target ordered.
- Reuse existing helpers and types in `internal/gateway` before adding new abstractions.

## Toolchain

- Go version: `1.22`
- Main dependency: `github.com/gosnmp/gosnmp`

Common commands:

```bash
go test ./...
go test ./internal/gateway -run TestName
go run ./cmd/snmp-proxy
docker build -t snmp-proxy .
```

Local startup requires credentials, for example:

```bash
SNMP_PROXY_BASIC_AUTH_USERNAME=user \
SNMP_PROXY_BASIC_AUTH_PASSWORD=pass \
go run ./cmd/snmp-proxy
```

## Implementation Notes

- Configuration flows through `gateway.LoadConfig`; prefer extending validation there instead of scattering checks through handlers.
- `Server` owns HTTP behavior, auth, request validation, metrics exposure, and response formatting.
- `GoSNMPExecutor` owns device interaction behavior.
- Trap/inform behavior belongs with the trap service implementation, not the HTTP layer.
- Keep request/response schemas strict. The HTTP layer uses `DisallowUnknownFields`; preserve that contract unless the spec changes.
- Preserve default TLS behavior and graceful shutdown behavior unless the change explicitly targets startup lifecycle.
- When changing limits, timeouts, routes, metrics, or logging, inspect `SPEC.md` before editing and update it if the contract changes.

## Testing Expectations

- Run `go test ./...` for normal code changes.
- Add or update focused tests near the affected code:
  - config changes: `config_test.go`
  - request validation/schema changes: `validation_test.go`
  - HTTP behavior: `server_test.go`
  - SNMP execution behavior: `executor_test.go`
  - trap/inform behavior: `traps_test.go`
  - TLS lifecycle: `tls_test.go`
- Use integration coverage when behavior crosses modules or network boundaries; existing examples live in `integration_test.go`.
- Prefer deterministic tests with local simulators/fakes over external dependencies.

## Documentation Rules

- Update `SPEC.md` for contract changes.
- Update `README.md` when quickstart, endpoints, environment variables, or operational defaults change.
- Update `HOWTO.md` when request examples or supported operation semantics change.

## Code Style

- Follow standard Go formatting with `gofmt`.
- Keep comments short and only where they clarify non-obvious behavior.
- Match the existing plain-data style for request/response models and the current `slog` structured logging approach.
- Favor explicit validation and clear error messages over cleverness.

## Review Checklist

Before finishing a change, confirm:

1. The implementation matches `SPEC.md`.
2. Secrets are not exposed in logs, metrics, or responses.
3. Limits, ordering, and partial-failure semantics still hold.
4. Tests cover the new behavior and `go test ./...` passes.
5. User-facing documentation is updated when behavior changed.
