# Origin

The initial secrets implementation and regression tests were extracted from
`github.com/adenta/codex-ops`, commit
`ef47c97e74086501019f76671e140c9a5abaf3fa` (2026-09-15 source snapshot).

Source paths: `cmd/codex-secrets`, `internal/secrets`, `docs/secrets.md`,
`deploy/secrets`, and `skills/codex-secrets`. No other Ops runtime is included.

op-bridge replaces the original machine-specific layout and packaging with its
own administrator-owned configuration and installation paths.
