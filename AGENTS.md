# Working on op-bridge

This is a standalone Linux utility. Keep the command usable without an agent or
Codex installation. The skill is optional. Machines are configured individually.

Preserve the native 1Password authorization boundary, pinned account, exact sudo
bridge permission, strict operation allowlist, notification gate, private access
history, terminal lifetime, cancellation, resource bounds, and write uncertainty.
Never retry a submitted write automatically. Never log values or templates.

Use fake CLI processes, temporary sockets, and disposable D-Bus sessions in tests.
Do not call the live desktop, install system files, change authentication, or
change SSH configuration during development. Run `go test ./...`, `go test -race
./...`, `go vet ./...`, and `bin/check-package` before release. Use existing Go
toolchains; do not replace shared toolchains as part of validation.

Keep packaging small: one binary, explicit per-host configuration, optional skill,
and documented manual installation. No fleet manager or compatibility runtime.
