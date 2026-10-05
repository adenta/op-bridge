# Security boundaries

op-bridge uses the native 1Password desktop authorization flow. It is intended
for trusted callers and offers broad read/create/edit access within one configured
account. It does not isolate tasks or provide per-vault permissions. Approval may
be reused inside the shared terminal session. The ten-minute worker lifetime is
a helper limit, not a promise about how often 1Password will prompt.

Administrator-owned configuration selects the desktop owner, caller, account,
and permitted routes. Runtime requests cannot supply executables, environments,
configuration paths, shell commands, or arbitrary native CLI flags. The bridge
and worker reconstruct argv and independently enforce account and command policy.
The native executable is fixed at `/usr/bin/op` on Linux and
`/opt/homebrew/bin/op` on macOS arm64; no PATH search or CLI override is accepted.
The child environment is rebuilt, with caching disabled and no inherited
service-account tokens.

Bulk `inject` is a read operation using stdin templates and stdout only. Native
file flags are rejected. The existing encoded request and output bounds apply;
failed operations release no rendered stdout. Templates are not parsed for access
history, and neither templates nor resolved values are logged or persisted by
the helper. Native stderr may contain secrets, as with other commands. The bridge
does not escape output for destination formats or execute rendered text.

Phone inject uses an explicitly supported template subset and manually selected
values, not verified native CLI lookups. The phone cannot replace the template,
change the pinned account, or add/remove requested references. A complete batch
must contain every request-local field ID exactly once before any rendering.
Repeated references share a selection; selected values are never reinterpreted
as templates. Malformed or incomplete releases retain no values. Limits, expiry,
cancellation, and concurrent release/deny decisions are enforced by the backend,
independently of Android. Well-formed incorrectly selected values cannot be
detected; the user must match the requested account/item/field.

The phone transport retains authenticated WSS, protected windows, transient
secret fields, no saved secret state, and no automatic mutation replay. Refresh
only checks status. Caller acknowledgment confirms complete-response receipt,
not downstream consumption; interrupted transmission can be uncertain. Templates,
references, selected values, and output are excluded from inject history and
operational logs. The same-UID/host-administrator trust boundary still applies.

SSH uses existing identities, `BatchMode=yes`, strict host-key checking, and a
fixed remote bridge command. Only strictly validated configuration values enter
that command; request data uses stdin. The local socket is private to the desktop
owner. The narrowly scoped sudo rule grants only the installed `_bridge` command
as that owner. Keep the binary, configuration, their parent directories, and the
sudo rule administrator-owned. Do not use a user-writable executable in sudoers.

On macOS the fixed, root-owned `Launch.command` and its parent directories must
also be protected from non-root writes. The Aqua LaunchAgent opens it in Terminal
with `open -g -j`; the script executes only the installed `_serve` entrypoint and
accepts no arguments. Requests still use the private socket, never shell text or
Terminal input. Launch failure does not fall back to background hosting. Terminal
preferences and macOS privacy permissions are not modified. Hidden hosting does
not suppress native 1Password approval or guarantee macOS will never prompt.

The desktop owner can already operate their own 1Password CLI. A caller with
unrestricted sudo/root access is an administrator; the narrow bridge does not
constrain that independent privilege.

No helper value cache, token file, terminal transcript, or secret log is written.
Secret data remains in process memory and, remotely, the SSH transport. Native
1Password maintains its own account data. Native stdout/stderr and temporary
files created by callers are outside the helper's metadata-only logging guarantee.

Report vulnerabilities privately through the repository's private vulnerability
reporting facility when available. Do not post credentials, item contents, or
private access-history identifiers in public issues.
