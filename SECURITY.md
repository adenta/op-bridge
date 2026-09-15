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
The native executable is fixed at `/usr/bin/op`; no PATH search or CLI override
is accepted. The child environment is rebuilt, with caching disabled and no
inherited service-account tokens.

SSH uses existing identities, `BatchMode=yes`, strict host-key checking, and a
fixed remote bridge command. Only strictly validated configuration values enter
that command; request data uses stdin. The local socket is private to the desktop
owner. The narrowly scoped sudo rule grants only the installed `_bridge` command
as that owner. Keep the binary, configuration, their parent directories, and the
sudo rule administrator-owned. Do not use a user-writable executable in sudoers.

The desktop owner can already operate their own 1Password CLI. A caller with
unrestricted sudo/root access is an administrator; the narrow bridge does not
constrain that independent privilege. Notification gating is a property of the
supported bridge workflow, not a boundary against a compromised desktop owner.

No helper value cache, token file, terminal transcript, or secret log is written.
Secret data remains in process memory and, remotely, the SSH transport. Native
1Password maintains its own account data. Native stdout/stderr and temporary
files created by callers are outside the helper's metadata-only logging guarantee.

Report vulnerabilities privately through the repository's private vulnerability
reporting facility when available. Do not post credentials, item contents, or
private access-history identifiers in public issues.
