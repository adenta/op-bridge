# One-time extraction from Codex Ops

This procedure is for existing users of the former `codex-secrets` helper. New
installations should use [the installation guide](install.md). Nothing in a build,
test, or normal op-bridge invocation performs this migration automatically.

## Remove old ownership before cutover

Prepare the corresponding secrets-only changes in the source Ops repository:

- Remove `codex-secrets` from the Linux build and package binary lists.
- Remove installation of its binary/link, generated configuration, sudo rule,
  skill, and user skill links from `cmd/codex-ops-package`.
- Remove secrets requirements from `internal/localinstall/bootstrap_linux.go`.
- Remove secrets configuration generation, host fields, and session service
  mapping from `internal/layout` once their direct consumers are removed.
- Update secrets-specific generated instructions, skill requirements, and package
  tests. Ops must not install or require the optional op-bridge skill.
- Retire the old secrets implementation/assets and link users to this utility.

Do not alter other component behavior. Review how older Ops packages and rollback
archives could reinstall the retired helper. After cutover, use only Ops versions
that have relinquished these secrets paths; any deliberate rollback to an older
Ops release needs separate coordination to avoid resurrecting the old helper.

## Prepare each machine

Translate its old version-2 policy to version 3. Separate local bridge capability
from outgoing destination entries. Carry forward the same desktop owner, caller,
SSH aliases, default desktop, and approved account. Existing personal-account
installations retain `my.1password.com`; generalization does not change the account.
Do not fetch credentials, rotate keys, modify SSH identities, or copy native
1Password data. Prepare and validate all files before pausing callers.

## Cut over with requests paused

1. Pause all callers. Let active operations finish. Resolve any uncertain writes.
2. Stop the old session on each approval desktop, selecting the local desktop
   explicitly. Confirm the old transient service is stopped before proceeding.
3. On that desktop, as its owner, move only
   `~/.local/state/codex-ops/secrets/history/` to
   `~/.local/state/op-bridge/history/`. Require an absent destination; if either
   location already contains records, stop and reconcile deliberately rather than
   overwrite. Verify regular files, owner, 0700 directories, and 0600 files.
   Compare file names and content hashes before/after the move. A cross-filesystem
   transfer requires copy, verification, then removal of the source. Keep the
   history schema, timestamps, request IDs, and existing incomplete records intact.
4. Install the standalone executable, policy, and narrow sudo rule as a matched
   set. Keep one scoped recovery copy of only the retired helper files until
   verification completes. Do not copy sockets or active sessions.
5. Switch calling instructions/scripts and optional skill links. Verify local and
   remote routes using metadata-only requests. The new helper continues the same
   90-day history retention policy; expired files may be cleaned at startup.
6. Remove the retired command `/usr/local/bin/codex-secrets`, executable
   `/usr/local/libexec/codex-ops/codex-secrets`, configuration
   `/etc/codex-secrets.json`, sudo rule `/etc/sudoers.d/codex-secrets`, and installed
   `codex-secrets` skill copies/links. Remove only verified component files.
7. Resume callers and remove temporary recovery/staging files after verification.

Do not leave a command alias, duplicate session, or automatic legacy fallback.
Install desktops before their clients and validate every intended route. Machines
may be maintained separately, but requests must stay paused for routes whose
callers and destinations have not both completed the switch.

## Failed cutover

Keep affected callers paused. Stop the new local sessions, restore the saved old
helper files/rules as a matched set, and switch callers back explicitly. If the new
history directory has received records, preserve them: move the complete directory
back only when the old history destination is absent. Never overwrite or discard
records created during the attempted cutover. Inspect/reconcile any conflicting
history directories before resuming. Do not restore native account state or replay
writes. Record any retained recovery files and remove them when recovery finishes.
