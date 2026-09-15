# Configuration

Runtime policy lives in `/etc/op-bridge.json`. It must be a regular root-owned
file, not a symlink, and must not be group/world-writable. Configuration version
3 is required; old Ops configuration is rejected. Unknown and duplicate JSON
keys, trailing data, and files larger than 64 KiB are rejected.

Start with `deploy/desktop.json`, `deploy/owner-only.json`, or `deploy/client.json`.
Examples are templates; review every route and remove any you do not use.

```json
{
  "version": 3,
  "machine": "build-server",
  "default_desktop": "laptop",
  "desktops": {
    "laptop": {
      "transport": "ssh",
      "ssh_host": "laptop",
      "owner": "alice",
      "account": "my.1password.com"
    }
  }
}
```

`machine` is a descriptive identifier for the execution host, not automatic host
detection. Desktop names are local route identifiers selected by `--desktop`.
Names and SSH aliases use ASCII letters, digits, dots, underscores, and hyphens;
the first character must be alphanumeric. Maximum length is 128 characters.

An SSH route specifies an **existing SSH alias**, the destination's desktop owner,
and its expected account sign-in address. The alias selects the SSH login account
and identity using the caller's existing SSH configuration. It must log in as the
destination's permitted caller. Do not put `user@host`, options, shell syntax, or
inline credentials in `ssh_host`. There is no identity substitution or fallback.

The local desktop's optional capability is separate from outgoing routes:

```json
"local_bridge": {
  "owner": "alice",
  "caller": "automation",
  "account": "my.1password.com"
}
```

`owner` is the existing non-root user running 1Password. `caller` is an optional,
distinct non-root user permitted to invoke the bridge through sudo. Omit `caller`
for owner-only local use; no sudo rule is needed. Usernames follow the conservative
form `[a-z_][a-z0-9_-]{0,31}`. This avoids shell and sudoers alias interpretation.
Accounts are sign-in hostnames such as `my.1password.com` or `team.1password.eu`;
do not supply a URL, email address, token, or password.

A local route has `transport: "local"` and an `account` matching `local_bridge`.
It omits `ssh_host` and `owner`. At most one local route is allowed. A desktop may
default to a remote route and still serve its own local bridge. Client-only hosts
omit `local_bridge`. Configure between 1 and 64 destinations.

The local owner connects directly to their private socket. The configured local
caller invokes `/usr/bin/sudo -n -u OWNER` with the fixed `_bridge` command. Remote
requests invoke that same bridge through SSH; they never follow the destination's
outgoing default route again.

## Account enforcement

Each desktop authoritatively pins one account. Clients also record the expected
account per route. A secret request carries that expected account, and the desktop
and terminal worker independently validate it. A mismatch fails rather than using
a different account. An explicit operation-level `--account` is accepted only if
it matches. No caller-controlled environment or global native CLI option can
change the policy.

`session doctor` and running `session status` report the desktop's actual account.
Check those during installation; control requests do not select an account or
request authorization. Configuration changes require stopping the existing local
session before replacement so a worker cannot retain old policy.

## Validate before installation

```sh
./op-bridge config check host.json
./op-bridge config sudoers host.json > op-bridge.sudoers
visudo -cf op-bridge.sudoers
```

These commands inspect the explicit staging file only. They do not install files,
verify file ownership or live prerequisites, start sessions, or override runtime
policy. `config sudoers` reports that no rule is needed for client-only and
owner-only configurations.
