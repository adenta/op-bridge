# Install on one machine

Install each machine individually. Commands below are a manual administrator
procedure, not a fleet rollout. They do not create users, install 1Password,
change SSH identities, or enable services at boot.

## Prerequisites

- Linux, with `/usr/bin/ssh` on remote callers.
- On approval desktops: an existing non-root desktop user, a working systemd
  user manager and `/run/user/UID/bus`, a notification service, the 1Password
  desktop app with CLI integration, and `/usr/bin/op`.
- `/usr/bin/sudo` and `visudo` if a separate caller will use a desktop bridge.
- Existing SSH aliases and keys for remote routes. The remote login is the
  configured caller account; the desktop owner remains the native CLI user.

The owner can use the local command directly with `deploy/owner-only.json`.
No second account or sudo rule is needed for that case.

## Build or unpack

From source, using the existing Go toolchain:

```sh
go test ./...
go vet ./...
bin/build-release dev
```

The archive and its SHA-256 file appear in `dist/`. The build supports Linux amd64
and arm64 (`GOARCH=arm64 bin/build-release VERSION`). Cross-compilation does not
prove native desktop behavior on that architecture. Checksums detect damage; use
a trusted source for the executable and checksum.

Unpack the archive and work inside its `op-bridge-VERSION-linux-ARCH` directory.
The executable is `./op-bridge`. Check `./op-bridge --version`.

## Prepare policy

Copy an example to `host.json`. Set existing users, the account sign-in address,
default desktop, and only the routes this machine should use. Do not copy example
users or routes blindly. See [configuration](configuration.md).

```sh
./op-bridge config check host.json
# Only for a local bridge with a separate caller:
./op-bridge config sudoers host.json > op-bridge.sudoers
visudo -cf op-bridge.sudoers
```

Validate SSH connections separately without retrieving credentials. An unavailable
desktop route should fail; do not substitute identities or disable host-key checks.

## First installation

Confirm these target paths are absent and their parents are trusted root-owned
directories. If an installation already exists, follow the update section instead.
Run from the unpacked archive after reviewing `host.json` and the sudo rule:

```sh
sudo install -d -o root -g root -m 0755 /usr/local/libexec/op-bridge
sudo install -o root -g root -m 0755 ./op-bridge /usr/local/libexec/op-bridge/op-bridge
sudo install -o root -g root -m 0644 host.json /etc/op-bridge.json
sudo ln -s /usr/local/libexec/op-bridge/op-bridge /usr/local/bin/op-bridge
```

For a desktop bridge with a separate caller, install its validated rule last:

```sh
sudo install -o root -g root -m 0440 op-bridge.sudoers /etc/sudoers.d/op-bridge
sudo visudo -c
```

Client-only and owner-only installations need no sudo rule. Do not grant general
sudo access as part of installing this utility. The installed executable and
configuration must not be writable by the caller or desktop owner.

No session is started by installation. There is no service unit to enable.
History directories are created privately by the desktop owner on first use.

## Verify

```sh
op-bridge --version
op-bridge route show --format=json
op-bridge session doctor
op-bridge session status
```

Check the actual account reported by doctor. Test every configured destination
with the corresponding `--desktop NAME` override. Doctor does not prove native
authorization or visible notification delivery.

When desktop access testing is authorized, run a metadata request with stdout
discarded and approve on the selected desktop:

```sh
op-bridge vault list --format=json > /dev/null
```

Observe a separate banner for each request. Repeat within two minutes, then after
two idle minutes. For the lifetime check, make metadata requests every minute for
more than ten minutes, inspect worker age with status, and observe native approval
behavior when the worker rotates. Do not use a separate native `op whoami` as a
session test. Never verify installation by writing a real secret.

## Update and recovery

Prepare and validate the new archive and any deliberately changed policy before
pausing requests. Routine updates retain `/etc/op-bridge.json`, the sudo rule, and
all history. If changing policy, validate the whole replacement and its generated
sudo rule first. Do not run two versions of the helper concurrently.

When changing the permitted caller, replace the sudo rule in the same paused
window. When switching to owner-only or client-only use, remove the old
`/etc/sudoers.d/op-bridge` rule. Editing configuration alone does not revoke an
existing sudo grant to run the bridge as the desktop owner.

1. Pause callers. Let active requests finish and resolve uncertain writes.
2. On each approval desktop being updated, stop its **local** session with the
   appropriate `--desktop NAME session stop`. Its outgoing default may be remote.
3. Keep one private recovery directory containing only this installation's old
   executable, configuration, sudo rule (if present), and command link target.
   This is for restoring this update, not a whole-machine backup. Never copy
   1Password account data, sockets, or authorization state.
4. Stage each replacement beside its final path, set root ownership and the same
   modes as first installation, then rename it into place. Replace the executable,
   and only deliberately changed config/rule files, while callers remain paused.
   Validate sudoers again before resuming. A changed executable needs a fresh
   session; do not restart an old worker with new files.
5. Run the verification checks. Resume callers only after they pass. Remove the
   recovery directory and staging files after successful verification.

If replacement or verification fails, keep callers paused, stop any new local
session, and restore the saved executable/configuration/rule/link as a matched
set. Revalidate and verify before resuming. Keep recovery files only while that
recovery is unfinished, and record their location. Preserve all access history,
including events written by the failed update. Never retry a submitted write as
part of recovery. An account change is a deliberate policy change, not an update
prerequisite.

For a partially completed first installation, remove only the files created by
that attempt after stopping its local session; do not remove history or native
account data. These procedures are manual; there is no hidden rollback controller.

## Optional agent skill

Install the skill only if desired. One option is to keep its reviewed source in
`/usr/local/share/op-bridge/skills/op-bridge/` and link that directory into the
chosen agent's user-owned skill directory. For Codex, that is normally
`~/.codex/skills/op-bridge`. Other agents can consume the plain `SKILL.md` directly;
`agents/openai.yaml` is optional UI metadata. Do not overwrite an existing skill
or change other agent settings incidentally. Skill updates should match the CLI.

## Uninstall

Pause callers and stop the local session on approval desktops. Explicitly remove
only the command link, executable directory, configuration, scoped sudo rule,
and optional skill copies/links installed above. Preserve
`~/.local/state/op-bridge/history/` unless separately choosing to delete history.
Keep native 1Password data and unrelated credential stores. Do not restore retired
helpers or tokens as a side effect of uninstalling.
