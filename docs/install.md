# Install on one machine

Install each machine individually. Commands below are a manual administrator
procedure, not a fleet rollout. They do not create users, install 1Password,
change SSH identities, or enable services at boot.

## Prerequisites

- Linux amd64/arm64 or macOS arm64, with `/usr/bin/ssh` on remote callers.
- On Linux approval desktops: an existing non-root desktop user, a working
  systemd user manager and `/run/user/UID/bus`, the 1Password desktop app with
  CLI integration, and `/usr/bin/op`.
- On a macOS approval desktop: an existing logged-in Aqua user, the 1Password
  desktop app with CLI integration, `/opt/homebrew/bin/op`, and permission to
  bootstrap a LaunchAgent into that user's `gui/UID` domain, plus the built-in
  `/System/Applications/Utilities/Terminal.app`.
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

The archive and its SHA-256 file appear in `dist/`. The build supports Linux
amd64/arm64 and Darwin arm64:

```sh
GOOS=linux GOARCH=amd64 bin/build-release VERSION
GOOS=linux GOARCH=arm64 bin/build-release VERSION
GOOS=darwin GOARCH=arm64 bin/build-release VERSION
```

Cross-compilation does not prove native desktop behavior on that platform.
Checksums detect damage; use a trusted source for the executable and checksum.

Unpack the archive and work inside its `op-bridge-VERSION-OS-ARCH` directory. The
executable is `./op-bridge`. Check `./op-bridge --version`.

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
op_bridge_root_group=$(id -gn root) # root on Linux, wheel on macOS
sudo install -d -o root -g "$op_bridge_root_group" -m 0755 /usr/local/libexec/op-bridge
sudo install -o root -g "$op_bridge_root_group" -m 0755 ./op-bridge /usr/local/libexec/op-bridge/op-bridge
sudo install -o root -g "$op_bridge_root_group" -m 0644 host.json /etc/op-bridge.json
sudo ln -s /usr/local/libexec/op-bridge/op-bridge /usr/local/bin/op-bridge
```

For a desktop bridge with a separate caller, install its validated rule last:

```sh
sudo install -o root -g "$op_bridge_root_group" -m 0440 op-bridge.sudoers /etc/sudoers.d/op-bridge
sudo visudo -c
```

Client-only and owner-only installations need no sudo rule. Do not grant general
sudo access as part of installing this utility. The installed executable and
configuration must not be writable by the caller or desktop owner.

No session is started by installation. Linux has no service unit to enable.
History directories are created privately by the desktop owner on first use.

For a macOS approval desktop, also install the LaunchAgent as the desktop owner
and bootstrap it once as an administrator. Replace `andrew` and `501` with the
configured owner and UID:

```sh
sudo install -o root -g wheel -m 0755 deploy/macos/Launch.command \
  /usr/local/libexec/op-bridge/Launch.command
sudo install -d -o andrew -g staff -m 0755 /Users/andrew/Library/LaunchAgents
sudo install -o andrew -g staff -m 0644 \
  deploy/macos/com.adenta.op-bridge.session.plist \
  /Users/andrew/Library/LaunchAgents/com.adenta.op-bridge.session.plist
sudo launchctl bootstrap gui/501 \
  /Users/andrew/Library/LaunchAgents/com.adenta.op-bridge.session.plist
```

The job is registered in the Aqua domain but remains dormant because
`RunAtLoad=false` and `KeepAlive=false`. `_bridge` uses `launchctl kickstart`
when the private socket is absent. The agent runs `open -g -j` with the fixed
root-owned launcher to start `_serve` in hidden, non-activating Terminal, then
returns to dormancy immediately. The independent Terminal server exits after two
idle minutes. Both the launcher and all its parent directories must be root-owned,
without group/other write access. Do not replace this with a boot daemon.

Terminal preferences are unchanged; completed hidden tabs may remain depending
on existing settings. No AppleScript permission, Full Disk Access, or signing
setup is required by this installation. Whether the extra macOS access prompt is
eliminated must be verified on the target Mac. Native 1Password approval remains
in effect.

## Verify

```sh
op-bridge --version
op-bridge route show --format=json
op-bridge session doctor
op-bridge session status
```

Check the actual account reported by doctor. Test every configured destination
with the corresponding `--desktop NAME` override. Doctor does not prove native
authorization.

On macOS, doctor checks the CLI, Aqua GUI domain, LaunchAgent registration,
Terminal availability, trusted launcher ownership/permissions, and private cache
path. Standard 1Password desktop integration owns Touch ID,
unlock, and authorization.

When desktop access testing is authorized, run a metadata request with stdout
discarded and approve on the selected desktop:

```sh
op-bridge vault list --format=json > /dev/null
```

On the Mac, test with Terminal already running and, when no unrelated Terminal
work is open, with Terminal not running. Verify that startup stays hidden and
does not take focus. Check whether the extra macOS access prompt returns; treat
the workaround as incomplete if it does. Never quit unrelated Terminal work.

Repeat within two minutes, then after two idle minutes. For the lifetime check,
make metadata requests every minute for more than ten minutes, inspect worker age
with status, and observe native approval behavior when the worker rotates. Do not
use a separate native `op whoami` as a session test. Never verify installation by
writing a real secret.

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
   Wait until `session status` reports stopped before replacing files. On macOS,
   booting out the LaunchAgent alone does not stop the Terminal server.
3. Keep one private recovery directory containing only this installation's old
   executable, configuration, sudo rule (if present), command link target, and
   macOS LaunchAgent and `Launch.command` (if present).
   This is for restoring this update, not a whole-machine backup. Never copy
   1Password account data, sockets, or authorization state.
4. Stage each replacement beside its final path, set root ownership and the same
   modes as first installation, then rename it into place. Replace the executable,
   and only deliberately changed config/rule files, while callers remain paused.
   For a changed Mac LaunchAgent, boot out its old registration and bootstrap the
   replacement while callers remain paused. Install or replace `Launch.command`
   before registering the updated job, including when upgrading an old version
   without a launcher. Validate sudoers again before resuming. A changed executable
   needs a fresh session; do not restart an old worker with new files.
5. Run the verification checks. Resume callers only after they pass. Remove the
   recovery directory and staging files after successful verification.

If replacement or verification fails, keep callers paused, stop any new local
session and wait for stopped status (even if its LaunchAgent is dormant), and
restore the saved executable/configuration/rule/link/launcher as a matched set.
Restore the saved Mac LaunchAgent and its prior registration state; remove a
newly introduced launcher when rolling back to a version without one. Revalidate
and verify before resuming. Keep recovery files only while that recovery is
unfinished, and record their location. Preserve all access history,
including events written by the failed update. Never retry a submitted write as
part of recovery. An account change is a deliberate policy change, not an update
prerequisite.

For a partially completed first installation, remove only the files created by
that attempt after stopping its local session; do not remove history or native
account data. These procedures are manual; there is no hidden rollback controller.

## Repository-owned Ansible deployment

The repository includes one inventory-driven playbook for the four personal
hosts. Grace is the controller. Ansible manages only the release binary, command
symlink, configuration, generated sudoers rule, Mac LaunchAgent and Terminal
launcher, and the optional Grace/Love skill copies. It does not build code or
manage SSH aliases, users,
administrator access, 1Password, authentication, or unrelated Codex settings.

Copy `deploy/ansible/inventory.example.yml` to the gitignored
`deploy/ansible/inventory.local.yml`, then enter the real host identities,
accounts, routes, and skill paths. Build both checksummed artifacts before any
playbook run:

```sh
GOOS=linux GOARCH=amd64 bin/build-release VERSION
GOOS=darwin GOARCH=arm64 bin/build-release VERSION
mise trust
mise install
mise exec -- ansible-playbook -i deploy/ansible/inventory.local.yml \
  deploy/ansible/site.yml --syntax-check
```

Roll out serially. Keep XPS as the Grace/Love default during the first Mac
validation, then deliberately change those inventory defaults only after the
explicit Mac route succeeds:

```sh
mise exec -- ansible-playbook -i deploy/ansible/inventory.local.yml \
  deploy/ansible/site.yml --check --diff --limit mac
mise exec -- ansible-playbook -i deploy/ansible/inventory.local.yml \
  deploy/ansible/site.yml --limit mac
mise exec -- ansible-playbook -i deploy/ansible/inventory.local.yml \
  deploy/ansible/site.yml --limit 'grace:love'
mise exec -- ansible-playbook -i deploy/ansible/inventory.local.yml \
  deploy/ansible/site.yml --limit xps
```

Check mode validates target identity and artifact checksum and previews
configuration, LaunchAgent, Terminal launcher, and skill files. It deliberately does not unpack or
execute the target binary, generate sudoers, stop sessions, replace files, or
bootstrap launchd. A real run validates all staged inputs, refuses pending local
requests, stops the idle local session, saves the exact managed set, activates
and verifies it, and removes recovery data only after success. If activation or
verification fails, it restores the matched prior set. If restoration itself
cannot finish, its private recovery directory remains under `/var/tmp`; resolve
it before another run of that version.

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
macOS LaunchAgent registration/file and `Launch.command`, and optional skill
copies/links installed above. Preserve
`~/.local/state/op-bridge/history/` unless separately choosing to delete history.
Keep native 1Password data and unrelated credential stores. Do not restore retired
helpers or tokens as a side effect of uninstalling.
