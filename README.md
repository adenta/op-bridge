# op-bridge

Use a desktop's native 1Password authorization from local tools, remote shells,
and trusted automation. op-bridge provides a small, restricted CLI for listing,
reading, creating, and editing 1Password items. It works without Codex or an agent.

```sh
op-bridge route show
op-bridge vault list --format=json
op-bridge read 'op://Vault/Item/password'
op-bridge --desktop office --timeout 180 item get ITEM_ID --fields password
op-bridge item create --vault VAULT - < item.json
op-bridge item edit ITEM_ID --vault VAULT < updated.json
```

Output can contain secrets. Request only the needed field and pass it directly to
the process that needs it. Do not put values in logs, shell arguments, or source files.

## How it works

```text
caller → local bridge or existing SSH alias → desktop owner's private socket
       → temporary shared terminal worker → native op CLI → 1Password desktop
```

Each approval desktop pins one administrator-configured account. Native
1Password decides whether approval or unlocking is needed. The helper shares one
terminal for up to ten minutes and stops after two idle minutes.

Requests are serialized and bounded. Writes use JSON on stdin and are never
automatically retried. Private request/outcome metadata stays on the approval
desktop for 90 days. Secret values and templates are not cached or logged by the
helper; native stdout and stderr are returned to the caller.

Linux amd64/arm64 and macOS arm64 are supported. Linux approval desktops use a
transient systemd user service, the desktop user session, and `/usr/bin/op`. An
Apple Silicon approval desktop uses a registered but normally dormant Aqua
LaunchAgent that opens the fixed launcher in hidden, non-activating Terminal,
and `/opt/homebrew/bin/op`. Both use the ordinary 1Password desktop
integration for Touch ID, unlocking, and authorization. Remote clients need
OpenSSH and an existing working SSH alias. There is no fleet service, custom
network listener, or unattended account login.

## Get started

1. [Build and install](docs/install.md) on each machine you want to use.
2. [Configure routes and accounts](docs/configuration.md).
3. Read the [command and behavior reference](docs/usage.md).

The [agent skill](skills/op-bridge/SKILL.md) is optional. Installing the command
does not modify agent settings, SSH identities, account authentication, or system
administrator permissions.

## Trust model

This utility is for trusted callers. Access is broad within the configured
account, not restricted by vault, item, task, or individual request approval.
1Password can authorize later requests in the same terminal session.

The privileged bridge is a fixed root-owned executable with one narrowly scoped
sudo entry. A caller that already has unrestricted sudo remains an administrator.
See [security boundaries](SECURITY.md).

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
bin/check-package
```

Deployment recovery can also be tested locally with the repository's existing
Ansible toolchain, using disposable files and a fake bridge:

```sh
mise exec -- ansible-playbook -i localhost, -c local tests/deployment-recovery.yml
```

Tests use fake CLI processes, private temporary sockets, and on macOS a
disposable Aqua LaunchAgent. Bash, Node.js, and `visudo` exercise additional
integration checks. No test accesses a live 1Password desktop. Sandboxes that
prohibit Unix sockets cannot run the integration suite. Build requirements are
in `go.mod`.

The implementation was extracted from the secrets helper in Codex Ops; see
[origin](ORIGIN.md). op-bridge is an independent project, not an official
1Password product.
