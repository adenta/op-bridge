# Commands and behavior

## Commands

```sh
op-bridge vault list --format=json
op-bridge item list --vault VAULT --format=json
op-bridge item get ITEM_ID --vault VAULT --fields password
op-bridge read 'op://Vault/Item/field'
op-bridge --desktop office --timeout 180 read 'op://Vault/Item/field'
op-bridge inject < secrets.template
op-bridge item create --vault VAULT - < item.json
op-bridge item edit ITEM_ID --vault VAULT < updated.json
op-bridge route show --format=json
op-bridge session doctor
op-bridge session status
op-bridge session stop
```

Global `--desktop` and `--timeout` precede the operation. Both accept `--name=value`
and `--name value`, in either order. Duplicate global options are rejected. A
desktop override affects one invocation; there is no saved task preference,
automatic desktop detection, fan-out, or fallback. The client names the selected
desktop on stderr before secret requests.

`route show` reports `execution_host`, `desktop`, `transport`, and `source`
(`default` or `override`). It reads local configuration only. Session commands use
the selected route too. `session stop` affects every caller sharing that desktop's
session. Doctor/status/route checks do not request native authorization or keep
the session alive. On Linux, doctor checks the CLI, runtime path, and desktop bus.
On macOS arm64, it checks `/opt/homebrew/bin/op`, the Aqua GUI domain,
LaunchAgent registration, Terminal availability, the trusted installed launcher,
and the private cache path. Doctor adds `terminal_available` and
`terminal_launcher_trusted` booleans on macOS. It does not ask 1Password
to authorize.

| Operation | Supported options |
|---|---|
| `vault list` | `--format` |
| `item list` | `--format`, `--vault`, `--tags`, `--categories`, `--favorite`, `--include-archive`, `--long` |
| `item get ITEM` | `--vault`, `--fields`, `--format`, `--reveal`, `--otp`, `--include-archive` |
| `read REFERENCE` | `--no-newline` or `-n` |
| `inject` | None; template on stdin, rendered output on stdout |
| `item create -`, `item edit ITEM` | `--vault`, `--format`, `--dry-run` |

Formats are `json` and `human-readable`. All operations accept an explicit
`--account` only when it matches the configured account. Unknown commands/options,
deletion, documents, attachments, shell execution, native file options, `exec`,
`run`, and environment injection are rejected.

## Bulk retrieval

`inject` resolves several secret references using one bridge request and one
native `op inject` invocation in the shared terminal worker:

```sh
op-bridge --desktop mac --timeout 180 inject <<'EOF'
REGISTRY_PASSWORD={{ op://Personal/Registry/password }}
DATABASE_PASSWORD={{ op://Production/Database/password }}
EOF
```

Use native `{{ op://Vault/Item/field }}` template syntax. The bridge forwards the
template without parsing or rewriting it; native 1Password resolves references
under the pinned account. Caller environment variables are not forwarded. There
is no custom escaping: callers must handle the destination's JSON, shell,
dotenv, or other format requirements. Do not evaluate rendered output as shell
code. Repeated references, literal text, multiline content, and empty templates
are passed through to native 1Password.

Templates are accepted only on stdin. Input redirection reads files on the
caller's machine; `--in-file`, `--out-file`, positional filenames, and other
native options are rejected (the matching pinned `--account` remains allowed).
The client reads and validates the complete input before opening transport and
provides it to the native CLI through an OS pipe. The existing 64 KiB encoded
request limit includes the template; output streams remain limited to 16 MiB
each. One request timeout covers the whole operation, including queuing.

Stdout is buffered and returned only if the entire operation succeeds. A native
failure, timeout, cancellation, or output-limit failure returns no stdout, even
if the CLI emitted a partial result. Native stderr and nonzero exit status follow
the existing command behavior; stderr can contain secrets. No template or
rendered output is logged, cached, or saved by the helper.

Update both client and approval desktop before using `inject`. The wire protocol
remains version 2, but older desktops reject this new allowlisted command. Phone
approval support is separate follow-up work.

## Safe writes

Writes require a nonempty native JSON item object on stdin. Create requires `-`;
edit requires an item selector. Put the category, title, and fields in the JSON.
Command-line field assignments are rejected. Input redirection happens on the
caller's machine. The helper reads input before opening its request transport,
then supplies native CLI stdin through an OS pipe, including for Node callers.

Before editing, retrieve the complete item with `item get ITEM --vault VAULT
--format=json`, change only the requested fields, and preserve everything else.
**Do not template-edit items containing passkeys:** use the 1Password app instead.
The helper does not detect or preserve passkeys automatically. Prefer preparing
JSON in a process and piping it directly. If a temporary file is necessary, use
private permissions and remove it afterward. Dry-run output can contain secrets.

Writes are never retried automatically. After a disconnect, timeout, or lost
response, the result can be unknown even if the CLI made the change. Inspect the
item before considering another write. Protocol responses carry `not_started`
only when execution is known not to have begun.

Except for discarding failed `inject` stdout, native stdout, stderr, and exit
status are preserved; the helper adds route and
failure diagnostics on stderr. Native output can itself contain secrets. Wrapper
transport errors never include request input, environment, or secret references.

## Session and resource limits

On Linux, the first secret request starts a transient
`op-bridge-session.service` under the desktop owner with `Restart=no`. On macOS
arm64, it kickstarts the already registered
`com.adenta.op-bridge.session` Aqua LaunchAgent. That agent has
`RunAtLoad=false` and `KeepAlive=false`: it remains registered but dormant until
needed. It runs `/usr/bin/open -g -j -a /System/Applications/Utilities/Terminal.app`
with the fixed `/usr/local/libexec/op-bridge/Launch.command`, then returns to
dormancy; the server runs inside Terminal independently of launchd. The script
executes the installed `_serve` command without request arguments. Startup is
serialized across callers and bounded to 15 seconds, including socket readiness;
failure reports an error without switching to background hosting.
The private `startup.lock` records only whether a launch was attempted and its
timestamp. For 15 seconds after an incomplete attempt, another caller waits for
its socket instead of opening a duplicate Terminal session. Once ready, the
marker is cleared; the lock file remains to coordinate future processes.

Terminal is requested to stay hidden and not take focus. Its preferences are not
changed, and completed hidden tabs may remain according to existing settings.
Quitting Terminal ends its hosted session. Use `session stop` to stop the bridge;
unloading the LaunchAgent alone does not stop a Terminal-hosted server. This
hosting method does not guarantee elimination of macOS access prompts.

The worker retains a
controlling PTY inherited by native CLI processes. No command data is sent
through the PTY, and no transcript is stored.

- Idle expiry: 120 seconds with no queued or active secret requests.
- Maximum terminal worker lifetime: ten minutes from creation, measured
  monotonically; activity cannot extend it.
- An operation active at expiry may finish within its existing request timeout.
  Before another dispatch, the worker is replaced. Queued deadlines remain intact.
- Request timeout: 120 seconds by default; explicit limits range from 1 to 300.
- At most 16 queued/active operations and 32 open session connections.
- Request limit: 64 KiB including JSON envelope, encoded stdin, and account pin.
- Each native output stream: at most 16 MiB.

Status includes idle limit, worker age, worker lifetime, and remaining reuse
lifetime. Remaining lifetime is not proof of native authorization; 1Password
locking and authorization limits still apply. No keepalive calls are made.
Disconnect/timeout cancels the CLI process group and escalates to killing a stuck
process. Operations are never replayed. A delayed JSON trailing newline does not
count as a disconnect. Request/response wire protocol remains version 2.

## Access history

The approval desktop stores daily JSON Lines files in its owner's
`~/.local/state/op-bridge/history/`. Directories are 0700 and files 0600. There is
no history CLI or cross-desktop aggregator. Paths reject unsafe permissions,
symlinks, and multiply linked history files.

Validated secret requests received by the session generate `request` and
`outcome` events joined by `request_id`. Records contain UTC time, operation,
dry-run flag, sanitized identifiers, and an outcome (`success`, `failure`,
`not_started`, or `unknown`). Native exit status is included when available.
Reasons use fixed codes, not raw errors.

There are no values, templates, field paths, native output, task identities, or
newly created item IDs in history. An incomplete request is not evidence of
success or of no effects. Invalid requests, control commands, and failures before
reaching the session are excluded. History is convenient metadata, not a
tamper-proof audit trail. Logging/cleanup failures warn without changing the
secret operation's exit status.

`inject` records only operation and outcome metadata; templates are not parsed
for vault, item, or field identifiers.

Files dated more than 90 days before the current UTC date are removed at session
startup and on the next logged event after a date change. Cleanup waits while the
helper is inactive. Updates preserve history.

```sh
# Run as the approval desktop owner; metadata can identify private items.
jq . ~/.local/state/op-bridge/history/YYYY-MM-DD.jsonl
```
