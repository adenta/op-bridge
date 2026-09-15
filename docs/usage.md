# Commands and behavior

## Commands

```sh
op-bridge vault list --format=json
op-bridge item list --vault VAULT --format=json
op-bridge item get ITEM_ID --vault VAULT --fields password
op-bridge read 'op://Vault/Item/field'
op-bridge --desktop office --timeout 180 read 'op://Vault/Item/field'
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
the session alive. Doctor checks CLI presence, the desktop bus, and notification
service ownership without sending a banner or activating the service.

| Operation | Supported options |
|---|---|
| `vault list` | `--format` |
| `item list` | `--format`, `--vault`, `--tags`, `--categories`, `--favorite`, `--include-archive`, `--long` |
| `item get ITEM` | `--vault`, `--fields`, `--format`, `--reveal`, `--otp`, `--include-archive` |
| `read REFERENCE` | `--no-newline` or `-n` |
| `item create -`, `item edit ITEM` | `--vault`, `--format`, `--dry-run` |

Formats are `json` and `human-readable`. All operations accept an explicit
`--account` only when it matches the configured account. Unknown commands/options,
deletion, documents, attachments, shell execution, native file options, `exec`,
`run`, and environment injection are rejected.

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
only when execution is known not to have begun. Failed notification acceptance
is a definite not-started result.

Native stdout, stderr, and exit status are preserved; the helper adds route and
failure diagnostics on stderr. Native output can itself contain secrets. Wrapper
transport errors never include request input, environment, or secret references.

## Session and resource limits

The first secret request starts a transient `op-bridge-session.service` under the
desktop owner with `Restart=no`. Nothing is enabled at login or boot. Its worker
retains a controlling PTY inherited by native CLI processes. No command data is
sent through the PTY, and no transcript is stored.

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

## Notifications

Each validated list, read, create, edit, or dry-run request must receive acceptance
from the selected desktop's notification service before dispatch. The entire
D-Bus connection and notification call has a two-second deadline. Missing service,
rejection, or timeout blocks the operation. There is no silent fallback.

The banner says **op-bridge: access requested** and shows the operation and supplied
vault/item identifiers. It never includes values, field paths, write contents,
native output, or arbitrary arguments. Identifiers are capped at 160 characters,
stripped of control/format characters, and escaped for markup. Templates are not
inspected for notification text. Names may appear on a lock screen.

Each banner requests a five-second expiry. Desktop settings can suppress it or
change its visible duration. Service acceptance is not proof that someone saw
the banner, nor that 1Password displayed a fresh authentication prompt. Invalid
requests, control commands, and requests canceled while queued do not notify.

## Access history

The approval desktop stores daily JSON Lines files in its owner's
`~/.local/state/op-bridge/history/`. Directories are 0700 and files 0600. There is
no history CLI or cross-desktop aggregator. Paths reject unsafe permissions,
symlinks, and multiply linked history files.

Validated secret requests received by the session generate `request` and
`outcome` events joined by `request_id`. Records contain UTC time, operation,
dry-run flag, notification-safe identifiers, notification acceptance, and an
outcome (`success`, `failure`, `not_started`, or `unknown`). Native exit status is
included when available. Reasons use fixed codes, not raw errors.

There are no values, templates, field paths, native output, task identities, or
newly created item IDs in history. An incomplete request is not evidence of
success or of no effects. Invalid requests, control commands, and failures before
reaching the session are excluded. History is convenient metadata, not a
tamper-proof audit trail. Logging/cleanup failures warn without changing the
secret operation's exit status.

Files dated more than 90 days before the current UTC date are removed at session
startup and on the next logged event after a date change. Cleanup waits while the
helper is inactive. Updates preserve history.

```sh
# Run as the approval desktop owner; metadata can identify private items.
jq . ~/.local/state/op-bridge/history/YYYY-MM-DD.jsonl
```
