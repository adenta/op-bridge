---
name: op-bridge
description: Retrieve 1Password secrets or create and edit items through a configured local or SSH desktop authorization bridge. Use when a task needs a credential, password, API key, token, or op:// reference, or needs to diagnose an op-bridge request.
---

# op-bridge

Use `op-bridge` on the machine where the task runs. It manages the configured
route, native authorization, desktop notification, and temporary shared session.
Use `op-bridge route show --format=json` to inspect the default route without
starting a session or requesting approval. Use `--desktop NAME` before the
operation to select an explicitly configured desktop for one invocation. If the
user requests that desktop for the task, pass the override on subsequent commands
in the task. There is no saved task preference or automatic route fallback.

## Retrieve a value

```sh
op-bridge vault list --format=json
op-bridge item list --vault VAULT --format=json
op-bridge item get ITEM_ID --vault VAULT --fields password
op-bridge read 'op://Vault/Item/field'
op-bridge --desktop NAME --timeout 180 read 'op://Vault/Item/field'
```

Use a known reference or item ID first. List metadata only when needed. Request
the required field instead of a full item. Keep values out of task output, logs,
source files, command arguments, and shell traces. Pass a value directly to the
process that needs it. Report a value to the user only when requested. Create a
`.env` file only if the task requires one.

Each approval desktop pins one administrator-configured account. The bridge
provides broad access within that account; there is no per-task vault restriction.
Do not attempt to switch accounts. Native 1Password may request approval; tell the
user to approve on the destination identified by the command. Requests default to
120 seconds; global `--timeout SECONDS` permits 1 to 300 seconds.

## Create or edit

Use writes only when the task calls for storing or changing an item. Supply a
native JSON item object on stdin, keeping secret values out of command arguments.
Input redirection happens on the caller's machine:

```sh
op-bridge item create --vault VAULT - < item.json
op-bridge item edit ITEM_ID --vault VAULT < updated.json
```

Both commands accept `--format=json`, `--format=human-readable`, and `--dry-run`.
Dry-run output can contain secrets. Set category, title, and fields in the JSON.
Attachments, native file options, and command-line field assignments are rejected.

Before editing, retrieve the full item with `item get ITEM_ID --vault VAULT
--format=json`, change only the requested fields, and preserve the others. Do not
template-edit items with passkeys; use the 1Password app. The helper does not
protect passkeys automatically.

Prefer JSON piped directly from its preparing process. If a temporary file is
necessary, use restrictive permissions and remove it afterward. Requests are
limited to 64 KiB including encoded stdin and the envelope. The helper does not
retain templates. Never automatically retry a write after timeout or disconnect:
it may have completed. Inspect the item before deciding whether another write
is necessary. `not_started` is a definite rejection before execution.

## Diagnose

```sh
op-bridge session doctor
op-bridge session status
```

Use the same desktop override as the failing operation. These commands do not
unlock 1Password or start a secrets session. Status reports helper state, not
native authorization. Doctor checks CLI presence, the user bus, and notification
service availability. Report failed routes or authorization; do not repeatedly
retry. Do not change SSH identities, sudo rules, or authentication as a workaround.
Do not run `op signin`, copy session tokens, add accounts, or require a separate
`op whoami`: separate terminals can have different authorization states.

Every secret operation requires notification-service acceptance within two seconds.
If it fails, report the failure; do not bypass it by calling native `op` directly
or changing desktop settings. Banners show operation and sanitized vault/item
identifiers, never values or templates. Identifiers may appear on a lock screen.
Service acceptance does not prove visibility or fresh native authentication.

The shared session stops after two idle minutes. Its terminal worker has a
nonextendable ten-minute maximum lifetime; an active operation may finish within
its timeout, then the next request uses a fresh worker. Queued deadlines remain
intact and requests are never replayed. Native locking and limits still apply.
Status and doctor do not keep it alive. Stop the session only at the user's request
or when recovery requires it; stopping affects all callers using that desktop.

The desktop owner keeps private 90-day request/outcome metadata in
`~/.local/state/op-bridge/history/YYYY-MM-DD.jsonl`. Inspect it on the selected
desktop when investigating access. Correlate events by `request_id`; an incomplete
request or `unknown` outcome does not prove that nothing happened. Records exclude
values, templates, native output, field paths, task identity, and created item IDs.
Logging failures warn without blocking access. There is no history CLI.

Only `vault list`, `item list`, `item get`, `read`, `item create`, and `item edit`
are supported. No deletion, document transfer, `exec`, `run`, or environment
injection. See `op-bridge --help` and the installed documentation for details.
