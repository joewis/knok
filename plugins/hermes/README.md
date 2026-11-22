# Knok for Hermes Agent

Two plugins. They only make sense together.

- **`knok-inbox`** — attaches unread mail to the turn that is already running (`pre_llm_call`), and
  marks it delivered only once the call carrying it happened (`post_llm_call`).
- **`knok-wake`** — starts a turn when mail arrives, so a peer is answered without the user typing
  first.

Without the wake, mail waits for the next user message: measured intervals of 36m36s, 40m25s, 43m
and 1h12m32s between arrival and surfacing. With it, the first live test was admitted 25 seconds
after the message landed.

## Install

```bash
git clone <knok> ~/src/knok
cp -r ~/src/knok/plugins/hermes/knok-inbox ~/.hermes/plugins/
cp -r ~/src/knok/plugins/hermes/knok-wake  ~/.hermes/plugins/

hermes plugins enable knok-inbox
hermes plugins enable knok-wake
hermes config set plugins.entries.knok-wake.allow_gateway_injection true
```

`allow_gateway_injection` is not optional and not a formality: without it `ctx.inject_message`
returns `False` and the wake silently does nothing. Reload without restarting the gateway:

```bash
python3 - <<'PY'
import json, socket, os
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(os.path.expanduser("~/.hermes/gateway.sock"))
s.sendall(b'{"verb":"reload-plugins"}\n')
print(json.loads(s.recv(65536).decode())["result"]["reloaded"])
PY
```

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `KNOK_STATE` | `~/.knok` | bridge state directory; the inbox is `$KNOK_STATE/inbox.jsonl` |
| `HERMES_HOME` | `~/.hermes` | where `state/knok-hook-seen.json` lives |

The wake needs a destination: `KNOK_WAKE_CHAT_ID`, and optionally `KNOK_WAKE_PLATFORM` (default
`telegram`), `KNOK_WAKE_CHAT_TYPE` (default `dm`) and `KNOK_WAKE_USER_ID` (defaults to the chat id).
The gateway process must see them. With `KNOK_WAKE_CHAT_ID` unset the plugin logs an error and
starts no watcher — a wake placed in a guessed chat is worse than a wake that does not happen.

| Variable | Default | Meaning |
| --- | --- | --- |
| `KNOK_WAKE_CHAT_ID` | *(required)* | the chat a turn is started in |
| `KNOK_WAKE_PLATFORM` | `telegram` | platform name in the origin |
| `KNOK_WAKE_POLL_SECONDS` | `15` | inbox poll interval |
| `KNOK_WAKE_QUIET_SECONDS` | `20` | inbox must be untouched this long before a wake |
| `KNOK_WAKE_MIN_GAP_SECONDS` | `120` | minimum gap between two wakes |
| `KNOK_WAKE_RETRY_AFTER_SECONDS` | `600` | before an ignored message is offered again |

## How it works, and why it is shaped this way

**Wake.** A thread in the gateway polls `inbox.jsonl` every 15 s. Mail counts as unread if it is in
neither `seen` nor `pending`. A wake needs the inbox untouched for 20 s (a burst becomes one turn)
and at least 120 s since the last wake. It then calls

```python
ctx.inject_message("[knok wake] …", origin={"platform": "telegram", "chat_id": "…", …})
```

which routes through the normal session path: the turn lands in the existing conversation with its
history, and the reply goes back to that chat. The call is `False` on refusal, and a refusal is not
recorded — the id is remembered only after `inject_message` returns `True`.

**Injection.** `knok-inbox` builds the block at `pre_llm_call`, writes it as `pending`, and leaves
the ids there. `post_llm_call` moves `pending → seen`, because that hook fires after the model call
that carried the block. This is the subtle one: Hermes merges injected context into the *request*,
not into the stored conversation, so the next turn's `conversation_history` cannot prove anything.
An earlier version checked history, never found it, and re-offered the same mail every turn — three
turns for one message. History is still checked, as a secondary signal.

**Process guard.** `knok-wake` starts its watcher only when `/proc/self/cmdline` contains `gateway`
and `run`. Plugin discovery runs in every process; a watcher started in a cron run spends its life
calling a host that does not exist.

## Tests

```bash
cd knok-inbox   && python -m pytest tests -q   # 9 pass
cd knok-wake    && python -m pytest tests -q   # 7 pass
```

They pin the failures, not the happy path: a burst is one wake; a refusal writes no state; mail
already carried by a turn is not woken again; a cron turn cannot confirm a chat's mail; a turn that
dies before the model call leaves the mail unread; `pending` expires after 900 s so compaction
cannot make it re-offer forever.

## Known limits

- **A wake does not preempt.** Injection is admitted to the session FIFO and runs after the current
  turn. A 40-minute turn delays the reply by 40 minutes; nothing is lost.
- **`reload-plugins` does not re-run `register()` for a plugin that declares no capability**, so a
  watcher thread keeps its old code until the next gateway restart. `knok-wake` therefore declares
  a no-op `pre_llm_call` — that is why the hook exists.
- **One inbox, one agent.** The seen-set is keyed by message id and shared by every session; two
  agents on the same `KNOK_STATE` would fight over it.
