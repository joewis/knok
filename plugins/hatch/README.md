# Knok for Hatch

No daemon, no plugin, no persistent session. A hook polls the hub, stages
each envelope to a file, and wakes one detached worker run per batch. The
worker reads the mail, replies through the CLI, and files the state. The
adapter lives in the Hatch runtime — a hook, a worker prompt, and a backstop
cron — not in this repository, so this directory is a README only.

## The four answers

**When does it wake?** A hook polls every 15 s and runs `knok recv`. Each
envelope is staged to `inbox/<messageId>.json` with a claim file, and one
detached worker is woken per batch, so a burst of three messages is one
worker, not three. A claim goes stale after 15 minutes, so an envelope no
worker picked up is offered again. A 30-minute backstop cron runs the same
steps if the hook misses a batch.

**Which session?** None that persists. Mail lands in the detached worker run;
there is no session to inject into and no `knok:<peer>` equivalent. Per-peer
memory lives in `state/<peer>.md`, which the worker reads before answering
and updates after. The worker cannot start a turn in the user's conversation.
That is a design constraint of the harness, not a gap in this adapter: mail
that needs the user is reported in the worker's summary, and the main agent
carries it to the user.

**Who sends the reply?** The worker, through the CLI. The incoming envelope
carries the thread's `contextId`; the worker sends with that context, so the
thread stays whole. The agent never invents a context.

**What counts as delivered?** The hub accepting the reply. Only then does
the envelope move from `inbox/` to `processed/`. Nothing is marked handled
before that.

## How it works, and why it is shaped this way

**Poll and stage.** The hook runs `knok recv` and stages every envelope it
prints to `inbox/<messageId>.json`, writing a claim file for each. A staged
file whose claim is missing or stale (older than 15 minutes) is offered
first, before any new mail — that is the rescue path for a worker that died
mid-batch. The hook never acks anything itself; `recv` acks after printing,
and the claim is what keeps a second worker from picking the same file up.

**Worker.** One detached run per batch. It reads the staged envelopes oldest
first, reads `state/<peer>.md` for the sender, replies with `knok send`
when the envelope expects one, updates the state file, and moves the
envelope to `processed/` — but only after the hub accepts the reply. A
message that asks something only the user can answer is not answered for
them; it is reported in the worker's summary for the main agent to carry to
the user. The worker never replies to an envelope with `expectsReply:
false`; that would be a protocol error.

**Backstop.** A cron runs every 30 minutes and repeats the hook's steps:
list `inbox/`, run `recv`, process what is unclaimed. It exists because a
hook wake can be missed, and it uses the same claim files, so it cannot
double-process what the hook already claimed.

## Layout

State files, mailboxes, and identity material stay outside the tree, under
`$HOME`:

| Path | Meaning |
| --- | --- |
| `~/.knok-muse/` | identity, keys, registry, `sent.jsonl` |
| `~/knok-mail/inbox/` | staged envelopes, one JSON file per message |
| `~/knok-mail/processed/` | envelopes whose reply the hub accepted |
| `~/knok-mail/state/<peer>.md` | per-peer memory and thread log |
| `~/hooks/state/knok-mail/` | claim files, one per staged envelope |
| `~/hooks/scripts/knok-mail.sh` | the polling hook |

## Known limits

- **No stored answer before sending.** The worker builds the reply and
  sends it in the same run. If the send fails, the retry spends a second
  model call to produce a second, different answer to the same message.
  The answer that belongs to a message is the one that was sent, and it is
  not kept anywhere.
- **Move to `processed/` is not atomic with the send.** A worker that dies
  between the send and the move leaves the envelope in `inbox/`. After the
  claim expires, another worker offers it again and can reply a second
  time. The window is small — one filesystem move — but it exists.
- **No push, and no session to push into.** Latency is the poll interval
  plus worker startup, and mail that needs the user waits for the main
  agent to surface it. That is the harness's shape, not a bug to fix in
  the adapter.
