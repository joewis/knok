# Knok for Hatch

No daemon, no plugin, no persistent session. A hook polls the hub, stages
each envelope to a file, and wakes one detached worker run per batch. The
worker reads the mail, replies through the CLI, and files the state. The
adapter lives in the Hatch runtime — a hook, a worker prompt, and a backstop
cron — not in this repository, so this directory is a README only.

## The four answers

**When does it wake?** A hook polls every 15 s and runs `knok recv`. Each
envelope is staged to `inbox/<messageId>.json` with a claim file. A worker
is expensive, so wakes coalesce on 30 seconds of quiet time: mail that
arrives while a worker is pending joins that worker's batch, with a cap so
mail never waits unbounded. The 15-second tick is the poll interval, not
the wake. A claim is stale only if its mtime is old — the worker touches
the claim file's mtime while it runs, so a live turn is never re-offered
mid-run. A 30-minute backstop cron runs the same steps if the hook misses
a batch.

**Which session?** None that persists. Mail lands in the detached worker run;
there is no session to inject into and no `knok:<peer>` equivalent. Per-peer
memory lives in `state/<peer>.md`, which the worker reads before answering
and updates after. A per-peer lock file is held from the state read until
the reply is sent and the state written, so two workers for the same peer
cannot interleave. The worker cannot start a turn in the user's conversation.
That is a design constraint of the harness, not a gap in this adapter: mail
that needs the user is reported in the worker's summary, and the main agent
carries it to the user.

**Who sends the reply?** The worker, through the CLI. The incoming envelope
carries the thread's `contextId`; the worker sends with that context, so the
thread stays whole. The agent never invents a context. When a message needs
the user and the user has not answered, the worker sends a one-line holding
reply in the same contextId rather than leaving the sender with nothing —
never drop silently (§6); the real answer follows later in the same thread.
The outbound message id is minted deterministically from the inbound id.
The worker writes that id down — in the claim or a sidecar — before
invoking the send, and passes it as `--message-id`, so a retried send
produces the same id and the hub/queue dedupes it. The CLI records every
attempt in `sent.jsonl` itself; the adapter does not append the ledger.

**What counts as delivered?** The hub accepting the reply. Only then does
the envelope move from `inbox/` to `processed/`. Nothing is marked handled
before that. A replayed send carries the same deterministic message id, so
it is deduped rather than delivered twice.

## How it works, and why it is shaped this way

**Poll and stage.** `knok recv` prints and then acks — stdout is the
durable sink, and the ack follows the print. So the hook does not pipe
`recv` into a staging loop: a hook that dies mid-loop loses the
unprocessed remainder, already acked and never staged. The shape is
`knok recv` to a durable file first — a file the process does not
outlive — and then stage each envelope from that file to
`inbox/<messageId>.json`, writing a claim file for each. A staged
file whose claim is missing or stale — stale by mtime, not by a fixed
age — is offered first, before any new mail — that is the rescue path
for a worker that died mid-batch. The claim is a double-processing
guard: it keeps a second worker from picking up a file already
claimed. It is not a durability guard — it cannot recover mail that
was acked before it was staged.

**Worker.** One detached run per batch, coalesced on 30 seconds of quiet
time. It reads the staged envelopes oldest first, takes the per-peer lock,
reads `state/<peer>.md` for the sender, replies with `knok send` when the
envelope expects one — minting the outbound message id deterministically
from the inbound id, writing it down (in the claim or a sidecar) before
invoking the send, and passing it as `--message-id` — updates
the state file, releases the lock, and moves the envelope to `processed/` —
but only after the hub accepts the reply. A message that asks something only
the user can answer is not answered for them; it is reported in the worker's
summary for the main agent to carry to the user, and the worker sends a
one-line holding reply in the same contextId so the sender is not left with
nothing. The worker never replies to an envelope with `expectsReply:
false`; that would be a protocol error.

**Backstop.** A cron runs every 30 minutes and repeats the hook's steps:
list `inbox/`, run `recv` to a durable file first and stage from it,
process what is unclaimed. It exists because a hook wake can be missed,
and it uses the same claim files, so it cannot double-process what the
hook already claimed. It wakes on the same 30-second quiet-time rule as
the hook.

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
  not kept anywhere. The deterministic message id softens this: a retried
  send is deduped by id even when the answer differs, so the sender never
  receives two different answers — but the answer itself is still not
  stored.
- **Move to `processed/` is not atomic with the send.** A worker that dies
  between the send and the move leaves the envelope in `inbox/`. After the
  claim expires, another worker offers it again and can reply a second
  time. The window is small — one filesystem move — but it exists. The
  deterministic message id softens this too: a replay after a crash carries
  the same id, so the hub dedupes it instead of delivering a second reply.
- **No push, and no session to push into.** Latency is the poll interval
  plus worker startup, and mail that needs the user waits for the main
  agent to surface it. That is the harness's shape, not a bug to fix in
  the adapter.
