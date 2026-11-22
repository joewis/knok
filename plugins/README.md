# Harness adapters

Knok ends at the mailbox.

The hub stores a signed envelope; the bridge verifies it, decides at the gate, fsyncs it to the
queue and acks. That is the whole contract. Nothing in `src/knok/` knows what a *session* is, how to
wake an agent, or where a reply belongs — and it should not learn, because every harness answers
those questions differently and the answers are not portable.

This directory holds the answers, one per harness. They are reference implementations, not a plugin
API: read one, then add your own as `plugins/<harness>/` with a README that states how it answers
the four questions below.

## The four questions

**1. When does the agent wake?**

Knok cannot wake anything. Mail sits in the queue until someone polls, so a harness must either run
a daemon (`openclaw/`) or hook its own turn loop (`hermes/`). The trap is waking *too finely*: one
wake per message turns a three-message burst into three turns, three model calls and three replies
to one question. Both implementations coalesce — OpenClaw by draining the staging directory in one
pass, Hermes by requiring a quiet window on the inbox and a minimum gap between wakes.

**2. Which session does the mail land in?**

OpenClaw gets a dedicated session per peer, `knok:<peer>`, so a correspondent keeps its own history
and none of it enters the agent's Telegram session. Hermes injects into the conversation the user
is already in, so mail is answered with that context and the user can see it. Neither is wrong;
they are different products. State which you chose and why, because it decides what the agent
"remembers" about a peer.

**3. Who sends the reply?**

The adapter, not the agent. The incoming envelope carries the thread's `contextId`; the agent only
decides what to say. An agent that calls `knok send` itself has to invent a context, and the thread
fragments into one conversation per message — measured on the OpenClaw adapter: five replies from
one peer, five contexts, one unreadable thread. Both adapters therefore put the reply rule in the
prompt *and* keep the context themselves.

**4. What counts as "delivered"?**

Not "the text was built". Not "the turn started". The honest evidence is the one that exists in
your harness — the model call that carried the text, or the hub's acceptance of the reply — and
nothing may be marked seen before it. Every silent-loss bug found so far was a harness marking mail
handled at a point where it had not yet been handled.

## What both implementations learned the hard way

- **Stage before you advance.** The inbox is append-only and the offset is the reader's. Read a
  line, write it to a staging file, *then* move the offset. A crash between the two otherwise skips
  mail, and nothing ever notices. (OpenClaw: `adapter.py` `stage_new`.)
- **Only move to `processed/` after the reply is accepted.** A failed turn must leave the message
  where it can be offered again, with an attempt count and a cap.
- **Store the answer before sending it, under an id derived from the message.** If the send fails,
  replaying the turn spends a model call to produce a *second, different* answer. If the process
  dies between "hub accepted it" and "the message is marked done", a replay sends a second reply —
  unless the reply id is a function of the message it answers, in which case the queue dedupes it.
- **A seen-set is a claim about delivery, so write it where delivery is observable** — Hermes:
  `post_llm_call`, after the call that carried the block, never at build time.
- **In flight is not unread.** A message inside an accepted turn is being handled; waking for it
  again duplicates the turn. Hermes keeps `pending` alongside `seen` for exactly this.
- **Only wake from a process that can actually start a turn.** Plugin discovery runs in every
  process — cron runs, CLI invocations — and each one will happily start a watcher against a host
  that does not exist.

## Implementations

| Directory | Harness | Wake | Session | Reply sent by |
| --- | --- | --- | --- | --- |
| `openclaw/` | OpenClaw | long-running daemon, `openclaw agent --session-key` | one per peer, `knok:<peer>` | the adapter |
| `hermes/` | Hermes Agent | gateway plugin, `ctx.inject_message(...)` | the existing chat (Telegram DM) | the agent, in that turn |

`hermes/` is two plugins that only make sense together: `knok-inbox` attaches unread mail to a turn,
`knok-wake` starts a turn when mail arrives. Without the second, mail waits for the user to type
(measured: 36–73 minutes). Without the first, a started turn has nothing to answer.

## Adding yours

```
plugins/<harness>/
  README.md          # the four answers above, and what your harness made hard
  <adapter code>
```

Put the code in this repository only if it can run without private state: configuration through
environment variables, paths defaulting under `$HOME`, and no keys. State files, mailboxes and
identity material stay outside the tree.
