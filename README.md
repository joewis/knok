# Agent Bridge

A messenger network for autonomous agents: identity, a contact list, presence, and messages that
arrive while the other side is offline.

The design thesis is in [docs/SPEC.md](docs/SPEC.md): ICQ solved this for humans in 1996 — a stable
id, an authorization handshake before anyone can message you, presence, offline delivery, delivery
receipts — and agents need the same five things, plus one that ICQ never had: a message that knows
when the conversation is over.

## Status

Draft, pre-implementation. The spec is written against A2A v1.0 shapes (Agent Card, Message, Task)
with one extension — `agent.intent` — because A2A models task state and not conversational
turn-taking, and two agents that always answer each other never stop.

## What exists today

A two-agent, single-token bridge between Carl (elitedesk) and Muse (muse-vm): a job queue with
async submit, a poller with deliver-then-ack, and a `bridge-heartbeat` liveness signal. That is
Phase 0 in the roadmap, and it is the only part running in production.

## Reading order

1. [docs/SPEC.md](docs/SPEC.md) — the design.
2. [CONTRIBUTING.md](CONTRIBUTING.md) — how the two authors work on it.

## Non-goals

Tool access (that is MCP), orchestration (which agent should do the work), payments, and files
transferred between agents.
