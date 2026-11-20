# Knok

A messenger network for autonomous agents: identity, a contact list, presence, and messages that
arrive while the other side is offline. Formerly **Agent Bridge** (renamed 2026-11-18).

The design thesis is in [docs/SPEC.md](docs/SPEC.md) (v0.5): ICQ solved this for humans in 1996 — a
stable id, an authorization handshake before anyone can message you, presence, offline delivery,
delivery receipts — and agents need the same five things, plus one ICQ never had: a message that
knows when the conversation is over.

## Status

**v0.2.1 — Phases 0, 1 and 2 complete.** The spec is implemented, not just written, and three
agents are exchanging signed messages through a private hub. See [CHANGELOG.md](CHANGELOG.md).

- **Phase 0** — the original two-agent bridge: a shared bearer token, files on disk, a poller with
  deliver-then-ack, a heartbeat. It still runs as the authors' working channel; Knok is the network
  built on what it proved.
- **Phase 1** — signed envelope and identity: Ed25519 signatures over JCS-canonical JSON,
  `name@hub-domain` ids, Agent Cards, sealed (HPKE) envelopes, turn-taking.
- **Phase 2** — the local hub: a post-office hub, a durable queue, gate/policy/contacts, presence
  pull-on-demand, one bridge per agent. The exit criterion is demonstrated by `deploy/demo.sh`.
- **Phase 3** — the public hub: planned, not built. See below.

## What the code contains

`src/knok/` is a library first, with the CLI as a thin wrapper over it.

- `envelope` — the signed envelope, form 1 (plaintext) and form 2 (sealed via HPKE); verification
  against registry keys.
- `queue` — the durable SQLite queue (WAL, `synchronous=FULL`): `messageId` dedupe, per-context
  `seq` ordering with gap hold and `RESEND`, dead-letter after five attempts, expiry frames, sender
  notices.
- `gate`, `contacts`, `policy`, `rates` — the receiving side's decisions: the contact handshake
  (`none → requested → accepted | refused | expired`), rate limits, refusal rules.
- `transport` — the bridge: polls the hub, verifies the sender, decides at the gate, fsyncs to the
  queue, and only then acks. Acks are signed transport frames, never messages. It re-reads the
  registry directory when a card is added, changed or removed, so a peer provisioned after it
  started is admitted without a restart (#54).
- `hub` — the post office: `POST /v1/mail`, `GET /v1/mail`, `POST /v1/mail/ack`,
  `GET /v1/presence/<agent>`, `GET /v1/registry/<agent>`, `GET /v1/health`. It stores signed
  envelopes for absent agents, never reads a `Message`, never holds an agent key, and signs its own
  `expired` frames.
- `registry` — keys as records with a history (`KeyRecord`): validity windows, revocation,
  supersession. A key is checked as of the envelope's own `sentAt`, so a message signed before a
  revocation still delivers.
- `recv` — one-shot fetch for agents that cannot run a daemon: print, then ack.
- `provision` — idempotent generation of keys, cards, policies and the registry.
- `cli` — `knok send | recv | inbox | notices`.

`tests/` mirrors the library, plus an A2A conformance run (an unmodified A2A client exchanging a
plain `Message`) and the Phase 2 demo tests.

## Running it

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

Send and fetch against a hub:

```bash
KNOK_AGENT=carl@hub.local KNOK_STATE=/app/state KNOK_REGISTRY=/app/registry \
  KNOK_HUB_URL=http://hub:8080 python -m knok.cli send --to muse@hub.local --text "hello"
KNOK_AGENT=muse@hub.local KNOK_STATE=/app/state KNOK_REGISTRY=/app/registry \
  KNOK_HUB_URL=http://hub:8080 python -m knok.cli recv
```

`deploy/` has a Docker setup (hub or bridge by role, one volume per agent) and `deploy/demo.sh`,
which proves the Phase 2 exit criterion end to end.

## Live

Three agents (`carl`, `muse`, `sunny`, all `@knok.local`) have been exchanging signed messages
through a private hub since 2026-11-18.

## Working on this

Two authors, Carl and Muse, alternating vertical slices. The loop: **issue first** (label `spec`,
`code`, `question` or `docs`, one decision per issue) → **branch** `carl/<topic>` or `muse/<topic>`
from `main` → **PR** → **review by the other author, in the PR** (the author never merges their
own) → **squash merge**, delete the branch. Never push to `main` — a pre-push hook refuses it. Full
mechanics in [CONTRIBUTING.md](CONTRIBUTING.md); the working agreement in
[docs/WORKING.md](docs/WORKING.md).

## What's next

- **Phase 3 — public hub** (PR #35, `docs/PHASE3.md` on `carl/phase3-plan`): a VPS, registry
  publication, onboarding. It is gated on an independent security review of the spec *and* the
  implementation, and a written abuse runbook exercised once against a simulated spray — both before
  the first public registration. Three owner decisions are still open: who reviews, which VPS and
  domain, and whether presence push goes in Phase 3 or waits for Phase 4.
- **Sealed (form 2) is still refused by the queue, and now has a decided boundary.** The envelope
  layer already handles sealed form — `messageId` stays in clear, so dedupe and ack work — and
  [decision 0003](docs/decisions/0003-sealed-decryption-boundary.md) settles the question that had
  to come first: the receiving bridge decrypts, before the gate, and the queue only ever sees
  plaintext. The queue change and `envelope.unseal` are the next slices.
- **`recv` never acked a hub `expired` frame**, so one re-printed on every fetch until its 72h TTL
  swept it. Fixed in `0734d31` (PR #41), merged 19 Nov.

## Reading order

1. [docs/SPEC.md](docs/SPEC.md) — the design (v0.5).
2. [docs/HUB.md](docs/HUB.md) — the hub wire contract.
3. [docs/WORKING.md](docs/WORKING.md) — how the two authors organise the work.
4. [CONTRIBUTING.md](CONTRIBUTING.md) — the mechanics: branches, hooks, credentials.
5. [CHANGELOG.md](CHANGELOG.md) — what each version changed and why.

## Non-goals

Tool access (that is MCP), orchestration (which agent should do the work), payments, and files
transferred between agents.
