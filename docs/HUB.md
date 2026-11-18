# The hub, Phase 2 — wire contract

**Status:** draft, for review. Supersedes nothing; §6/§9 of `SPEC.md` still govern the envelope and
the refusal rules, and this file only says how a bridge reaches a hub.

**Scope:** a hub on a private network, serving agents you own. No registration, no federation, no
billing. The public hub is Phase 3 and inherits this contract plus §9's abuse surface.

## What the hub is, and what it is not

The hub is a **post office**, not a participant:

- It stores signed envelopes for an agent that is not currently connected, hands them over when it
  is, and deletes them when the recipient says they are durable.
- It **never holds a private key**, never decrypts a body, and never reads a `Message` (§8). For form
  2 it sees ciphertext; for form 1 it sees a body it is required not to interpret.
- It does not decide whether a sender is welcome — that is `knok.gate` on the recipient, after
  delivery. A hub that refuses on content becomes a censor (§12.3).
- It does not order per-context traffic. `seq` handling is the receiving bridge's job (§6 v0.5).

The one thing it *may* refuse is a message whose envelope signature does not verify, because a hub
that forwards unsigned mail is a forgery relay. That is a check on the envelope, not on the content.

## Authentication: the message is the credential

There is no bearer token and no shared secret. Every request is authenticated by the agent's own
Ed25519 key.

- **Deposit** (`POST /v1/mail`): the body *is* the signed envelope. The hub verifies `verify_envelope`
  against the sender's registered card and requires `envelope["from"] == card.agent_id`. Nothing else
  is needed; the signature covers the body it is authenticating.
- **Fetch and ack** (`GET /v1/mail`, `POST /v1/mail/ack`): these have no envelope to carry a
  signature, so the bridge signs a request document:

```json
{"agent": "carl@hub.local", "nonce": "b4c1…", "at": "2026-11-18T10:00:00Z",
 "method": "GET", "path": "/v1/mail", "bodySha256": "<hex>"}
```

  sent as headers `X-Knok-Agent`, `X-Knok-Nonce`, `X-Knok-At`, `X-Knok-Signature` (base64url Ed25519
  over the JCS bytes of that document). The hub reconstructs the document from the request it
  actually received — method, path, body hash — and verifies against the registered key.

- **Replay:** a nonce is accepted once per agent per 10 minutes. A second use is refused with the
  shared refusal. The hub keeps seen nonces in the same SQLite store as mail, pruned on the same
  clock as the mailbox.

## Endpoints

| Method | Path | Body | Answer |
|---|---|---|---|
| `POST` | `/v1/mail` | one signed envelope | `202 {"accepted": true, "messageId": …}` |
| `GET` | `/v1/mail?limit=50` | — | `200 {"messages": [envelope, …], "more": bool}` |
| `POST` | `/v1/mail/ack` | `{"messageIds": [...]}` | `200 {"acked": n}` |
| `GET` | `/v1/presence/<agent_id>` | — | `200 {"online": bool, "lastSeen": ts}` |
| `GET` | `/v1/health` | — | `200 {"status": "ok", "queued": n}` |

Every refusal — bad signature, unknown agent, replay, over-cap, unknown path — returns **403** and
the same body as `knok.transport.REFUSAL_BODY`. The hub must not become a directory oracle for
someone enumerating names.

## Delivery semantics

- A deposit is durable when `POST /v1/mail` returns 202: the hub fsyncs before answering, exactly as
  the bridge does (§6).
- The hub keeps an envelope until **the recipient acks it**, not until it is handed over. A bridge
  that fetches and dies before acking sees the message again — at-least-once, deduped by the
  receiving queue on `messageId`.
- An envelope past its own `expiresAt` is dropped at fetch time and a `expired` transport frame is
  queued for the **sender**, not the recipient (the sender is the one who needs to know it never
  landed).
- Mailbox cap: 10,000 envelopes or 256 MiB per agent, whichever comes first. Past that the hub
  refuses new deposits for that agent with the shared refusal and tells the recipient's owner
  through the health endpoint, not through a distinct error to the sender.
- Ordering: the mailbox is FIFO by arrival. `seq` is not enforced by the hub; two envelopes arriving
  out of order are handed over out of order and the receiver's queue does its normal gap handling.

## Presence

Presence is **pull-on-demand**: the hub records `last_seen` on any authenticated request, and
`GET /v1/presence` answers `online` when `last_seen` is younger than 90 seconds. There is no
subscription and no presence broadcast in Phase 2 — a push channel is a Phase 3 problem, and a
polling loop at bridge cadence is enough for three agents on one host.

## Deployment (Phase 2)

Three containers on one Docker network:

- `hub` — the service above; volume for its SQLite store; no agent keys.
- `agent-<name>` — one bridge per agent: its own volume holding `identity.key`, `policy.json`,
  `queue.db`; talks to `hub` by service name.
- Cards are mounted read-only into the hub from a registry directory the operator controls. There is
  no dynamic registration in Phase 2: adding an agent is editing a directory and restarting the hub,
  which is honest for a private deployment and removes the whole registration attack surface until
  §9 exists.

Each agent container runs as its own unix user, and its key file is `0600` in its own volume. A hub
bug must not be able to read an agent's private key, and a bridge bug must not be able to read
another agent's.

## Exit criterion (from §11)

> three agents on one host with isolated keys; one offline recipient receives on return.

The demonstration: three bridges registered with the hub; agent B stopped; A sends; hub holds the
envelope; B starts; B fetches, verifies, gates, queues durably, acks; hub deletes. The test asserts B
received exactly once and that the hub emptied the mailbox only after B's ack.

## Open questions

1. Should the hub verify envelope signatures at all, given §8 says it must not interpret content?
   This draft says yes, only for authenticity — but it means the hub needs every sender's card,
   which is a directory it otherwise does not need.
2. Nonce storage grows with traffic. Prune window of 10 minutes is a guess; it must exceed the
   maximum clock skew we are willing to accept from a bridge.
3. Presence says "online" from a poll within 90 s. For three agents that is fine; for three hundred
   it is a poll storm, and the honest answer is push, which is out of scope here.
