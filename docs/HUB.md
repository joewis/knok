# The hub, Phase 2 — wire contract

**Status:** draft v0.2 for review. §6/§9 of `SPEC.md` still govern the envelope and the refusal rules;
this file says only how a bridge reaches a hub.

**Scope:** a hub on a private network, serving agents you own. No registration, no federation, no
billing. The public hub is Phase 3 and inherits this contract plus §9's abuse surface.

## What the hub is, and what it is not

The hub is a **post office**, not a participant:

- It stores signed envelopes for an agent that is not currently connected, hands them over when it
  is, and deletes them when the recipient says they are handled.
- It **never holds an agent's private key**, never decrypts a body, and never reads a `Message`
  (§8). For form 2 it sees ciphertext; for form 1 it sees a body it is required not to interpret.
- It **may** inspect envelope *headers* — `from`, `to`, `messageId`, `expiresAt`, `seq` — because
  routing, dedupe and expiry are header work. The rule is **headers yes, `Message` body no**.
- It does not decide whether a sender is welcome; that is `knok.gate` on the recipient. A hub that
  refuses on content becomes a censor (§12.3).
- It does not order per-context traffic. `seq` handling is the receiving bridge's job (§6 v0.5).

The hub has **its own identity**: an Ed25519 keypair and a card in the same registry as the agents.
It needs one because it emits transport frames (`expired`, `dead`) that a bridge must be able to
distinguish from a forged envelope dropped into its mailbox by any other agent.

## Authentication: the message is the credential

No bearer token, no shared secret. Every request is authenticated by an Ed25519 signature.

**Deposit** (`POST /v1/mail`): the body *is* the signed envelope. The hub verifies `verify_envelope`
against the sender's registered card and requires `envelope["from"] == card.agent_id`.

**Fetch and ack** (`GET /v1/mail`, `POST /v1/mail/ack`): no envelope to carry a signature, so the
bridge signs a request document:

```json
{"agent": "carl@hub.local", "nonce": "b4c1…", "at": "2026-11-18T10:00:00Z",
 "method": "GET", "target": "/v1/mail?cursor=…&limit=50", "bodySha256": "<hex>"}
```

sent in headers `X-Knok-Agent`, `X-Knok-Nonce`, `X-Knok-At`, `X-Knok-Signature` (base64url Ed25519
over the JCS bytes of that document).

- **The signed `target` is the exact request-target, query string included and sorted.** A hub that
  rebuilt the document from a normalised path would leave `limit` and `cursor` unsigned, and a
  middlebox could raise the limit or move the cursor.
- **`at` must be within 5 minutes of the hub's clock**, in either direction. Outside that the request
  is refused, signed or not.
- **Nonces are stored durably and accepted once per agent within 10 minutes** — twice the skew
  window, so a request cannot be replayed after the skew check has stopped being able to reject it.
  The nonce table survives restart and is pruned on the same clock.
- **`X-Knok-Agent` must equal the `agent` inside the signed document.** A mismatch is a refusal, not
  something to reconcile.

## Endpoints

| Method | Path | Body | Answer |
|---|---|---|---|
| `POST` | `/v1/mail` | one signed envelope | `202 {"accepted": true, "messageId": …}` |
| `GET` | `/v1/mail?limit=50&cursor=…` | — | `200 {"messages": [...], "next": "…" \| null}` |
| `POST` | `/v1/mail/ack` | `{"messageIds": [...]}` | `200 {"acked": n}` |
| `GET` | `/v1/presence/<agent_id>` | — | `200 {"online": bool, "lastSeen": ts}` |
| `GET` | `/v1/registry/<agent_id>` | — | `200 {"card": <flattened JWS>}`, `404` when never registered |
| `GET` | `/v1/health` | — | `200` (authenticated; caller's own mailbox only) |

**The registry lookup serves one card, and only while it still verifies.** It is authenticated like
`presence` and `health` — a signed request from a registered agent — so it is not an open directory:
an agent outside the registry cannot ask, and cannot therefore learn who is in it. It answers
`404` only for an id the hub has never registered, which is the one case in which a sender refusing
locally is honest; the hub answers with the pinned document only while it still verifies against the
hub's own registry, so a revoked, expired or superseded key is not handed out — *registered* is not
the same as *valid now*. A bridge needs this because its copy of the registry is a snapshot: a peer
that registered after the tarball was issued is otherwise unreachable until an operator re-issues it.
The client check is not optional and is not the hub's word: the returned card must verify under its
own signature and must name the id that was asked for.

**Acks are scoped to the caller's own mailbox.** An ack deletes only ids present in the caller's box;
foreign ids are ignored rather than refused, `acked` counts what was actually deleted, and a
duplicate ack is idempotent (second call returns `0` with `200`). A hub that deletes on any presented
id lets one agent delete another's mail.

**Ack means *handled*, not *delivered*.** The bridge acks a message once it has either made it
durable in its queue or refused it at the gate and recorded that refusal. Without this a
gate-refused message is re-fetched forever — a poison loop where a 50-message page never advances.
`next` is the cursor for the following page, and a page whose messages were all gate-refused still
advances it.

## Delivery semantics

- **Durability before ack, both directions.** A deposit is durable when `POST /v1/mail` returns 202:
  the hub fsyncs before answering. A handover is durable when the bridge has fsynced its own queue
  **and** the row in its delivery ledger saying what it decided about the item; **it MUST NOT ack
  before both fsyncs return.** Otherwise the hub deletes mail the bridge has not written down, and
  at-least-once becomes at-most-once. A decision that destroys mail — `duplicate`, `dropped` — is
  exactly the case where the record is the only remaining evidence, so a bridge that cannot write
  the ledger acks nothing and lets the page be re-offered.
- **Deduped on both sides.** The bridge's `seen` table is durable (it lives in `queue.db`), and the
  hub keeps its own `(recipient, messageId)` index so a duplicate deposit does not create a second
  copy. A duplicate deposit returns `202` with the same `messageId` and stores nothing.
- **Mail is deleted only on ack.** A bridge that fetches and dies before acking sees the same
  messages again; the receiving queue drops the repeats it has already seen.
- **Expiry is swept, not lazy.** A background sweep runs at least every 60 seconds, dropping
  envelopes past `expiresAt` and queuing a signed `expired` frame for the **sender**. An envelope
  already expired at deposit is accepted (`202`), dropped immediately, and produces the same frame —
  accepting it and silently discarding it would make the sender's ack a lie.
- **The lifetime cap bounds the envelope, not our storage.** `expiresAt` may be at most 30 days after
  the envelope's own `sentAt`, and `sentAt` is asserted by the sender (§4), so the cap is a statement
  about the envelope the sender signed, not about how long this hub will hold a row for it. A sender
  that backdates can still set `expiresAt` past the horizon the queue's retention is sized around;
  that residual is #90, and closing it needs a clock the hub trusts rather than another check on a
  field the sender writes. Reading this cap as a retention guarantee would be wrong in exactly that
  case.
- **Frames are hub-signed and have their own retention.** An `expired` or `dead` frame sits in the
  sender's mailbox under the same 72-hour TTL as mail and counts against the cap; if it cannot be
  queued (sender's box at cap) the hub logs it and the health endpoint reports the drop for that
  owner. Nothing disappears silently.
- **Ordering:** the mailbox is FIFO by arrival. `seq` is not enforced by the hub; two envelopes
  arriving out of order are handed over out of order and the receiver's queue does its normal gap
  handling.

## Refusals, and the one place they differ

Every authentication or identity failure returns **403** with the same body as
`knok.transport.REFUSAL_BODY`: no signature, bad signature, unknown agent, replay, bad skew, unknown
path, `from`/`to` inconsistency.

**Over-capacity is the exception, and only on a private hub.** When a mailbox is at cap the hub
answers **429** with a retry hint, because the honest distinction is *retryable* versus *permanent*,
and a sender that cannot tell them apart either retries a bad signature forever or gives up on a full
box. This is safe only where every agent is already known to every other — a private deployment,
which is what Phase 2 is. On a public hub the answer must fold back into the uniform 403, and that
constraint is written here so Phase 3 cannot quietly inherit an existence oracle.

Permanent deposit refusals (**403**): unknown recipient; more than one recipient in `to` (fan-out is
not in v1 — one ack cannot acknowledge a message delivered to three boxes); envelope over 64 KiB
(§9's per-message cap); `messageId` already used by that sender with a different body.

**An acked id stays spent until its envelope expires (#99).** The mail row is deleted on ack, so
without a tombstone a replay of the same still-valid envelope would be stored again and handed over
twice. The tombstone carries the payload hash, so reusing the id for a different body is still
refused, and it is pruned once the envelope could no longer verify. A retry is unaffected: SPEC §8
mints a new messageId carrying `retryOf`, which is a different id and therefore a different message.

**The tombstone is consulted before the cap, and that ordering is deliberate.** In `deposit` the
tombstone lookup runs ahead of the `_at_cap` check, so a replay of an already-acked id against a
*full* mailbox answers `duplicate` (`202`) rather than 429. The sender learns the truth about a
message it already sent, and whether the box is full has no bearing on that answer. It is still an
existence-shaped difference — the same full mailbox answers differently for a fresh id and a spent
one — so it is accepted only on the ground the 429 above already rests on: a private hub where every
agent knows every other. On a public hub it folds back into the uniform 403 with the rest.

Mailbox cap: 10,000 envelopes or 256 MiB per agent, whichever comes first.

## Presence

Presence is **pull-on-demand**. `last_seen` is written only on a request that authenticated, and
`GET /v1/presence/<agent>` answers `online` when it is younger than 90 seconds.

- The bridge polls mail every 2 seconds with ±20 % jitter; the same tick keeps presence fresh, so
  presence costs no extra request.
- 90 seconds is 45 poll intervals: a single slow poll cannot flip an agent offline.
- **The supported ceiling for Phase 2 is 10 agents on one hub**, where the poll cost is a few SQLite
  writes per second. Beyond that the honest answer is long-poll or push — a Phase 3 change, not
  something to discover by scaling a polling loop.

## Contact policy on a private hub

§7's handshake exists so two agents who do not know each other can establish consent. On a private
hub the operator has already done that: the registry is a short list of agents the operator says may
talk, published to everyone. Provisioning therefore pre-approves the listed peers in each agent's
allow-list, which is the gate's pre-approval path rather than a bypass — an agent *outside* the
registry never gets a card, so it can never reach the gate at all.

This is a deliberate Phase 2 decision, not a general rule. On a public hub the registry is not a
statement of consent, the handshake is the only consent that exists, and `knok-provision
--no-preapprove` is the correct setting. The distinction is a flag because it is a policy choice,
and a policy choice baked into a default becomes a vulnerability on the next deployment.

## Transport security

Signatures prove who sent a message; they do not hide a form-1 body from the network. Any deployment
where bridge and hub are not on the same loopback or a single trusted Docker network **must** use TLS
with the hub presenting a certificate the bridges pin by fingerprint. Phase 2 runs on one Docker
network with the hub port bound to `127.0.0.1`, which is the only reason plain HTTP is acceptable
there — and that reason is written down rather than assumed.

## Deployment (Phase 2)

- `hub` — the service above; a volume for its store and its own key; no agent keys. Port published to
  `127.0.0.1` only.
- `agent-<name>` — one bridge per agent: its own volume holding `identity.key`, `policy.json`,
  `queue.db`; talks to `hub` by service name.
- Cards, including the hub's, are mounted read-only from an operator-controlled registry directory.
  There is no dynamic registration in Phase 2: adding an agent is editing a directory and restarting
  the hub. That removes §9's registration surface until the public hub exists, and it is why card
  distribution, rotation and revocation are an open question rather than designed here.
  **The bridges do not have to be part of that restart.** A bridge re-reads the directory when a
  card is added, changed or removed, and swaps the pinned set in one assignment between messages —
  so a peer provisioned mid-run is admitted, and a deleted card stops being trusted, without
  bouncing a container. Two cases are refused rather than swapped: a directory that yields no cards
  (a provisioning step caught mid-rewrite is not "trust nobody"), and one that no longer holds the
  bridge's own card (a misconfigured bridge is not a decommission).
- Each agent runs in its own container with its own volume and a `0600` key. A hub bug must not reach
  an agent's private key; a bridge bug must not reach another agent's.

## Exit criterion (from §11)

> three agents on one host with isolated keys; one offline recipient receives on return.

Demonstration: three bridges registered; B stopped; A sends; the hub holds the envelope; B starts;
B fetches, verifies, gates, fsyncs, acks; the hub deletes. The test asserts B received exactly once,
that the hub emptied the box only after B's ack, and that killing B between fetch and ack redelivers
to the restarted B with no duplicate reaching the application.

## Open questions

1. **Card distribution and rotation.** Where do hub and agent cards live, how does a bridge learn
   about a rotation without a restart, and what revokes one? (#23 is the same question for the
   identity layer.) Phase 2's answer is "a directory and a restart", which is not an answer for
   Phase 3.
2. **Nonce store growth.** Ten minutes at ten agents is small; at a public hub it is a table with
   every request in it. The pruning rule and the storage bound need a number before Phase 3.
3. **What the 10-agent ceiling really is.** The claim above is an estimate, not a measurement — the
   poll loop should be benchmarked before the number is treated as a limit.

4. **Deposit is authenticated by the envelope alone.** That is deliberate on a private hub: the
   envelope signature is checked against the registry before anything is stored, and a replay is
   deduped by `(recipient, sender, messageId)`. What it does not give is a nonce and a skew bound on
   the deposit path, so a public hub must sign deposits like every other request and rate-limit them
   per caller. Written down here so Phase 3 cannot inherit the cheaper form by accident.
