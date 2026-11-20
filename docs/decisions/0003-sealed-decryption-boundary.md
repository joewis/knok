# 0003 — A sealed message is decrypted in the receiving bridge

Date: 2026-11-20
Status: proposed — owner decision made; Muse confirms the adapter side
Authors: Carl
Addresses: #70
Blocks: queue support for form 2, Phase 3's encrypted-messaging claim
Relates to: 0002 (a key is a record; the X25519 encryption record is separate from the card)

## Decision

**The receiving bridge decrypts**, at admission: after the envelope's signature and the sender's
card have been verified, and **before** the gate runs. The queue is handed the decrypted form 1
envelope and stores plaintext. The bridge does not retain the ciphertext.

The clear header does not change. It stays exactly what SPEC §6 already defines — `messageId`,
`seq`, `from`, `to`, `sentAt`, `expiresAt`, `turn`, `signature` — and `contextId` stays inside
`sealed`. Nothing has to move into the clear to make this work, which is the main reason to prefer
it.

Consequence for the trusted computing base, said plainly: **the bridge process, its host, and
whoever can read its key material are inside it.** The agent adapter is outside it — it never holds
a decryption key and never sees ciphertext. That last clause holds for the bridge/queue path, where
the adapter receives what the queue holds; `recv` is a separate path, addressed below.

## Why

1. **The spec already decided the ordering half.** SPEC §6: "Ordering sealed traffic happens after
   decryption, at the receiving bridge. `contextId` is inside the sealed body, so nothing before
   decryption can say which stream a `seq` belongs to. The hub therefore stores and forwards opaque
   blobs … A hub asked to order sealed traffic would have to read it." The queue's refusal is
   consistent with that sentence; what was actually undecided was *which process on the receiving
   side* holds the key. It is the bridge, because the bridge is where the spec put the ordering.
2. **The gate cannot run without the plaintext, and the gate is not optional.** Policy, contacts,
   rate limits and thread counters read the decrypted message: `contextId` for the thread rule,
   `metadata` for the refusal-notice path (`NOTICE_KEY`), and `parts` for any policy that will one
   day look inside. Decrypting in the agent would either move the gate into every adapter — policy
   duplicated per implementation, against the one-implementation rule — or leave the bridge gating
   on clear headers alone, losing the thread rule and the notice path.
3. **The bridge is already in the TCB for authenticity.** It holds the identity's Ed25519 signing
   key and signs acks with it. A host that can read that key can already speak as the agent.
   Adding the X25519 decryption key widens what an attacker who already owns the host can read; it
   does not create a new class of attacker. Claiming a stronger boundary than that would be
   security theatre, and a compromised bridge would go on signing perfectly valid messages while
   the design claimed to protect their contents.

## What it costs

- **The hub stays blind**, which is the property being bought: it routes on `from`, `to`, `seq` and
  `messageId`, and never learns `contextId`, the body, or which messages belong to one conversation.
- **Mail at rest is plaintext.** `queue.db` holds decrypted envelopes, so a backup of it is a copy
  of the mail, and a dead-lettered sealed message is metadata only (SPEC §6) only because the
  ciphertext is discarded at admission. Encrypting the queue at rest is a deployment decision; it
  does not become a protocol feature by being wished for here.
- **HPKE's forward secrecy is a wire property.** A key compromised later does not open ciphertext
  the bridge already decrypted and dropped — but it does open everything a host-level attacker can
  read live. Two different claims; only the first is being made.
- **Key delivery becomes a bridge concern.** The X25519 private key must reach the bridge process
  with the same care as the signing key — one operator store, injected as a file or environment
  credential, never in a config file. 0002 already names the record (`encryptionKeyId`) and answers
  revocation (`status(fingerprint, at)`); this decision only says where the private half is used.

## One spec sentence this changes, and how to keep it

SPEC §6 says: *"Dead letters are retained 30 days, and are never encrypted differently from the
message they came from — to anyone but the key holder, a sealed dead letter is metadata only."*

Under this decision the live queue holds plaintext, so a dead-lettered message would be plaintext at
rest for 30 days — which makes that sentence false for sealed mail. The resolution is narrow: the
dead-letter store keeps the envelope **as it was received** (ciphertext, for a sealed message) while
the live queue keeps the decrypted form. That keeps §6's claim true, and costs one extra field on
the dead-letter row — the row keeps the decrypted form for owner inspection alongside the envelope
as received, so the owner can still read what died. It does not by itself settle the re-offer: §6's
re-offer mints a new `messageId` (the old one is in `seen` and would be dropped), so sending the
original bytes unchanged is not a re-offer. The follow-on slice must define the sealed re-offer
shape — re-seal the plaintext with a new id, or exempt it — rather than assuming the stored bytes
are the answer.

## recv is out of scope for sealed mail

`knok recv` fetches straight from the hub and prints each envelope verbatim, so it bypasses the
bridge — and with it this decision's decrypt step. A sealed envelope fetched via recv reaches the
adapter as ciphertext, which the adapter cannot read and must not be asked to. Sealed mail is
therefore bridge-only in Phase 3: an agent that needs it runs a bridge.

recv's own sealed behaviour is now settled in code rather than left to the follow-on: since #77
(`2b03de7`) it prints nothing for an envelope with no `message`, writes one line to stderr, and
**does not ack it**, so the envelope stays at the hub for a bridge to fetch. Refusing would have
hidden a sealed message as if it were a policy decision, and acking would have deleted mail recv
cannot read — the two wrong answers were the ones available.

No sealed mail exists today: the hub refuses form 2 at deposit (403), and on this branch
`bridge._handle` returns `unhandled` for an envelope with no form 1 message rather than raising —
it used to raise at the notice check, and the guard precedes it now. The unseal slice still has to
land before either the hub's deposit path or the queue can carry a sealed message.

## Rejected alternatives

**Agent decrypts, bridge stores ciphertext.** Buys: a compromised bridge host reads only ciphertext.
Costs three things, each of them load-bearing:

- `contextId` must move into the clear header so the queue can order anything — which hands the
  *hub* thread grouping it does not have today, a leak of exactly the metadata `sealed` exists to
  protect;
- the gate moves into every adapter, or the thread rule and the notice path are dropped;
- the stream key in clear becomes a stable correlator for a hub watching `RESEND`s.

Rejected for Phase 3. If it is revisited, those three are the price of the change, not details to
be negotiated later.

**Hub decrypts.** Rejected by §8 (the hub is untrusted for confidentiality). Listed only to close it.

## Follow-on work this unblocks — deliberately not in this record's PR

1. `envelope.unseal(envelope, private_key)` returning the form 1 envelope, under the same JCS and
   signature rules; a test that a tampered ciphertext is a refusal, never an exception.
2. `transport.deliver` and `bridge._handle` become verify → unseal → gate → queue, with the sealed
   body's `messageId` cross-checked against the clear one (a body naming a different id is
   malformed, not "the id from inside").
3. Removing the queue's form 2 refusal (`queue.py`, the `"message" not in env` branch) once it is
   only ever handed plaintext. The queue should never learn that a message was sealed — that is what
   this boundary buys, and it is what keeps #69's transaction unchanged for sealed mail.
4. An undecryptable sealed message (rotated key, corrupt ciphertext) is a **refusal**,
   indistinguishable from any other, and the sender's copy is retried at the hub until TTL. Whether
   that deserves a metadata-only dead-letter record belongs to the abuse runbook.
5. The hub's deposit path, which reads `envelope["message"]` today and refuses form 2. It must
   land before sealed mail can travel at all. recv's half is decided (#77): sealed mail is left
   unacked at the hub, never printed and never deleted.
6. The sealed dead-letter re-offer shape (re-seal with a new id, or exempt it), and confirming the
   dead-letter row keeps the decrypted form for owner inspection alongside the as-received envelope.

## Status

Accepted, 2026-11-20. Muse confirmed the adapter side by reviewing this record against the code:
adapters need no keys and no "plaintext before the gate" hook on the bridge path, because the
adapter receives what the queue already holds in plaintext. Item 3 (removing the queue's form 2
refusal) is the next slice; items 1, 2, 4 and 6 remain unbuilt, and item 5 is the hub's half only.

The boundary as accepted has one known edge, stated here rather than discovered later: a sealed
message fetched by `recv` is invisible to that agent until a bridge exists to unseal it. That is
the cost of keeping the key in one process, and it is the right cost for Phase 3.
