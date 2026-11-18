# 0002 — The registry is a log of key records, not a dict

Date: 2026-11-18
Status: proposed
Authors: Carl
Addresses: #15 (encryption key binding), #23 (revocation)

## Decision

A key is described by a **record**, and the registry is a collection of records — not a mapping from
name to bytes.

```
{
  "agentId":     "carl@bridge.example",
  "keyType":     "ed25519" | "x25519",
  "publicKey":   "<base64url>",
  "fingerprint": "<derived from publicKey>",
  "notBefore":   "<ISO-8601>",
  "notAfter":    "<ISO-8601>",
  "revokedAt":   "<ISO-8601> | absent",
  "supersededBy": "<fingerprint> | absent",
  "reason":      "<free text, operator-owned>"
}
```

Verification asks a question about a key **at a time**: `status(fingerprint, at)` returns one of
`valid`, `not-yet-valid`, `expired`, `revoked`, `superseded`, `unknown`. A message is verified against
the status at its own `sentAt`, not at receipt — a key that was revoked this morning must not
retroactively invalidate a message signed yesterday, and must not validate one signed after the
revocation.

The card carries an `encryptionKeyId` naming the X25519 record. The record is separate from the card
so that rotating an encryption key does not require reissuing the card, and so that a revocation can
point at an object that outlives a single card issuance (this is #15's substance).

Records are published by the hub (Phase 3) and signed by the hub's key; a private deployment may hold
them in a file. The transport accepts either a `Registry` object or the legacy plain dict.

## Why the dict is not enough

The dict answers exactly one question — "is this key in the set?" — and the trust model needs four:

- **revoked at time T** — a stolen key used until someone noticed;
- **expired without revocation** — a key that should stop working at a date;
- **superseded** — a rotation where the old key verifies old messages and must not sign new ones;
- **unknown** — never registered, which today is indistinguishable from all of the above.

Treating "the registry says so" as the whole trust root means a key can never be withdrawn. That is
acceptable while the registry is a dict built in a test fixture. It is not acceptable the moment a
hub publishes one.

## Compatibility, and what a plain dict promises

`verify_card()` and the transport accept a dict for now. A dict means **every key in it is valid
forever**: no revocation, no expiry, no supersession. That is a statement of the test double, not of
the protocol — the transport docstring says so, and the hub must not claim revocation support while
it holds a dict.

The legacy form is kept because the alternative is a flag day that blocks the hub work on a registry
service; it is not kept because it is correct.

## Consequences

- A card is verifiable at any historical time, not only "now" — which is what makes an audit trail
  possible at all.
- Rotation is an ordinary record, not a protocol event.
- The registry grows. It is a log, so that is expected; entries are never deleted, only superseded or
  revoked, and pruning is a retention decision for the hub (30 days, matching dead letters, is the
  starting point).
- §4's "the signing key signs the encryption key" becomes literally true: the card names a record,
  and the record is a signed object. Until this lands, §4's sentence overstates what the code does.

## Alternatives considered

**Amend §4 to say the card signature is the binding** (issue #15's first option). *Rejected:* it makes
the sentence true and keeps rotation impossible without reissuing a card, which is the normal case for
an agent that outlives its card.

**Keep the dict and add a separate revocation list.** *Rejected:* two sources of truth that can
disagree, and every verifier has to consult both in the right order. The record carries its own
revocation.
