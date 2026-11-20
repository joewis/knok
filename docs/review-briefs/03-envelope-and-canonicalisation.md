# Review brief 3 — Envelope format, validation and signatures

You are reviewing the object that everything else trusts: what an envelope claims, what the signature
actually covers, and whether a sender can produce a valid signature over something the receiver did
not intend to accept. Report findings, not a summary.

## Scope — read only these

- `src/knok/envelope.py` — `validate`, `verify_envelope`, `sign`, `sent_at`, `seal`, `unseal`
- `src/knok/canonical.py` — the canonical encoding the signature covers
- `src/knok/message.py` — the body object
- `tests/test_envelope.py`, `tests/test_canonical.py`, `tests/test_sealed_envelope.py`

## Context

- `docs/SPEC.md` §6 (envelope, forms, thread fields)
- `docs/decisions/0003-sealed-decryption-boundary.md`

## Deliberately outside this brief

HPKE internals (brief 5) — here, treat `seal`/`unseal` as a function whose contract you check, not
whose cryptography you review. Transport and nonces (brief 1).

## Questions

1. **What is signed.** Enumerate the fields included and excluded from the signature input. Show
   that two envelopes with the same meaning but different key insertion order produce the same bytes.
2. **Canonicalisation.** How are integers, floats, negative zero, exponents, unicode (NFC vs NFD),
   control characters, duplicate keys and `null` encoded? Is there any pair of distinct envelopes
   that canonicalise to the same signed bytes? Is there any value that raises instead of refusing?
3. **Unknown fields.** Does validation reject them? Could a sender put meaning in a field this
   implementation ignores but another would honour — and would the signature still verify there?
4. **Forms.** In form 2, which fields stay in clear and which are inside `sealed`? Does the signature
   cover both? Can a sealed envelope be relabelled as plaintext, or a plaintext body relabelled as
   sealed, without breaking verification? What does the receiver do with form 2 today?
5. **Time fields.** What do `sentAt` and `expiresAt` guarantee at validation? What is *not* checked —
   future `sentAt`, very old `sentAt`, an `expiresAt` years away? Cross-reference issue #90.
6. **Identifiers.** Are `messageId`, `contextId`, `seq` and `replyTo` (if present) validated for type,
   format and mutual consistency, or trusted? What happens on a mismatch between `seq` and context?
7. **Turn flags.** What do `expectsReply` and `closesThread` permit? Can a sender set a combination
   that makes the receiver's thread state do something it would not otherwise do?
8. **Malformed input.** For each of: not an object, missing field, wrong type, bad base64, signature
   of the wrong length, oversized field — does the receiver refuse uniformly, raise, or crash? Name
   the exception types that escape.

## Report

Begin with a precise statement of the signed bytes (field list and encoding), because every finding
below depends on it. Then `F1`, `F2`, … with `file:line`, the input that produces a valid signature
over something unintended, and the consequence. A finding that requires the attacker to hold a valid
key is still a finding — say whose key suffices.
