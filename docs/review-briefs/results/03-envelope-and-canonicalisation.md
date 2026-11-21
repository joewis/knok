# Review 03 — Envelope format, validation and signatures

## Signed bytes

For both envelope forms, the Ed25519 signature is over:

`canonical_bytes({ ...envelope fields except "signature" })`

The signed fields are therefore every accepted envelope field: `envelopeVersion`, `seq`, `from`, `to`, `sentAt`, `expiresAt`, `turn`, and exactly one of:
- Form 1: `message` (including `messageId`, `contextId`, role, parts and any accepted A2A Message fields).
- Form 2: clear `messageId` and the complete `sealed` object (including `hpke.enc`, `hpke.ciphertext`, and `recipientKeyId`).

Only `signature` is excluded. `sign()` builds the signed body by removing that key, then signs its canonical bytes; `verify_envelope()` reconstructs the same body. Reordering object keys does not change the canonical bytes. The existing key-order test checks verification after reversing the top-level keys; the canonicalisation test checks nested key order too.

## Findings

### F1 — `expiresAt` has no maximum lifetime

**Severity: Medium**  
**Location:** `src/knok/envelope.py:190-200`; protocol limit: `docs/SPEC.md:362`.

`validate()` requires `expiresAt > sentAt` and rejects an envelope once the current time reaches `expiresAt`. It does not require `expiresAt` to be no more than 30 days after `sentAt` (or otherwise cap its distance from the receiver's clock).

A sender with an otherwise valid signing key can submit a valid envelope with `sentAt` now and `expiresAt` years in the future. The queue uses that timestamp as the message expiry, and the `seen` retention is explicitly sized around the spec's 30-day maximum (`src/knok/queue.py:87`). The message can therefore remain deliverable and deduped well beyond the protocol's stated lifetime.

This is not a signature bypass: the sender signs the overlong lifetime itself. It is a validation gap against the protocol limit. Enforce the 30-day maximum at the receiving boundary, using a clearly defined reference instant, and test the exact boundary.

### F2 — Sender-controlled `sentAt` still controls key validity without a freshness bound

**Severity: High for a public hub; lower in a private, fully trusted deployment**  
**Location:** `src/knok/envelope.py:55-66, 190-200`; call sites: `src/knok/bridge.py:608-612`, `src/knok/transport.py:364-373`.

The timestamp parser accepts a syntactically parseable `sentAt`, but validation does not bound it against the receiver's clock. The bridge and transport use that sender-supplied instant when selecting the sender's registry/card key. A holder of a revoked, superseded, or expired key can therefore create a *new* message, backdate `sentAt) to a time when the key was valid, set a future `expiresAt`, sign it, and have it accepted. Future-dating is also not rejected, so a key whose validity begins in the future can be selected before that start time.

This is the issue already recorded as [#90](https://github.com/joewis/knok/issues/90), not a newly discovered replay flaw. The spec itself acknowledges the sender-asserted timestamp limitation and says a receiver that needs a current revocation bound must apply its own freshness window. The implementation does not currently apply that window. Decide and implement a maximum age and future-skew policy at the receiving bridge and `recv` boundary, or explicitly accept that revocation cannot stop a compromised key from minting new messages. Do not describe this as replay: message-id dedupe handles exact repeats, not newly minted backdated messages.

### F3 — `turn` accepts unknown fields and contradictory flags

**Severity: Low (protocol ambiguity; a concrete state inconsistency for the contradictory combination)**  
**Location:** `src/knok/envelope.py:202-205`; state effect: `src/knok/gate.py:111-124, 139-140`.

The validator checks only that `turn` is a dictionary and that `expectsReply` and `closesThread` are booleans. It does not reject additional keys. For example, a sender can sign and successfully verify:

```json
"turn": {
  "expectsReply": false,
  "closesThread": false,
  "forceClose": true
}
```

Knok ignores `forceClose`; another implementation could assign it meaning. The signature authenticates the extra field but does not make its interpretation interoperable. This is inconsistent with the strict unknown-field rejection applied to the envelope, sealed object, and A2A Message. Reject unknown `turn` keys unless the protocol defines an extension mechanism.

There is also no mutual-consistency check for `expectsReply=true` and `closesThread=true`. `Threads.note_sent()` increments the outstanding-reply counter and sets `closed=1`; `Threads.receipt()` then rejects a reply whenever the thread is closed. Thus a signed envelope can simultaneously record that a reply is owed and make that reply inadmissible. Either reject that combination or define its intended precedence explicitly.

### F4 — Message identifiers are only checked for non-emptiness, not the specified generation profile

**Severity: Medium (message loss / dedupe collision; sender key required)**  
**Location:** `src/knok/message.py:63-66`; sealed clear id: `src/knok/envelope.py:139-145`; dedupe key: `src/knok/queue.py:112-115`.

The spec requires `messageId` to contain at least 128 bits from a CSPRNG and to be unique across all senders (`docs/SPEC.md:235-237`). Validation only requires a non-empty string for the form-1 Message id and form-2 clear id. It accepts values such as `"x"`, sequential counters, or a constant reused for every message. `contextId` is likewise only checked as a non-empty string.

The queue's `seen` table has `message_id` as its sole primary key, so reuse of an id causes later messages with that id to be treated as duplicates, even if their sender or body differs. A sender can trivially make its own later messages disappear by reusing an id; predictable ids also make cross-sender collisions easier than the protocol's required random namespace intends.

A receiver cannot prove that a value was generated by a CSPRNG, but it can enforce a canonical identifier representation and minimum size, and it should scope dedupe to the protocol's stated uniqueness domain or reject collisions with a different sender/body rather than silently treating them as an ordinary retry. Add tests for a reused id from the same sender and a collision from a different sender.

## Canonicalisation and form handling — checks that passed

- **Numbers:** booleans are handled before integers; integers outside the IEEE-754 safe range are rejected; all floats (including `1.0`, exponent forms and negative zero represented as a float) are rejected. JSON `-0` parsed as integer zero canonicalises as `0`. `null` is retained as JSON `null`.
- **Unicode:** object keys are sorted by UTF-16 code units, as JCS requires. Strings are not NFC-normalised; NFC and NFD spellings remain distinct values and produce distinct bytes, which is correct for JCS. Control characters are escaped by the JSON encoder. Lone surrogate code points fail UTF-8 encoding and are converted to `CanonicalisationError`.
- **Duplicate keys:** a Python dictionary cannot represent duplicate object keys, so `canonical_bytes()` cannot detect them. Raw JSON duplicate-key rejection belongs at the JSON parsing boundary; this module's dictionary-level contract cannot establish it.
- **No observed canonical collisions:** for the supported Python value domain, object key order and insignificant whitespace do not affect the output; array order and actual string/code-point values do. No pair of distinct supported values was found that collapses to the same canonical bytes beyond JSON's own numeric equivalences (for example, lexical `-0` and `0` both parse to integer zero).
- **Unknown fields:** top-level envelope fields, `sealed`, `sealed.hpke`, and A2A Message/Part fields are rejected when unknown. The `turn` exception is F3.
- **Form 2:** the signature covers both the clear header and ciphertext. Editing the clear `messageId`, ciphertext, or any other field after signing breaks verification. A plaintext envelope cannot be relabelled as sealed (or vice versa) without changing signed bytes and failing verification. `unseal()` cross-checks the inner Message's `messageId` against the clear id and validates the opened form-1 envelope.
- **Decryption contract:** `unseal()` deliberately does not verify the sender signature; its caller must verify the sealed envelope first. The returned form-1 object retains the original signature, which is evidence over the sealed form and is not expected to verify again as a plaintext envelope. This contract is explicit in the module documentation. The current bridge path still leaves form 2 unhandled; the sealed receive flow is not yet live, consistent with decision 0003 and the open follow-on work.

## Time and identifier validation details

- `sentAt` may be arbitrarily old or in the future; see F2 and issue #90.
- `expiresAt` must be after `sentAt` and not yet expired, but has no 30-day upper bound; see F1.
- `_parse_time()` treats a timestamp without a timezone as UTC. That is deterministic in this implementation, but a timezone-less value is not an unambiguous absolute instant across implementations. Require an explicit `Z` or numeric offset if these timestamps drive key validity.
- `seq` is a non-negative safe-range integer. Per-context sequencing is enforced later by the queue, not by envelope validation; this is the correct layer for the stateful ordering check.
- `replyTo` is not an accepted Message field; strict A2A Message validation rejects it as unknown. `taskId` and `referenceTaskIds` are accepted with the types checked by `validate_message()`, but there is no cross-field task consistency check here.

## Malformed-input behaviour

For ordinary JSON-shaped inputs, the tested malformed cases (non-object envelope, missing/wrong fields, invalid base64, wrong signature encoding/length, tampered signature) are refused rather than raised. `verify_envelope()` catches canonicalisation errors and defensive exceptions during canonicalisation; `validate()` also catches the recursive-copy failure for a deeply nested Message.

The “never raises” contract is narrower than an arbitrary Python-object contract: `validate()` runs before the defensive `try` in `verify_envelope()`. Non-JSON Python objects (for example, dictionaries with mixed non-string keys, or a caller-supplied naive `now` datetime compared with an aware expiry) can still raise. Those values cannot arrive through a conforming JSON parser, but the public Python API should either document the JSON-shaped-input precondition or harden the outer validation boundary.

Tests were reviewed statically; they were **not run**. The existing tests cover key-order invariance, normal sign/verify, tampering, basic malformed fields, form-2 signature coverage, and message-id cross-checking. They do not cover the 30-day expiry boundary, stale/future `sentAt`, unknown `turn` fields, contradictory turn flags, low-entropy/reused ids, or timezone-less timestamps.
