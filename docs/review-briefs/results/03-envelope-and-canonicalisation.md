# Review 03 — Envelope format, validation and signatures

**Commit reviewed:** 828c9791da92704ad0c7d71dac26f4d3693aa6f3

## Signed bytes

For both envelope forms, the Ed25519 signature is over (`src/knok/envelope.py:220-222`, `sign`; `src/knok/envelope.py:234-236`, `verify_envelope`):

`canonical_bytes({ ...envelope fields except "signature" })` (`src/knok/canonical.py:71-88`, `canonical_bytes`)

The signed fields are therefore every accepted envelope field: `envelopeVersion`, `seq`, `from`, `to`, `sentAt`, `expiresAt`, `turn`, and exactly one of:
- Form 1: `message` (including `messageId`, `contextId`, role, parts and any accepted A2A Message fields).
- Form 2: clear `messageId` and the complete `sealed` object (including `hpke.enc`, `hpke.ciphertext`, and `recipientKeyId`).

Only `signature` is excluded (`src/knok/envelope.py:51`, `OPTIONAL`). `sign()` builds the signed body by removing that key, then signs its canonical bytes (`src/knok/envelope.py:209-223`, `sign`); `verify_envelope()` reconstructs the same body (`src/knok/envelope.py:226-243`, `verify_envelope`). Reordering object keys does not change the canonical bytes (`src/knok/canonical.py:57-68`, `_utf16_key`). The existing key-order test checks verification after reversing the top-level keys (`tests/test_envelope.py:145-148`, `test_key_order_does_not_break_verification`); the canonicalisation test checks nested key order too (`tests/test_canonical.py:7-10`, `test_key_order_does_not_change_bytes`).

## Findings

### F1 — `expiresAt` has no maximum lifetime

**Severity: Medium**  
**Location:** `src/knok/envelope.py:190-200` (`validate`); protocol limit: `docs/SPEC.md:362`.

`validate()` requires `expiresAt > sentAt` and rejects an envelope once the current time reaches `expiresAt` (`src/knok/envelope.py:196-200`, `validate`). It does not require `expiresAt` to be no more than 30 days after `sentAt` (or otherwise cap its distance from the receiver's clock) (`src/knok/envelope.py:190-200`, `validate`).

A sender with an otherwise valid signing key can submit a valid envelope with `sentAt` now and `expiresAt` years in the future. The queue uses that timestamp as the message expiry (`src/knok/queue.py:545`, `Queue.put`), and the `seen` retention is explicitly sized around the spec's 30-day maximum (`src/knok/queue.py:87-89`, `SEEN_RETENTION`). The message can therefore remain deliverable and deduped well beyond the protocol's stated lifetime.

This is not a signature bypass: the sender signs the overlong lifetime itself (`src/knok/envelope.py:220-222`, `sign`). It is a validation gap against the protocol limit. Enforce the 30-day maximum at the receiving boundary, using a clearly defined reference instant, and test the exact boundary.

### F2 — Sender-controlled `sentAt` still controls key validity without a freshness bound

**Severity: High for a public hub; lower in a private, fully trusted deployment**  
**Location:** `src/knok/envelope.py:55-66, 190-200` (`_parse_time`; `validate`); call sites: `src/knok/bridge.py:608-612` (`Bridge._handle`), `src/knok/transport.py:364-373` (`Bridge.deliver`).

The timestamp parser accepts a syntactically parseable `sentAt` (`src/knok/envelope.py:55-63`, `_parse_time`), but validation does not bound it against the receiver's clock (`src/knok/envelope.py:190-192`, `validate`). The bridge and transport use that sender-supplied instant when selecting the sender's registry/card key (`src/knok/bridge.py:608`, `Bridge._handle`; `src/knok/transport.py:363-365`, `Bridge.deliver`). A holder of a revoked, superseded, or expired key can therefore create a *new* message, backdate `sentAt) to a time when the key was valid, set a future `expiresAt`, sign it, and have it accepted. Future-dating is also not rejected (`src/knok/envelope.py:190-200`, `validate`), so a key whose validity begins in the future can be selected before that start time.

This is the issue already recorded as [#90](https://github.com/joewis/knok/issues/90), not a newly discovered replay flaw. The spec itself acknowledges the sender-asserted timestamp limitation and says a receiver that needs a current revocation bound must apply its own freshness window (`docs/SPEC.md:113-119`; `src/knok/envelope.py:113-121`, `sent_at`). The implementation does not currently apply that window (`src/knok/envelope.py:190-200`, `validate`). Decide and implement a maximum age and future-skew policy at the receiving bridge and `recv` boundary, or explicitly accept that revocation cannot stop a compromised key from minting new messages. Do not describe this as replay: message-id dedupe handles exact repeats, not newly minted backdated messages.

### F3 — `turn` accepts unknown fields and contradictory flags

**Severity: Low (protocol ambiguity; a concrete state inconsistency for the contradictory combination)**  
**Location:** `src/knok/envelope.py:202-205` (`validate`); state effect: `src/knok/gate.py:111-124, 139-140` (`Threads.note_sent`, `src/knok/gate.py:111-123`; `Threads.receipt`, `src/knok/gate.py:139-142`).

The validator checks only that `turn` is a dictionary and that `expectsReply` and `closesThread` are booleans (`src/knok/envelope.py:203-205`, `validate`). It does not reject additional keys (`src/knok/envelope.py:202-205`, `validate`). For example, a sender can sign and successfully verify:

```json
"turn": {
  "expectsReply": false,
  "closesThread": false,
  "forceClose": true
}
```

Knok ignores `forceClose` (`src/knok/envelope.py:202-205`, `validate`); another implementation could assign it meaning. The signature authenticates the extra field but does not make its interpretation interoperable. This is inconsistent with the strict unknown-field rejection applied to the envelope, sealed object, and A2A Message (`src/knok/envelope.py:128-130`, `validate`; `src/knok/envelope.py:84-89`, `_validate_sealed`; `src/knok/message.py:56-58`, `validate_message`). Reject unknown `turn` keys unless the protocol defines an extension mechanism.

There is also no mutual-consistency check for `expectsReply=true` and `closesThread=true` (`src/knok/envelope.py:202-205`, `validate`). `Threads.note_sent()` increments the outstanding-reply counter and sets `closed=1` (`src/knok/gate.py:111-123`, `Threads.note_sent`); `Threads.receipt()` then rejects a reply whenever the thread is closed (`src/knok/gate.py:139-142`, `Threads.receipt`). Thus a signed envelope can simultaneously record that a reply is owed and make that reply inadmissible. Either reject that combination or define its intended precedence explicitly.

### F4 — Message identifiers are only checked for non-emptiness, not the specified generation profile

**Severity: Medium (message loss / dedupe collision; sender key required)**  
**Location:** `src/knok/message.py:63-66` (`validate_message`); sealed clear id: `src/knok/envelope.py:139-145` (`validate`); dedupe key: `src/knok/queue.py:112-115` (`seen`; `src/knok/queue.py:509-512`, `Queue.put`).

The spec requires `messageId` to contain at least 128 bits from a CSPRNG and to be unique across all senders (`docs/SPEC.md:235-237`). Validation only requires a non-empty string for the form-1 Message id and form-2 clear id (`src/knok/message.py:63-66`, `validate_message`; `src/knok/envelope.py:143-145`, `validate`). It accepts values such as `"x"`, sequential counters, or a constant reused for every message. `contextId` is likewise only checked as a non-empty string (`src/knok/message.py:63-66`, `validate_message`).

The queue's `seen` table has `message_id` as its sole primary key, so reuse of an id causes later messages with that id to be treated as duplicates, even if their sender or body differs (`src/knok/queue.py:112-116`; `src/knok/queue.py:509-512`, `Queue.put`). A sender can trivially make its own later messages disappear by reusing an id; predictable ids also make cross-sender collisions easier than the protocol's required random namespace intends.

A receiver cannot prove that a value was generated by a CSPRNG, but it can enforce a canonical identifier representation and minimum size, and it should scope dedupe to the protocol's stated uniqueness domain or reject collisions with a different sender/body rather than silently treating them as an ordinary retry. Add tests for a reused id from the same sender and a collision from a different sender.

## Canonicalisation and form handling — checks that passed

- **Numbers:** booleans are handled before integers; integers outside the IEEE-754 safe range are rejected; all floats (including `1.0`, exponent forms and negative zero represented as a float) are rejected (`src/knok/canonical.py:36-43`, `_check`). JSON `-0` parsed as integer zero canonicalises as `0`. `null` is retained as JSON `null` (`src/knok/canonical.py:36`, `_check`).
- **Unicode:** object keys are sorted by UTF-16 code units, as JCS requires (`src/knok/canonical.py:12-13`; `src/knok/canonical.py:57-59`, `_utf16_key`; `tests/test_review_fixes.py:56-63`). Strings are not NFC-normalised; NFC and NFD spellings remain distinct values and produce distinct bytes, which is correct for JCS (`src/knok/canonical.py:74-81`, `canonical_bytes`). Control characters are escaped by the JSON encoder (`src/knok/canonical.py:75-81`, `canonical_bytes`). Lone surrogate code points fail UTF-8 encoding and are converted to `CanonicalisationError` (`src/knok/canonical.py:81-85`, `canonical_bytes`; `tests/test_review_fixes.py:39-43`, `test_lone_surrogate_is_refused_not_raised`).
- **Duplicate keys:** a Python dictionary cannot represent duplicate object keys, so `canonical_bytes()` cannot detect them (`src/knok/canonical.py:48-53`, `_check`). Raw JSON duplicate-key rejection belongs at the JSON parsing boundary; this module's dictionary-level contract cannot establish it.
- **No observed canonical collisions:** for the supported Python value domain, object key order and insignificant whitespace do not affect the output; array order and actual string/code-point values do (`src/knok/canonical.py:62-68`, `_ordered`; `tests/test_canonical.py:13-15`). No pair of distinct supported values was found that collapses to the same canonical bytes beyond JSON's own numeric equivalences (for example, lexical `-0` and `0` both parse to integer zero).
- **Unknown fields:** top-level envelope fields, `sealed`, `sealed.hpke`, and A2A Message/Part fields are rejected when unknown (`src/knok/envelope.py:128-130`; `src/knok/envelope.py:84-89`, `_validate_sealed`; `src/knok/envelope.py:96-101`; `src/knok/message.py:56-58`, `validate_message`; `src/knok/message.py:91-93`). The `turn` exception is F3.
- **Form 2:** the signature covers both the clear header and ciphertext (`src/knok/envelope.py:212-213`, `sign`; `src/knok/envelope.py:276-285`, `seal`). Editing the clear `messageId`, ciphertext, or any other field after signing breaks verification (`tests/test_envelope.py:36-40`, `test_form_2_tampered_sealed_fails`; `tests/test_envelope.py:43-49`, `test_form_2_message_id_swap_breaks_signature`). A plaintext envelope cannot be relabelled as sealed (or vice versa) without changing signed bytes and failing verification (`src/knok/envelope.py:137-140`, `validate`; `src/knok/envelope.py:66-77`, `form_of`). `unseal()` cross-checks the inner Message's `messageId` against the clear id and validates the opened form-1 envelope (`src/knok/envelope.py:337-346`, `unseal`; `tests/test_sealed_envelope.py:182-195`).
- **Decryption contract:** `unseal()` deliberately does not verify the sender signature; its caller must verify the sealed envelope first (`src/knok/envelope.py:17-23`; `src/knok/envelope.py:307-311`, `unseal`). The returned form-1 object retains the original signature, which is evidence over the sealed form and is not expected to verify again as a plaintext envelope. This contract is explicit in the module documentation (`src/knok/envelope.py:20-23`, `unseal`). The current bridge path still leaves form 2 unhandled (`src/knok/bridge.py:617-623`, `Bridge._handle`); the sealed receive flow is not yet live, consistent with decision 0003 and the open follow-on work.

## Time and identifier validation details

- `sentAt` may be arbitrarily old or in the future; see F2 and issue #90 (`src/knok/envelope.py:190-192`, `validate`).
- `expiresAt` must be after `sentAt` and not yet expired, but has no 30-day upper bound; see F1 (`src/knok/envelope.py:196-200`, `validate`).
- `_parse_time()` treats a timestamp without a timezone as UTC (`src/knok/envelope.py:55-63`, `_parse_time`). That is deterministic in this implementation, but a timezone-less value is not an unambiguous absolute instant across implementations. Require an explicit `Z` or numeric offset if these timestamps drive key validity.
- `seq` is a non-negative safe-range integer (`src/knok/envelope.py:157-162`, `validate`). Per-context sequencing is enforced later by the queue, not by envelope validation (`src/knok/queue.py:513-525`, `Queue.put`); this is the correct layer for the stateful ordering check.
- `replyTo` is not an accepted Message field; strict A2A Message validation rejects it as unknown (`src/knok/message.py:30-33`, `_MESSAGE_KEYS`; `src/knok/message.py:56-58`, `validate_message`). `taskId` and `referenceTaskIds` are accepted with the types checked by `validate_message()`, but there is no cross-field task consistency check here (`src/knok/message.py:78-82`, `validate_message`).

## Malformed-input behaviour

For ordinary JSON-shaped inputs, the tested malformed cases (non-object envelope, missing/wrong fields, invalid base64, wrong signature encoding/length, tampered signature) are refused rather than raised (`tests/test_envelope.py:151-166`, `test_malformed_input_never_raises`). `verify_envelope()` catches canonicalisation errors and defensive exceptions during canonicalisation (`src/knok/envelope.py:235-240`, `verify_envelope`); `validate()` also catches the recursive-copy failure for a deeply nested Message (`src/knok/envelope.py:169-172`, `validate`).

The “never raises” contract is narrower than an arbitrary Python-object contract: `validate()` runs before the defensive `try` in `verify_envelope()` (`src/knok/envelope.py:228`; `src/knok/envelope.py:235`, `verify_envelope`). Non-JSON Python objects (for example, dictionaries with mixed non-string keys, or a caller-supplied naive `now` datetime compared with an aware expiry) can still raise (`src/knok/envelope.py:198-200`, `validate`). Those values cannot arrive through a conforming JSON parser, but the public Python API should either document the JSON-shaped-input precondition or harden the outer validation boundary.

Tests were reviewed statically; they were **not run**. The existing tests cover key-order invariance, normal sign/verify, tampering, basic malformed fields, form-2 signature coverage, and message-id cross-checking (`tests/test_envelope.py:107-148`; `tests/test_envelope.py:29-49`; `tests/test_envelope.py:151-166`; `tests/test_sealed_envelope.py:182-195`). They do not cover the 30-day expiry boundary, stale/future `sentAt`, unknown `turn` fields, contradictory turn flags, low-entropy/reused ids, or timezone-less timestamps.
