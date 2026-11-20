# Review briefs

One review is not a review of a system; it is a review of whatever the reviewer happened to read.
These briefs cut the repository into areas small enough for a reviewer — human or model — to hold in
one pass, and give each pass the questions it exists to answer.

**How to use one.** Pick an area. Give the reviewer *only* the files in that brief's scope, plus the
two documents it names as context. Ask for every finding as `file:line` and the input that
demonstrates it. Do not give a reviewer the whole repository at once: a model that cannot hold it
will summarise instead of review, and a summary is not evidence.

**Ground rules to paste with every brief.**

- The spec is a claim, the code is an implementation, and they can disagree. A disagreement is a
  finding; say which of the two you believe and why.
- A behaviour you merely dislike is not a defect. Name the input, name the outcome, name why it
  matters. If it is deliberate and documented (the decision records, or `docs/HUB.md`'s known-risks
  section), say you are restating a documented risk rather than discovering one.
- Severity means consequence × reachability on the deployment described in `README.md`, not on a
  hypothetical public hub. Say which deployment you are assuming.
- Do not propose a fix before you have stated the failure. A fix without a failing input is a guess.

---

## 1. Authentication and request replay protection

**Scope:** `src/knok/hub.py` (`authenticate`, `_claim_nonce`, `_note_seen`, `_parse_iso`,
`_request_target`), `src/knok/identity.py`, `src/knok/hubclient.py`, `tests/hub/test_hub.py`, `tests/test_hubclient.py`.
**Context:** `docs/HUB.md` §Authentication, `docs/SPEC.md` §7.
**Known-deliberate:** deposit is authenticated by the envelope alone (`docs/HUB.md`, known risk 4).
Review it as a design and say what a public hub would need; do not report it as an oversight.

1. Build a table: every HTTP endpoint × what authenticates it (request signature, envelope
   signature, nothing). Which rows mutate state, and which of those have no nonce?
2. What exactly does the request signature cover — method, target with query, body bytes, headers?
   Show the bytes in the order they are concatenated, and show what happens if the query string is
   reordered or percent-encoded differently by a proxy.
3. Can a captured request be replayed? Within the skew window, after the nonce is pruned, after a
   hub restart, and against a second hub instance sharing the database?
4. What is the relationship between `SKEW_SECONDS` and `NONCE_WINDOW_SECONDS`, and what breaks if
   the hub clock steps backward by more than the skew during a request?
5. Is a nonce bound to the request it was issued for, or only to the agent? Can agent A's nonce
   affect agent B's request in any way?
6. What work does the hub do before authentication — body read, JSON parse, signature verify,
   registry lookup, database write? Can an unauthenticated caller make it do unbounded work?
7. Compare the response for: unknown agent, bad signature, replayed nonce, stale timestamp, and a
   valid request to a path that does not exist. Same bytes, same status, same timing?
8. Are the header values used for verification the same ones the signature covers? What does the
   server do with duplicate headers, and does that change under a reverse proxy?
9. When a key is looked up, what instant is used, and who chooses it? What can a sender choose
   about that instant, and what does the choice let them do?

**Report:** the endpoint table, then findings ranked by which row of it they break.

---

## 2. The hub's HTTP implementation

**Scope:** `src/knok/hub.py` (`do_GET`, `do_POST`, `_dispatch_get`, `_dispatch_post`, `_read_body`,
`_send`), `src/knok/transport.py`, `tests/transport/test_transport.py`.
**Context:** `docs/HUB.md` (storage, limits), `docs/SPEC.md` §7.

1. What bounds the size of a request body, a header line, a query string and a stored nonce? Is any
   bound enforced before the bytes are read, or after they are in memory?
2. How is `Content-Length` handled? What happens with a duplicate header, a chunked body, or a body
   longer or shorter than declared? Is there a request-smuggling shape behind a proxy?
3. What happens on a path that does not exist, a method that is not allowed, or a `POST` to a `GET`
   route? Does the difference tell a caller anything it should not know?
4. Which errors return a 500? For each, can an unauthenticated caller reach it?
5. Is any handler able to block the accept loop — a slow client, a slow database, a large body —
   and is there a timeout on any of them?
6. How many SQLite connections exist, in which threads, and what is the locking story? Can two
   requests deadlock or lose a write under `WAL`?
7. Are responses written in one call? What does a client see if the process dies mid-response?
8. Does every handler close what it opened — cursor, connection, file — on the exception path?
9. Is query parsing (`parse_qs`) tolerant of duplicates, blanks and absurd values, and does the
   signature cover the raw target rather than the parsed form?

**Report:** the bounds table (what limits exist, what value, where enforced), then findings.

---

## 3. Envelope format, validation and signatures

**Scope:** `src/knok/envelope.py`, `src/knok/canonical.py`, `tests/test_envelope.py`, `tests/test_canonical.py`.
**Context:** `docs/SPEC.md` §6, `docs/decisions/0001-two-authors.md`.

1. What exactly is signed? Enumerate the fields included and excluded, and show that the signature
   input is canonical for the same logical envelope built in a different insertion order.
2. How are numbers, unicode, duplicate keys and `null` handled in canonicalisation? Is there any
   input where two different envelopes produce the same signed bytes?
3. Does validation reject unknown fields? What can a sender smuggle in a field the receiver ignores
   but a different implementation would honour?
4. In form 2, which fields stay in clear and which are sealed, and does the signature cover both?
   Can a sealed envelope be downgraded to form 1, or a plaintext body relabelled as sealed?
5. What are `sentAt` / `expiresAt` used for at validation time, and what is not checked about them?
6. Are `messageId`, `contextId` and `seq` validated for type and relationship, or trusted?
7. What does `turn` mean, and can a sender set flags that make a receiver's state machine do
   something it would not otherwise do?
8. What does a malformed envelope cost the receiver — an exception, a refusal, or a crash?

**Report:** the signed-bytes definition, then any input that produces a valid signature over
something the sender did not intend.

---

## 4. Cryptographic key handling

**Scope:** `src/knok/identity.py`, `src/knok/keygen.py`, `src/knok/agentcard.py`, `src/knok/contacts.py` (key records,
rotation, approval), `src/knok/hub.py` (`_card_public_key`), `src/knok/cli.py` (key commands),
`tests/test_identity.py`, `tests/test_card_body.py`, `tests/test_card_expiry.py`.
**Context:** `docs/decisions/0002-registry-and-key-records.md`, `docs/SPEC.md` §5 and §9.

1. Where is a private key generated, and from what entropy? Is anything derived from a passphrase,
   an environment variable, or a file that could be world-readable?
2. What are the file modes and ownership of every artefact holding key material, on write and on
   read? Is the write atomic, and what is on disk if it is interrupted?
3. Can a private key reach a log line, an exception message, a serialised envelope, a notice, or
   `argv`? Search for every path that formats a key.
4. Are the signing key (Ed25519) and the sealing key (X25519) distinct? If one is used for both,
   say what that costs.
5. What happens on rotation: which key signs the new card, what does the registry keep, and what can
   the old key still do afterwards — send, receive, decrypt, authenticate a request?
6. When a card is trusted, what is bound to what: name, fingerprint, key, validity window? Can a
   card be moved between names or hubs?
7. In the approval flow, what exactly does the owner see, and what is recorded? Can the recorded
   decision be made about a different key than the one shown?
8. Is key material held in memory longer than needed, copied into an object that outlives the
   request, or written to a temporary file?

**Report:** a key lifecycle table (generate → publish → use → rotate → revoke → destroy), then
findings on that table.

---

## 5. Sealed messages and HPKE

**Scope:** `src/knok/hpke.py`, `src/knok/envelope.py` (`seal`, `unseal`), `tests/conformance/test_slice0.py`
(the RFC 9180 A.2 vectors), `tests/test_sealed_envelope.py`.
**Context:** `docs/decisions/0003-sealed-decryption-boundary.md`, `docs/SPEC.md` §6, issue **#83**.

1. Which HPKE mode is implemented, and is that mode correct for this use — base, psk, auth, auth-psk?
   What does the choice leave unauthenticated?
2. Run the RFC 9180 A.2 test vectors in both directions. If the code passes them, say what that does
   and does not prove.
3. What are `info` and `aad`, and what are they bound to? Can a ciphertext be moved to another
   recipient, another message id, another context, or another form without failing to open?
4. Is a fresh ephemeral key generated per message, and is the KEM shared secret used once?
5. Where does the recipient's public key come from, and what happens if it is stale, revoked, or
   belongs to a different agent?
6. On a wrong key, wrong aad, or tampered ciphertext: refusal or exception? Does the failure leak
   which of those it was?
7. Where does plaintext exist once unsealed — memory, the queue, the inbox file, logs, a temp file —
   and which of those is a change from the plaintext path?
8. What happens to a sealed message the receiver cannot open? Is it dropped, retried, dead-lettered,
   or does it block the queue?

**Report:** the mode and its limits, the aad/info binding table, then findings. Anything that is
issue #83's open question should be named as such, not reported as a defect.

---

## 6. Delivery, queue and durability

**Scope:** `src/knok/queue.py`, `src/knok/bridge.py` (`_handle`, `drain`, `delivery.jsonl`),
`src/knok/gate.py` (decide vs apply), `tests/queue/test_queue.py`, `tests/test_delivery_ledger.py`.
**Context:** `docs/SPEC.md` §6, `docs/HUB.md` (delivery), `#69`, `#79`, `#80`.

1. Trace one message from `fetch` to `inbox.jsonl`. At each step, what is durable, what is in memory,
   and what would be lost by a crash exactly there?
2. What is the order of dedupe, gate decision, queue write, and ack? Can any two of them disagree
   after a crash?
3. If the ack is lost and the hub re-offers the message, what happens to the reply counter and the
   rate budget? Show the code path.
4. What is the dedupe key, and what happens when a sender reuses `seq` in an existing context, or
   mints a new `messageId` at a consumed `seq`?
5. Is the mailbox cap enforced before or after storage? Can a sender fill a mailbox that then refuses
   the messages it needs?
6. What are the SQLite settings (`journal_mode`, `synchronous`), and what do they actually guarantee
   on this filesystem? Is the ledger fsynced before the ack?
7. Can two bridge processes run against the same state directory, and what breaks if they do?
8. What does the receiver do with a message it has already delivered but never acked — at the queue,
   at the thread, at the counter?

**Report:** the crash-point matrix (point × what survives × what is duplicated), then findings.

---

## 7. Retry policy and the CLI contract

**Scope:** `src/knok/retry.py`, `src/knok/cli.py` (`send`, `retry`, `notices`), `tests/test_retry_policy.py`,
`tests/test_send_retry.py`, `tests/test_notices_cli.py`.
**Context:** `docs/SPEC.md` §6 (delivery), `#68`.

1. When a retry is performed, is the envelope replayed verbatim — same `messageId`, same
   `contextId`, same `seq` — or is anything re-minted?
2. How is the retry budget reserved, and what happens if the ledger cannot be written? Is the retry
   performed anyway, refused, or counted after the fact?
3. Which failures are retryable and which are terminal? Show the classification for 400, 403, 404,
   409, 429, 500, a timeout, and a connection refused.
4. What does each exit code mean, and can two different outcomes share one? Is the code in scan mode
   the outcome of the scan or of the worst retry in it?
5. What happens to a notice whose message the adapter never sent? What happens to a retry whose
   message was already delivered?
6. Can a retry loop forever, or grow the ledger without bound? What prunes it?
7. Is the ledger read and written atomically? What does a truncated line do to the scan?
8. Does anything in the retry path depend on the wall clock in a way a clock step would break?

**Report:** the outcome table (condition → classification → exit code → what the ledger says), then
findings where the three disagree.

---

## 8. Contact gate, policy and abuse

**Scope:** `src/knok/gate.py`, `src/knok/policy.py`, `src/knok/rates.py`, `src/knok/contacts.py` (policy, limits,
approval), `tests/test_gate.py`, `tests/test_policy.py`, `tests/test_policy_reload.py`.
**Context:** `docs/SPEC.md` §9, `docs/TESTING.md` (the abuse scenarios), `#42`, `#65`.

1. Where does a peer's effective trust level come from, and can any input raise it without a local
   owner action?
2. What does a refusal look like from the sender's side — bytes, status, notice, silence? Is it the
   same refusal for "not allowed", "rate limited", "needs approval", and "thread closed"?
3. How are limits counted, and what resets them? A restart, a clock step, a policy reload, two
   bridges?
4. In the approval flow, what can a peer cause to appear on the owner's screen, how often, and can a
   peer make the owner's decision apply to a key the owner did not see?
5. Can a blocked sender consume storage, wake the agent, or starve a legitimate sender's mail?
6. What happens when the policy file changes mid-flight — is it re-read, cached, or reloaded only at
   start? Which requests see which policy?
7. Is there any path where a message is dropped without a record on either side? Name it.
8. What does an attacker learn from timing alone: hold vs refuse vs approve, and how fast?

**Report:** the refusal table (condition → what the sender observes → what is recorded), then
findings where a row is distinguishable when it should not be, or indistinguishable when the sender
needs the difference.

---

## 9. Logging, notices and secret leakage

**Scope:** `src/knok/bridge.py` (delivery ledger, notices), `src/knok/cli.py` (notices), every
`logging`/`print` call in `src/knok/`.
**Context:** `docs/SPEC.md` §9 (what a peer may learn), `docs/HUB.md` (what the hub stores).

1. What is written to disk on every message, where, with what mode, and for how long? Does any of it
   contain message bodies, keys, or peer-visible metadata that the spec says is local?
2. Can a log line or a notice be used to reconstruct a message the receiver was supposed to refuse?
3. Does any error path print a full envelope, a signature, a key, or a path containing one?
4. Are notices themselves messages — do they cross the wire, get stored, and count against limits?
   Can a notice loop?
5. Is anything logged with a timestamp that reveals the owner's activity pattern (when they approved,
   when they were at the keyboard)?
6. What does `delivery.jsonl` record about a message that was refused, and who can read it?
