# Review 01 — Authentication and request replay protection

**Review brief:** `docs/review-briefs/01-authentication-and-replay.md`  
**Deployment assessed:** the private tailnet hub described by the project README, with five trusted agents.  
**Review type:** static source and test review. The test suite was not executed. No code changes were made.

## Endpoint authentication matrix

| Endpoint | Authentication | State mutation |
|---|---|---|
| `POST /v1/mail` | Signed envelope (envelope signature); no request signature or request nonce | Mailbox insert / duplicate check; sender presence update; possibly expired-frame and dropped-frame state |
| `GET /v1/mail` | Signed request | Claims nonce; updates caller presence; reads mailbox |
| `POST /v1/mail/ack` | Signed request | Claims nonce; updates caller presence; deletes acknowledged mailbox rows |
| `GET /v1/presence/{agent}` | Signed request | Claims nonce; updates caller presence; reads presence |
| `GET /v1/registry/{agent}` | Signed request | Claims nonce; updates caller presence; reads registry/card data |
| `GET /v1/health` | Signed request | Claims nonce; updates caller presence; reads caller mailbox and dropped-frame counts |
| Any other path/method | No authentication; refused | No application state mutation |

The read endpoints are not state-free: successful request authentication claims a nonce and updates the caller's `last_seen` value. Deposit is the one deliberate exception to request-nonce authentication. The brief explicitly identifies that as a design choice, not an accidental omission.

## Findings

### F1 — A deposited envelope can be replayed after its mailbox copy is acknowledged

**Severity on the assessed deployment: Low.**  
**Location:** `src/knok/hub.py`, `Hub.deposit` (deduplication query and insert); `Hub.ack` (mail deletion).

**Input / sequence:**

1. Sender submits a valid, unexpired signed envelope E.
2. Recipient fetches E and acknowledges its `messageId`; `ack` deletes the mailbox row.
3. Before E expires, sender or anyone holding the exact envelope submits E again.

The deduplication check searches the live `mail` table. Once the recipient acknowledges and deletes the row, there is no durable tombstone for the tuple `(recipient, sender, messageId)`. The second deposit is therefore accepted and stored again.

**Consequence / reachability:** Anyone who has captured a still-valid envelope can cause it to be delivered again after acknowledgement. The hub does not authenticate the deposit request independently and does not retain a durable replay record for acknowledged message IDs. A recipient-side durable `seen` ledger can prevent the application from applying the same message twice, but the hub can still redeliver it and consume mailbox / processing capacity.

**Intent:** The absence of a request nonce on deposit is explicitly documented in `docs/HUB.md` known risk 4 and called out as deliberate in the review brief. The live-row-only deduplication behaviour is the consequence to account for; it is not request-authentication replay protection.

**Assessment:** Acceptable as a bounded trade-off for the current private tailnet deployment if recipients durably deduplicate message IDs. A public hub needs a persistent deduplication/tombstone policy (with a defined retention period) and additional sender abuse controls. Adding a request nonce alone would not prevent replay of the same signed envelope by a party that can resubmit it.

### F2 — Nonce expiry and timestamp-skew boundaries overlap at an exact instant

**Severity on the assessed deployment: Low; narrow boundary condition.**  
**Location:** `src/knok/hub.py`, `Hub.authenticate` (skew check) and `Hub._claim_nonce` (nonce pruning).

**Input / sequence:**

1. At time T0, submit a valid signed request with timestamp T0 and nonce N.
2. At exactly T0 + 600 seconds, submit the identical request again.

The timestamp check rejects only when the absolute skew is greater than 300 seconds. At exactly 300 seconds of age, the timestamp is still accepted. The nonce-pruning query deletes rows where `seen_at <= now - 600`; at exactly 600 seconds, N is deleted before the insert. The replay can therefore be accepted at this exact boundary.

The intended relationship is a ten-minute nonce retention window, twice the five-minute timestamp-skew window, so a request should not become replayable when timestamp validation stops rejecting it. The inclusive/exclusive comparisons leave one instant where both checks permit it.

**Consequence / reachability:** A party holding a captured request can replay it at the exact 600-second boundary, subject to clock and scheduling precision. This is not a practical broad replay window, but it contradicts the intended “accepted once” guarantee.

**Recommendation:** Make the nonce-retention interval strictly longer than the maximum accepted timestamp age, or change the comparisons so there is no instant at which the timestamp is accepted after its nonce has been pruned. Add a deterministic boundary test at exactly +300 and +600 seconds, plus just-before and just-after cases.

### F3 — A sufficiently large backward clock step can make a pruned request fresh again

**Severity on the assessed deployment: Low, conditional on a hub clock rollback.**  
**Location:** `src/knok/hub.py`, `Hub.authenticate` and `Hub._claim_nonce`.

**Input / sequence:**

1. A valid request with timestamp T0 and nonce N is accepted.
2. Hub time advances beyond T0 + 600 seconds and N is pruned.
3. The hub clock is then stepped backward to T0 + 240 seconds.
4. The captured request is submitted again.

At the rolled-back time, the request timestamp is only four minutes old and passes the skew check. Its nonce has already been deleted, so the request can be accepted again.

**Consequence / reachability:** A clock rollback after nonce pruning can re-enable a previously accepted signed request. Separately, a backward step of more than five minutes relative to agents' clocks causes legitimate requests to fail timestamp validation until clocks converge again.

**Recommendation:** Document clock synchronisation as an operational requirement and decide explicitly how the hub behaves after a clock discontinuity. For stronger protection, use a monotonic time basis for in-process age decisions together with durable replay state, or persist a high-water mark and refuse/handle wall-clock regressions rather than allowing old timestamps to become fresh. Add a clock-rollback regression test. A monotonic clock alone cannot directly replace persisted wall-clock timestamps across process restarts, so the persistence design needs to be considered.

### F4 — Authenticated agents can grow the nonce table without a configured bound

**Severity on the assessed deployment: Low with five trusted agents; material availability concern for a public or broadly shared hub.**  
**Location:** `src/knok/hub.py`, `nonces` schema, `Hub.authenticate`, and `Hub._claim_nonce`.

**Input:** An authenticated agent repeatedly sends valid requests using a new nonce each time.

The nonce table has a primary key on `(agent, nonce)` and old rows are pruned by age, but there is no per-agent or global row limit, rate limit, or explicit nonce length/format bound in the authentication path. A trusted but malfunctioning or compromised agent can generate a large number of unique nonces inside the ten-minute retention interval.

**Consequence / reachability:** SQLite storage and write load can grow with request rate. The table is time-bounded in normal operation, not rate- or size-bounded. This is an authenticated resource-exhaustion path, not an unauthenticated bypass.

**Intent:** `docs/HUB.md` lists nonce-store growth/pruning bounds as an open question. The implementation has age-based pruning but no capacity policy.

**Recommendation:** Before exposing the hub to a larger or less trusted population, define per-agent and global request-rate / nonce-count limits, bound nonce length, and decide what response is returned when a limit is reached. Keep the current private deployment's small trust boundary in view; do not add complexity without a deployment need.

### F5 — Duplicate authentication headers are not explicitly rejected

**Severity on the assessed deployment: Low; proxy-dependent ambiguity.**  
**Location:** `src/knok/hub.py`, `Hub.authenticate` (`headers.get("X-Knok-*")`).

**Input:** A request contains duplicate instances of one or more authentication headers, for example two `X-Knok-Agent` values.

The handler uses `headers.get()`, which returns one matching value (the first with Python's `http.client` message implementation); it does not check that exactly one instance exists. A reverse proxy may reject, preserve, combine, or normalise duplicates differently from the backend.

**Consequence / reachability:** The verifier and an intermediary may disagree about which header value represents the request. No direct signature bypass was demonstrated in this review, but inconsistent duplicate-header handling creates an avoidable ambiguity at the trust boundary.

**Recommendation:** Reject duplicate `X-Knok-Agent`, `X-Knok-Nonce`, `X-Knok-At`, and `X-Knok-Signature` fields at the hub, and configure any reverse proxy to reject them rather than combine or rewrite them.

## Protocol and implementation checks

### What the request signature covers

The client signs the JCS-canonicalised JSON request document with Ed25519. The document fields, in canonical JCS key order, are:

1. `agent` — `X-Knok-Agent`
2. `at` — `X-Knok-At`
3. `bodySha256` — SHA-256 hex digest of the exact body bytes
4. `method` — HTTP method
5. `nonce` — `X-Knok-Nonce`
6. `target` — exact request-target, including the query string

The signature covers the canonical document bytes, not a concatenation of raw HTTP header lines. The signature value is carried in `X-Knok-Signature` and is not itself part of the signed document. Other HTTP headers (including Host, Content-Type, and Content-Length) are not signed.

The hub rebuilds this document from the request it received. It verifies the exact `self.path` before parsing the query for dispatch. Therefore a proxy that reorders query parameters or changes percent-encoding causes verification to fail; the hub does not verify a normalised target and then dispatch a differently interpreted target. This is a sound binding between the signed target and the target received by the handler.

### Replay matrix

| Scenario | Result |
|---|---|
| Immediate replay of the same signed request | Rejected: the `(agent, nonce)` row already exists |
| Replay while timestamp remains fresh and nonce is retained | Rejected: nonce uniqueness |
| Replay after timestamp is more than five minutes old, nonce still retained | Rejected: timestamp skew |
| Replay after ordinary nonce expiry, with normal clock progression | Rejected: timestamp skew |
| Replay at the exact +600-second boundary | **Accepted in the boundary case described in F2** |
| Replay after hub restart | Rejected: nonce rows are stored durably in SQLite |
| Replay against a second hub process using the same store | Second process is prevented from opening the store by the advisory process lock; this is not a supported multi-process deployment |
| Same nonce used by a different agent | Does not collide: nonce uniqueness is scoped to `(agent, nonce)` |
| Same agent reuses a nonce for a different request | Rejected while the nonce row remains; the nonce is bound to the agent, not to a particular request payload |

### Work performed before authentication

- The HTTP server parses the request line and headers before application dispatch.
- `POST /v1/mail` reads a body capped at 64 KiB and JSON-parses it before envelope verification. This route intentionally authenticates by the envelope rather than `authenticate`.
- `POST /v1/mail/ack` reads its capped body before calling request authentication.
- The GET routes authenticate before parsing query parameters or performing their endpoint operation.
- The body reader does not accept an unbounded body: it rejects invalid lengths and reads at most the configured cap plus one byte for an over-limit body.

The remaining availability concern is time/concurrency rather than unbounded body size: the threaded HTTP server has no explicit socket read timeout or worker/concurrency cap in the reviewed code. A slow client can potentially occupy a worker while sending headers or a body. On the private tailnet this is a limited exposure; it belongs in the HTTP/availability review as well.

### Refusal behaviour

At the application layer, unknown agents, bad signatures, replayed nonces, stale timestamps, missing or empty authentication values, and unknown routes use the shared refusal response. Malformed authentication values that reach the handler also take this path.

There are deliberate distinctions outside that uniform refusal path:

- A valid authenticated request for an unknown registry agent returns 404; this is documented as a namespace lookup behaviour for an already registered caller.
- Mailbox over-capacity returns 429 on the private hub, with a retry hint, by design. The hub module documentation says a public hub should fold this into the shared refusal.
- HTTP syntax errors rejected by Python's HTTP parser can receive parser-level 400/431 responses before application authentication runs.

These distinctions should not be described as a universal same-bytes response for every malformed wire-level request. Within the application authentication path, the shared refusal handling is consistent.

### Key selection and issue #90

For signed requests, `authenticate` resolves the requester's public key through `_card_public_key(agent)` without passing the request's `X-Knok-At`. Key validity is therefore evaluated at the hub's current time, not at a timestamp chosen by the requester. The signed request timestamp does not widen the backdating behaviour associated with issue #90.

Deposit is different: it parses the envelope's sender-controlled `sentAt` and passes that instant to `_card_public_key(sender, at=sent_at)` and envelope verification. A sender can therefore ask the hub to evaluate the sender key at a backdated instant. This is the known issue #90 consequence acknowledged by `docs/SPEC.md` §5; it is outside the core request-authentication path but relevant to the deliberate envelope-only deposit design.

The current hub also accepts legacy dictionary registry entries whose keys are treated as valid indefinitely under decision 0002. That is a documented compatibility mode, not a new request-authentication defect.

## Test coverage observed

Existing tests cover endpoint request authentication, immediate replay rejection, stale/fresh timestamp behaviour, and persistence of mail/nonces across restart. The reviewed tests do not appear to cover:

- the exact +300 / +600 second boundary;
- clock rollback after nonce pruning;
- deposit replay after acknowledgement;
- duplicate authentication headers;
- nonce-table growth / limits.

These are recommended regression tests. **Tests were not run as part of this review.**

## Overall assessment and priorities

The request-authentication design is fundamentally sound for the stated private tailnet deployment: Ed25519 signatures bind the agent, timestamp, nonce, method, exact target, and body digest; nonce claims are atomic and durable; and the hub verifies what it received rather than a rewritten target.

The issues do not justify redesigning the authentication scheme. Prioritise:

1. Close the exact nonce/skew boundary gap (F2).
2. Define the intended replay guarantee for envelope-only deposit and retain message-ID tombstones if replay after acknowledgement is not acceptable (F1).
3. Define and test clock-regression behaviour (F3).
4. Add nonce resource limits before widening the trusted population (F4).
5. Reject duplicate authentication headers at the hub / proxy boundary (F5).

For the current five-agent private tailnet, F1, F3, F4, and F5 are bounded risks rather than immediate blockers. F2 is a real correctness defect but requires exact timing. None of the findings demonstrates an unauthenticated request-authentication bypass.
