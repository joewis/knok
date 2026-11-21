# Review 02 — The hub's HTTP implementation

**Review brief:** `docs/review-briefs/02-hub-http.md`  
**Deployment assessed:** the private tailnet hub described by the project documentation, with a small, operator-controlled registry (currently five agents).  
**Review type:** static source and test review. The test suite was not executed. No code changes were made.

## Bounds table

| Input / resource | Effective limit | Enforcement point | Before or after reading bytes? |
|---|---|---|---|
| Request body | 64 KiB (`MAX_ENVELOPE_BYTES`) | `_read_body` in `hub.py` | Content-Length is checked before body read; an oversized body is then read only up to 64 KiB + 1 byte before refusal. A permitted body is read fully before JSON parsing. |
| Individual header line | Approximately 64 KiB under the CPython `http.server` / `http.client` parser defaults | Standard-library header parser, before handler dispatch | The parser reads each line with a fixed maximum; the bytes are necessarily received into its buffer before the limit is reported. Knok does not configure a smaller limit. |
| Header count | 100 under the standard-library parser default | Standard-library `http.client.parse_headers` | Enforced while parsing headers, before handler dispatch. Not a Knok-specific setting. |
| Request target / URL | Approximately 64 KiB as part of the HTTP request-line limit | `BaseHTTPRequestHandler` request parser | Enforced by the standard-library parser before route dispatch. There is no separate Knok URL or query-string limit. |
| Query field count | No explicit field-count limit; indirectly bounded by the request-line limit | `urllib.parse.parse_qs` in `_fetch` | Parsing happens after the request target is already in memory and after request authentication. `max_num_fields` is not supplied. |
| Request nonce | No nonce-specific limit; indirectly bounded by the header-line limit | Header parser, then `authenticate` | Header bytes are already read before authentication. No explicit nonce length/format check. See Review 01 F4. |
| Fetch cursor | No explicit cursor length or numeric range; indirectly bounded by URL/request-line limit | `_decode_cursor` / `_cursor` | Decoded after the target is in memory and after authentication. |
| Mailbox | 10,000 rows or 256 MiB per recipient, whichever is reached first | `Hub._at_cap` before inserting an envelope/frame | Enforced after the incoming body has been read, parsed and verified. There is no separate global database/mailbox cap. |

The body cap and per-recipient mailbox cap are real application-level bounds. Header, request-line and header-count limits come from the Python standard library rather than explicit Knok configuration; they should be treated as runtime-dependent defaults. The mailbox cap bounds each recipient, not total hub storage. The documented ten-agent ceiling is a supported deployment estimate, not an enforced maximum registry size.

## Findings

### F1 — Slow clients can occupy an unbounded number of request threads

**Severity on the assessed deployment: Low; availability risk if an agent or tailnet peer is compromised.**  
**Location:** `src/knok/hub.py`, `Hub.start` and `_Handler._read_body`.

**Input:** An unauthenticated client opens connections and sends a request line/header slowly, or declares a body within the 64 KiB limit and trickles the body bytes without completing it.

The server is a `ThreadingHTTPServer`; each accepted connection is handled in its own daemon thread. The hub does not set a socket read timeout on accepted sockets and does not impose an application-level cap on concurrent request threads. `_read_body` performs a blocking read for the declared length. The 64 KiB cap limits the total body size, not the time taken to deliver it. Header parsing also occurs before the handler can apply any application policy.

**Consequence / reachability:** A client does not need valid Knok credentials to consume a handler thread. Enough slow connections can exhaust threads and associated file descriptors/memory, leaving legitimate agents unable to make progress. The accept loop is not synchronously blocked by one slow body—the server is threaded—but the worker population is not bounded.

**Spec status:** The current private-hub contract does not define a socket timeout or concurrency limit. This is an availability gap in the implementation, not a failure to enforce a documented timeout.

**Recommendation:** Set a finite per-connection read timeout immediately after accept, and add a concurrency limit or place the hub behind a front end that enforces connection and request timeouts. Test slow headers and slow bodies separately. Keep the private tailnet threat model in mind; this is not evidence of an unauthenticated data-access bypass.

### F2 — HTTP body framing relies on a single Content-Length value and does not reject ambiguous framing

**Severity on the assessed deployment: Low; proxy-dependent request-framing risk.**  
**Location:** `src/knok/hub.py`, `_Handler._read_body`.

**Inputs and behaviour:**

- **No Content-Length:** treated as length -1 and refused.
- **Malformed or negative Content-Length:** refused.
- **Chunked body without Content-Length:** `Transfer-Encoding` is not implemented; the missing length causes refusal. The chunk framing is not decoded.
- **Content-Length plus Transfer-Encoding:** the handler ignores `Transfer-Encoding` and reads the declared Content-Length bytes.
- **Duplicate Content-Length:** `self.headers.get("Content-Length")` selects one value (the first with Python's message implementation); the handler does not reject duplicates or compare all values.
- **Body shorter than declared:** `rfile.read(size)` waits for the requested bytes or connection termination. If fewer bytes arrive, the handler refuses.
- **Body longer than declared:** only the declared number of bytes is consumed and parsed. Trailing bytes are not checked as part of the body. The handler responds with connection close and the server uses HTTP/1.0, so it does not process a second request on that connection.
- **Body over 64 KiB:** the handler reads at most 64 KiB + 1 bytes and refuses.

**Consequence / reachability:** Direct clients cannot use chunked transfer encoding successfully. Duplicate or conflicting framing headers can, however, be interpreted differently by a reverse proxy and the backend. The backend's one-request-per-connection / close behaviour reduces the usual request-smuggling opportunity, and this review did not demonstrate a working desynchronisation exploit. It is still unsafe to rely on intermediaries making the same choice as `headers.get()`.

**Spec status:** The contract specifies a 64 KiB message cap, but does not define duplicate Content-Length handling or chunked transfer support. This is a hardening gap, not a missed numeric body limit.

**Recommendation:** Explicitly reject duplicate Content-Length and any Transfer-Encoding header; require exactly one valid Content-Length for body-bearing routes. Configure any reverse proxy to reject ambiguous framing too. Add raw-socket tests for duplicate lengths, CL+TE, chunked-only, short bodies and trailing bytes.

### F3 — A single authenticated ack request can fan out into thousands of serialized SQL statements

**Severity on the assessed deployment: Low to moderate; requires a registered agent able to sign requests.**  
**Location:** `src/knok/hub.py`, `_Handler._ack` and `Hub.ack`.

**Input:** A registered agent submits a valid signed `POST /v1/mail/ack` with a body containing a very large `messageIds` list. The body is still within the 64 KiB request-body limit; the list can contain thousands of short strings, including repeated or empty strings.

The handler checks only that `messageIds` is a list and every item is a string. It does not impose a maximum item count, reject empty IDs, or deduplicate the list. `Hub.ack` then starts one transaction and executes one DELETE statement for every list element while holding the hub's shared database lock.

**Consequence / reachability:** One authenticated but faulty or compromised agent can turn a small bounded request into thousands of SQL operations and hold the lock that serializes all hub database work. Fetches, deposits, health/presence reads, nonce claims and the expiry sweeper can all be delayed behind that work. This is not an unauthenticated attack, but it is a resource-amplification path inside the trusted-agent boundary.

**Spec status:** The body-size cap is enforced. The contract does not define an ack-list item limit; this is an unbounded-per-item-work gap within the bounded body.

**Recommendation:** Set a small maximum number of IDs per ack (for example, 100), require non-empty bounded-length strings, and deduplicate before entering the transaction. Add a test that an over-limit list is refused without partially deleting mail.

### F4 — Unsupported HTTP methods bypass the hub's shared refusal response

**Severity on the assessed deployment: Low (protocol fingerprinting / inconsistent refusal behaviour).**  
**Location:** `src/knok/hub.py`, `_Handler` method dispatch; inherited `BaseHTTPRequestHandler` handling for methods without a `do_<METHOD>` implementation.

**Input:** An unauthenticated caller sends a method other than GET or POST, such as PUT, HEAD, OPTIONS or TRACE.

The handler defines `do_GET` and `do_POST`, but does not override `send_error` or implement a common `do_* ` fallback. Python's base handler therefore responds to an unsupported method with its standard 501 error response (including its standard HTML error body), rather than Knok's shared 403 JSON refusal. Malformed request lines and parser-level header/request-line errors can likewise be rejected by the standard library before Knok dispatches the request.

**Consequence / reachability:** An unauthenticated caller can distinguish unsupported methods from unknown GET/POST routes and learn that the endpoint is a Python `BaseHTTPRequestHandler`-based service. This is a small information disclosure, not an authentication bypass. POST to a GET-only route and GET to a POST-only route do reach Knok dispatch and receive the shared 403.

**Spec status:** The shared-refusal contract is written for application authentication/identity failures; it does not clearly specify how unsupported HTTP methods or malformed HTTP syntax should be answered. The implementation is inconsistent with the broad module-docstring claim that no handler path leaks a distinguishable refusal, but not necessarily with the narrower wire contract.

**Recommendation:** Decide whether unsupported methods should intentionally return 501/405 or be folded into the shared refusal. If uniformity is intended, override the base error path deliberately and test it. Do not assume malformed HTTP syntax can be made identical to application-level refusals without taking control of the HTTP parser.

## Other questions checked

### Routing

- Unknown GET/POST paths are refused with the shared 403.
- POST to a GET route and GET to a POST route also fall through to the shared 403.
- A path containing literal `..` is not normalised into another route; it does not map to a filesystem path.
- Encoded slashes are only unquoted in the suffix of the presence and registry routes. The result is used as an agent-id lookup string, not as a filesystem path. An encoded slash therefore does not create path traversal; it produces a lookup miss for normal agent IDs.
- Very deep paths do not recurse through directories or filesystem components. They remain a string passed to route matching / lookup, subject to the request-line limit.
- Query parsing occurs only on the mail-fetch route. The raw request target is authenticated before `parse_qs` is applied (authentication details were covered in Review 01).

### Query values and cursors

- `limit` absent: defaults to 50.
- `limit` blank: `parse_qs` drops blank values by default, so it also behaves as absent and defaults to 50.
- `limit` repeated with two non-blank values: refused.
- `limit` non-integer or less than 1: refused.
- `limit` above 100: clamped to 100.
- `cursor` absent or blank: treated as 0.
- Repeated non-blank cursors: refused.
- A malformed cursor: refused.
- A negative integer cursor is accepted by `_decode_cursor`; it behaves much like a cursor of 0 because the query selects rows with `id > after`. An extremely large cursor simply yields no rows. Neither case permits reading another agent's mailbox: the SQL query always filters by the authenticated recipient.
- Cursors are not cryptographically bound to an agent or mailbox. That is not an access-control defect here: they are client-supplied pagination positions, and the database query scopes every page to the authenticated agent. A caller can choose a cursor that skips its own earlier mail, but cannot use it to read another mailbox.
- `parse_qs` has no explicit `max_num_fields`, but the request-line limit indirectly bounds the total query bytes. Unknown query keys are parsed and then ignored.

### Error handling and logs

The application GET/POST entry points catch ordinary exceptions and attempt the shared refusal response. No normal route path deliberately returns HTTP 500. A client disconnect during response writing can still cause a write exception; the handler's attempt to send a refusal may also fail, leaving the client with a truncated response or closed connection rather than a clean 403. This is a transport failure, not a meaningful application error response.

The base HTTP parser can emit its own 400/414/431-class errors before Knok code runs, and unsupported methods produce the 501 noted in F4. `log_message` is overridden to suppress ordinary request logging. The sweeper logs exceptions; the expired-frame capacity warning includes the sender ID and message ID. Those values originate in validated envelope metadata, but the message ID is sender-controlled, so log consumers should still treat it as untrusted text and avoid rendering it as terminal control sequences.

### Database concurrency and configuration

- One SQLite connection is created in `Hub.__init__` with `check_same_thread=False` and a 30-second SQLite busy timeout (`timeout=30.0`).
- The connection uses WAL journal mode, `synchronous=FULL`, and foreign keys enabled.
- A process-wide advisory `flock` prevents a second hub process from opening the same store.
- A single `threading.RLock` serializes access to the shared connection. The HTTP handlers and sweeper use that lock around database operations; nested helper calls are compatible with the re-entrant lock.
- The sweeper uses the same connection and lock. It cannot concurrently write through a second connection, and the reviewed code does not show a lock-order cycle that would deadlock the request threads against the sweeper.
- The 30-second SQLite busy timeout is not a request timeout. A request can still wait behind another operation holding the application lock, including the unbounded ack-list loop in F3 or an expiry sweep processing many rows.

### Response integrity and commit ordering

Responses are assembled in memory and written with one `wfile.write(body)` call after status and headers are sent. That is one application-level write, not a guarantee of one atomic network write.

- Deposit commits the mailbox change before sending 202.
- Ack commits its deletions before sending 200.
- Request authentication commits the nonce claim before the endpoint response.
- A process or connection failure during the response can therefore leave the client uncertain even though the state change has already committed. The client must retry with a fresh signed request nonce. Deposit duplicates are handled by the hub's existing live-row deduplication; ack is idempotent. Replaying the exact same signed request is not a valid retry because its nonce has already been claimed (Review 01).

### Resource release

The hub owns one SQLite connection and one lock-file descriptor; both are closed in `Hub.stop`. The server socket is closed by `server_close`, and the serving/sweeper threads are joined with finite waits. Request threads are daemon threads and are not individually joined by `stop`; that is another reason to bound request duration. No request-scoped database cursor or temporary file is retained across calls. The broad exception handlers in the request entry points convert application exceptions to refusals; the sweeper catches and logs failures so that a failed sweep does not terminate the loop.

## Test coverage observed

The hub tests cover normal deposit/fetch/ack, malformed and over-cap deposits, request authentication, cursor paging, mailbox capacity, expiry, restart persistence, and shared application refusal behaviour. They do not appear to exercise:

- slow headers or slow bodies / read-timeout behaviour;
- duplicate Content-Length, CL+TE, chunked-only, short or trailing request bodies;
- excessive ack-list length or repeated IDs;
- unsupported HTTP methods and parser-level 400/414/431 responses;
- very long request targets, excessive header count, or excessive query field count;
- response disconnects after a committed deposit/ack;
- stop behaviour while request threads are blocked.

**Tests were not run as part of this review.**

## Overall assessment and priorities

The HTTP implementation has sensible basic bounds: a 64 KiB body cap, a per-recipient mailbox cap, bounded fetch pages, and a single SQLite connection protected by a re-entrant lock. Routing does not expose filesystem traversal, and cursors cannot cross mailbox boundaries.

The main gaps are operational rather than cryptographic:

1. Add read timeouts and a concurrency limit so slow unauthenticated clients cannot accumulate worker threads (F1).
2. Reject ambiguous HTTP body framing explicitly, especially duplicate Content-Length and Transfer-Encoding (F2).
3. Bound the number of IDs processed by one ack request (F3).
4. Decide how unsupported methods and parser-level errors fit the refusal contract (F4).

For the current private tailnet, these are hardening tasks rather than evidence that an untrusted internet caller can access mailbox data. The most concrete availability weakness is the lack of request timeouts; the most direct authenticated resource-amplification weakness is the unbounded ack-list loop.
