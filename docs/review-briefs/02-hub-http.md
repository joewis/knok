# Review brief 2 — The hub's HTTP implementation

You are reviewing the HTTP server that faces the network: what it accepts, what it bounds, and what
it does when the input is wrong. Report findings, not a summary.

## Scope — read only these

- `src/knok/hub.py` — the request handlers and helpers: `do_GET`, `do_POST`, `_dispatch_get`,
  `_dispatch_post`, `_read_body`, `_json_body`, `_send`, `_refuse`, `_limit`, `_cursor`,
  `_encode_cursor`, `_decode_cursor`, `log_message`, `_sweep_loop`
- `src/knok/transport.py` — the client side of the same wire
- `tests/hub/test_hub.py`, `tests/transport/test_transport.py`

## Context

- `docs/HUB.md` — what the hub stores, its limits, and its known risks
- `docs/SPEC.md` §7 (transport)

## Deliberately outside this brief

Signature verification and nonces (brief 1) and what the stored mail means (brief 6). Where a bound
you find is enforced *inside* authentication, say so and stop there.

## Questions

1. **Bounds.** Build a table: request body, a header line, a header count, a URL, a query string, a
   nonce, a stored cursor, a mailbox. For each: what is the limit, where is it enforced, and is it
   enforced *before* the bytes are read or after they are in memory? Any row with no limit is a
   finding or an explicit accepted risk — say which.
2. **Body framing.** How is `Content-Length` read? What happens with a duplicate header, a chunked
   body, a body shorter than declared, a body longer than declared, or no length at all? Is there a
   request-smuggling shape if this sits behind a reverse proxy that disagrees?
3. **Routing.** What happens on an unknown path, a disallowed method, a `POST` to a `GET` route, a
   path with `..`, an encoded slash, or a very deep path? Does the difference tell a caller anything
   it should not know?
4. **Errors.** Which code paths return 500? For each, can an unauthenticated caller reach it, and
   does the response body or the log carry input-controlled text?
5. **Blocking.** Can one client block the accept loop — a slow body, a slow read, a large JSON
   document, a long database query? Is there a socket timeout, and is it set on every path?
6. **Database.** How many connections exist, created where, used from which thread? What are
   `journal_mode`, `synchronous` and the busy timeout? Can two concurrent requests deadlock, or can
   one lose a write, given the sweep loop also writes?
7. **Response integrity.** Is a response written in one call? What does a client observe if the
   process dies mid-body, or if the client disconnects mid-write — and is the state change already
   committed by then?
8. **Pagination.** How is the cursor built, and is it bound to the mailbox that requested it? Can a
   caller forge or mutate a cursor to read rows it should not, or to make the server loop forever?
9. **Query parsing.** Does the handler act on the parsed query (`parse_qs`) while the signature
   covered the raw target? What do duplicate, blank, absent and absurd values do?
10. **Resource release.** On every exception path: is the connection, cursor, file or temp object
    closed? Name any `except:` that swallows one and continues with a half-initialised state.

## Report

Start with the bounds table. Then findings as `F1`, `F2`, … each with `file:line`, the failing input,
the consequence, and whether it is reachable unauthenticated. Separate "the spec sets no bound here"
from "the code fails to enforce the bound the spec sets".
