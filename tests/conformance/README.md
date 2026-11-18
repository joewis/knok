# Slice-0 conformance harness

Proves spec §6 goal 6 from the first slice: an unmodified A2A v1.0 client
exchanges a plain `Message` with a bridge over HTTP on 127.0.0.1.

## Layout

| Path | What it is |
| --- | --- |
| `a2a_client.py` | The A2A client. Stdlib-only, imports nothing from the `knok` library, and must keep working with the library entirely absent. It wraps the `Message` in a Form 1 envelope, POSTs it, unwraps the reply and strictly parses the inner `Message`. |
| `test_slice0.py` | The harness. Starts the echo bridge itself on an ephemeral port. |
| `../src/knok/dev/echo.py` | The minimal echo bridge (dev tool, stdlib `http.server`). Binds 127.0.0.1 only. |
| `../src/knok/message.py` | The library's strict `Message` validator, used by the echo bridge. |

## Run

```sh
python -m knok.dev.echo --port 0   # in one terminal; note the printed port
pytest tests/conformance -q
```

`pytest tests/conformance -q` alone also works: the fixture starts the
bridge on an ephemeral port and stops it afterwards.

## What is checked

* Round trip: the client sends a `Message` (`kind`, `messageId`,
  `contextId`, role `agent`, `parts: [{kind: text}]`) and receives the
  identical dict back.
* The `Message` is never modified: no `signature` field, no invented
  fields inside it — on either side of the exchange.
* The strict parser rejects a `Message` carrying a `signature`, an unknown
  field, a wrong `kind`/`role`, a non-text part, or empty `parts`; the echo
  bridge answers those with HTTP 400.
* The client has no dependency on the library: its source contains no
  reference to it, and it runs as a standalone script with site-packages
  disabled (`python -S`).
* The bridge is unreachable on any non-loopback address.

## Deliberately not done here

* **No envelope signature.** The echo bridge produces and verifies no
  signature — it holds no keys. Signing and verification are slice 1
  (identity). The envelope it returns is Form 1 minus the `signature`
  field; the harness checks the `Message` shape only.
* **No queue, ack, dedupe or resend.** Delivery guarantees are slice 2.
* **No policy or handshake.** That is slice 3.
* **Text parts only.** The strict parser rejects non-text parts; other
  part kinds are admitted when a slice needs them.
* The validator admits every field A2A v1.0 defines on `Message` and
  `Part` (`metadata`, `extensions`, `referenceTaskIds`, `filename`,
  `mediaType`, plus `taskId`) — the rule is "no field A2A does not
  define", so a real A2A agent sending `metadata` passes, while a
  `signature` or any invented field is still rejected.
