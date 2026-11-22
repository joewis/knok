# Live deployment

The hub and the three local bridges run as containers from `knok:0.4.0`. State is **not** copied
into a volume — each container mounts the directory that was already in use, so the upgrade is a
process replacement, not a migration:

- hub: `/srv/knok-live/hub` (SQLite store, key) and `/srv/knok-live/registry` (read-only)
- carl: `/home/carl/.knok`
- sunny: `/home/openclaw/.knok`
- kiko: `/home/openclaw/.knok-kiko`

The adapters (`knok-adapter-openclaw`, `knok-adapter-kiko`) stay as systemd units. They read the
inbox files those directories contain and never speak the hub protocol, so an adapter restart is
not part of a knok upgrade.

## Upgrade

```bash
docker build -f deploy/Dockerfile -t knok:0.4.0 .          # or let compose build
docker compose -f deploy/live/docker-compose.yml up -d
```

Bridges first, hub last is the safe order: a 0.4 bridge speaks to a 0.3 hub (it sends an extra
`undelivered` key on ack, which the older hub ignores), while a 0.4 hub queues `delivered` frames
an older bridge would leave at the hub rather than ack. Nothing is lost either way; the order
avoids noise.

## Rollback

```bash
docker compose -f deploy/live/docker-compose.yml down
systemd-run --unit=knok-hub --setenv=KNOK_ROLE=hub     --setenv=KNOK_HUB_DOMAIN=knok.local \
  --setenv=KNOK_STATE=/srv/knok-live/hub --setenv=KNOK_REGISTRY=/srv/knok-live/registry \
  --setenv=KNOK_BIND=100.81.75.26:18443 \
  --setenv=PYTHONPATH=/opt/knok-live/src:/opt/knok-live/pylib /usr/bin/python3 -m knok.runner
# and the same shape for knok-bridge-carl, knok-bridge-openclaw, knok-bridge-kiko
```

`/opt/knok-live` is left untouched by the container deployment and still holds the 0.3 tree those
units ran, so rollback is a process swap in the other direction. Note that the 0.4 hub writes
`mail_seen` rows into the same SQLite file; a 0.3 hub ignores the table, which is why the file is
compatible in both directions.

## Checking it

```bash
docker compose -f deploy/live/docker-compose.yml ps
docker compose -f deploy/live/docker-compose.yml logs --tail=50 hub
docker compose -f deploy/live/docker-compose.yml logs --tail=20 bridge-carl
```

A healthy poll is silent; a bridge logs only when it fetches something. A hub that has lost its
lock file or cannot bind prints on startup and exits, and the restart policy will show it as
restarting rather than up.
