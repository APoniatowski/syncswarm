# SyncSwarm Relay

A standalone relay node for the [SyncSwarm](../README.md) network. Host one to help
the swarm: relays **forward traffic for other peers** and can **hold messages for
offline recipients** until they return. The more independent relays exist — across
different networks and operators — the more resilient and private the swarm.

A relay **cannot read the traffic it carries.** It only ever peels a single onion
layer with its own node key to learn the next hop; it never holds the content key,
so messages passing through it stay end-to-end encrypted. It is also
**application-agnostic** — the same relay serves SwarmMessenger or any SyncSwarm
app.

## Run it with Docker (recommended)

```bash
# from the SyncSwarm SDK repo root (the relay is part of that Go module):
docker build -f relay/Dockerfile -t syncswarm-relay .

docker run -d --name syncswarm-relay \
  -p 64512:64512/udp \
  -p 64513:64513/tcp \
  -v syncswarm-relay-data:/data \
  --restart unless-stopped \
  syncswarm-relay
```

Or with Compose:

```bash
docker compose -f relay/docker-compose.yml up --build -d
docker compose -f relay/docker-compose.yml logs -f
```

The image is a ~10 MB distroless build, runs as a non-root user, and has a
built-in `HEALTHCHECK`. The `/data` volume holds the node's persistent identity
and its offline message queue — keep it to preserve the relay's node ID.

## Run it as a plain binary (no Docker)

```bash
# from the SyncSwarm SDK repo root:
go build -o syncswarm-relay ./relay

./syncswarm-relay -store -scoring
```

Cross-compile for another host:

```bash
GOOS=linux   GOARCH=arm64 go build -o syncswarm-relay-linux-arm64 ./relay
GOOS=windows GOARCH=amd64 go build -o syncswarm-relay.exe          ./relay
GOOS=darwin  GOARCH=arm64 go build -o syncswarm-relay-macos        ./relay
```

Run it under systemd, a process supervisor, or in a `screen`/`tmux` session so it
stays up.

## Run as a systemd service (Ubuntu/Debian)

Keep a relay up across reboots without Docker. Install the binary and drop a unit:

```bash
sudo install -m 0755 syncswarm-relay /usr/local/bin/
```

`/etc/systemd/system/syncswarm-relay.service`:

```ini
[Unit]
Description=SyncSwarm Relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
StateDirectory=syncswarm-relay
ExecStart=/usr/local/bin/syncswarm-relay \
  -storage /var/lib/syncswarm-relay \
  -boot PEER_PUBLIC_IP:64512 \
  -http 127.0.0.1:8080 -store
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now syncswarm-relay
systemctl status syncswarm-relay
journalctl -u syncswarm-relay -f
```

- `StateDirectory` creates `/var/lib/syncswarm-relay` and **persists the node
  identity** — keep it so the relay's node ID stays stable across restarts.
- `DynamicUser=yes` runs it as a sandboxed, throwaway system user (no manual
  useradd).
- The health endpoint is bound to **localhost** — monitor it over SSH rather than
  exposing it. Drop `-boot` entirely on the *first* relay of a brand-new swarm.
- Open the firewall (below) for UDP `64512` + TCP `64513`.

## Configuration

Every setting is a flag with an environment-variable fallback, so the same binary
is convenient on the command line and in a container.

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `-disc` | `SYNCSWARM_DISCOVERY_PORT` | `64512` | UDP discovery port. |
| `-data` | `SYNCSWARM_DATA_PORT` | `64513` | TCP data-transfer port. |
| `-storage` | `SYNCSWARM_STORAGE_DIR` | `./relay-data` (`/data` in Docker) | Node identity + offline queue. |
| `-boot` | `SYNCSWARM_BOOTSTRAP` | – | Comma-separated `host:discPort` peers to join. |
| `-bridge-listen` | `SYNCSWARM_BRIDGE_LISTEN` | – | TCP address to accept inbound discovery **bridges** on (e.g. `:64514`); lets NAT'd clients bridge discovery through this relay. Empty = off. |
| `-bridge` | `SYNCSWARM_BRIDGE` | – | Comma-separated transport nodes to open outbound bridges to (`host:bridgePort`). |
| `-store` | `SYNCSWARM_STORE_FORWARD` | `true` | Hold messages for offline recipients. |
| `-store-ttl` | `SYNCSWARM_STORE_FORWARD_TTL` | default | How long to hold offline messages (e.g. `30m`). |
| `-scoring` | `SYNCSWARM_RELAY_SCORING` | `true` | Challenge peer relays; route around silent droppers. |
| `-http` | `SYNCSWARM_HTTP_ADDR` | – (`:8080` in Docker) | Health/metrics HTTP server (empty = off). |
| `-stats` | `SYNCSWARM_STATS_INTERVAL` | `1m` | How often to log a status line (`0` = never). |

There is **no content-key option** — a relay never needs one.

## Networking

- Open/forward **UDP `64512`** (discovery) and **TCP `64513`** (data) to the relay.
- For the relay to be reachable from the public internet it needs a routable
  address (a VPS, or port-forwarding on your router).
- To join an existing swarm, point `-boot` at one or more known peers. To start a
  new swarm, run the first relay with no `-boot` and give its address to others.
- **Firewall (ufw):** `sudo ufw allow 64512/udp && sudo ufw allow 64513/tcp`. Leave
  the health port (`8080`) closed — bind it to `127.0.0.1`.

### Running several relays (mesh them)

More independent relays across different networks/operators = more resilience and
path diversity. To link them into one swarm, give each one another's public address
via `-boot`:

- Relay **A**: `-boot B_PUBLIC_IP:64512`
- Relay **B**: `-boot A_PUBLIC_IP:64512`

They discover each other and merge into a single swarm; a client that reaches **any**
relay reaches the whole network. Point clients at all of them for redundancy:

```go
swarmsync.Options{ BootstrapPeers: []string{"A_PUBLIC_IP:64512", "B_PUBLIC_IP:64512"} }
```

(Two public relays link over UDP discovery — no TCP bridge needed. Bridges are for
pulling *NAT'd* nodes into the swarm.)

## Health & metrics

With `-http :8080` (default in Docker):

- `GET /healthz` → `200 ok` (used by the container `HEALTHCHECK`).
- `GET /stats` → JSON: node ID, uptime, forwarding counters, and peer-table
  health. Contains **no message contents** — only aggregate activity.

```bash
curl -s localhost:8080/stats | jq
```

The process also logs a periodic one-line summary (peers, forwarded/received,
stored, dropped, excommunicated).

## Notes

- The relay is part of the SyncSwarm SDK Go module, which is why the Docker build
  context is the repo root. If the relay is later split into its own repository,
  drop that coupling and pin a released SDK version.
- Stopping is graceful: on `SIGINT`/`SIGTERM` the node flushes and shuts down.
