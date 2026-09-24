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
| `-bridge-psk-file` | `SYNCSWARM_BRIDGE_PSK_FILE` | – | File holding a pre-shared key that gates **who may attach a bridge**, inbound and outbound. Empty = open bridge (the default). |
| – | `SYNCSWARM_BRIDGE_PSK` | – | The key itself, taking precedence over the file. Minimum 16 bytes. |
| `-bridge` | `SYNCSWARM_BRIDGE` | – | Open outbound discovery **bridges**. Bare `-bridge` uses the built-in default bridge hosts; `-bridge=host:64514[,...]` targets specific transport nodes. Omit it entirely for no bridge. **Note the `=`** — `-bridge host:64514` (space) is rejected, since a bare flag can't take a spaced value. |
| `-auto` | `SYNCSWARM_AUTO_INTERFACE` | `false` | Zero-config LAN discovery via IPv6 link-local multicast — peers on the same physical network find this relay with no `-boot`/DNS. Skipped (logged) on a host with no multicast interface. |
| `-lora` | `SYNCSWARM_LORA_DEVICE` | – | Serial LoRa modem (RNode / Meshtastic / MeshCore in KISS mode) to join the mesh over the air, e.g. `/dev/ttyUSB0`. Serial backend on Linux and macOS; empty = off. |
| `-lora-baud` | `SYNCSWARM_LORA_BAUD` | `0` | LoRa modem baud rate (0 = default 115200). |
| `-serial` | `SYNCSWARM_SERIAL_DEVICE` | – | KISS/serial radio modem (TNC, packet radio), e.g. `/dev/ttyS0`. Empty = off. |
| `-serial-baud` | `SYNCSWARM_SERIAL_BAUD` | `0` | Serial modem baud rate (0 = default 9600). |
| `-lora-duty` | `SYNCSWARM_LORA_DUTY` | `0` | Transmit duty-cycle limit as a fraction of airtime per hour (e.g. `0.01` for the 1% licence-free bands allow). Over-budget sends are refused, not transmitted. 0 = unlimited. |
| `-serial-duty` | `SYNCSWARM_SERIAL_DUTY` | `0` | Same, for the serial radio interface. |
| `-store` | `SYNCSWARM_STORE_FORWARD` | `true` | Hold messages for offline recipients. |
| `-store-ttl` | `SYNCSWARM_STORE_FORWARD_TTL` | default | How long to hold offline messages (e.g. `30m`). |
| `-relay` | `SYNCSWARM_RELAY` | `true` | Advertise this node as a relay that forwards for others. **Automatically suspended** while AutoNAT finds the node unreachable (see below), and resumed if that changes. Set `false` to run as a plain swarm participant. |
| `-scoring` | `SYNCSWARM_RELAY_SCORING` | `true` | Challenge peer relays; route around silent droppers. |
| `-http` | `SYNCSWARM_HTTP_ADDR` | – (`:8080` in Docker) | Health/metrics HTTP server (empty = off). |
| `-stats` | `SYNCSWARM_STATS_INTERVAL` | `1m` | How often to log a status line (`0` = never). |

There is **no content-key option** — a relay never needs one.

## Running behind NAT

A relay behind NAT with no forwarded ports **still joins the swarm** — give it
`-bridge` (bare, for the default hosts, or `-bridge=host:64514`) and its outbound
connection carries announces and path requests both ways. It is discovered, it
discovers, and it can send.

What it *cannot* do is relay: other nodes route through a relay by dialling its
data port, and nothing can dial into your LAN. The relay detects this itself —
AutoNAT concludes it is unreachable and **suspends the relay advertisement**:

```
relay: NOT reachable from the outside — suspending relay advertisement
       (check port forwarding/firewall for the data port); will resume automatically
```

That matters because an undialable relay that keeps advertising gets selected as
an onion hop, fails, wastes other nodes' paths and is eventually excommunicated —
so a misconfigured relay degrades the network rather than just itself. Suspension
is automatic and reversible: forward **TCP 64513** (and ideally **UDP 64512**) and
it resumes on its own, no restart needed.

*Known limitation:* the capability is advertised for the whole node, so a machine
that is reachable on its LAN but not from the internet is demoted for LAN peers
too. Tracked in `ROADMAP.md`.

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

### Restricting who may bridge

By default a bridge listener accepts every connection. That is deliberate for a
public relay — anyone running `-bridge` must be able to attach — but it means the
bridge host sees the discovery metadata of everyone attached to it (node IDs,
addresses, timing) and could drop their traffic selectively. It cannot read message
contents: payloads are sealed end to end and discovery packets are signed.

For a private relay, set a pre-shared key on **both** ends:

```bash
# on the relay accepting bridges
head -c 32 /dev/urandom | base64 > /etc/syncswarm/bridge.psk
chmod 600 /etc/syncswarm/bridge.psk
syncswarm-relay -bridge-listen :64514 -bridge-psk-file /etc/syncswarm/bridge.psk

# on a node bridging to it (same key)
SYNCSWARM_BRIDGE_PSK="$(cat bridge.psk)" syncswarm-relay -bridge=relay.example.net:64514
```

The check is mutual, so the dialer also confirms it reached the intended bridge
rather than an impostor on the same address, and it is repeated on every reconnect.

There is intentionally **no `-bridge-psk` flag**: a command line is readable by every
local user via `ps`, so a key passed that way would leak to anyone with a shell on
the host. Use the environment variable or a file with restrictive permissions.

A node without the key can still open a TCP connection, but the relay reads nothing
from it and never registers it. On the client side that shows up as:

```
discovery: bridge "..." connected but received no traffic in 45s — ... or requires
a bridge pre-shared key this node does not have
```

## If nothing can reach your relay

A relay that cannot accept inbound connections is worse than no relay: other nodes
keep selecting it as a hop, fail to dial it, and waste paths. AutoNAT detects this
and the relay suspends its own `relay` advertisement, resuming automatically when
reachability returns. Watch for either line in the log:

```
relay: reachable from the outside — advertising relay capability
relay: NOT reachable from the outside — suspending relay advertisement
```

**Seeing neither** means no verdict has been reached — usually too few peers to ask.

Two gotchas that produce a relay which looks healthy but carries nothing:

- **The cloud security list is not the only firewall.** On OCI the instance also has
  its own iptables rules, and the stock image accepts **only SSH**, rejecting the
  rest. A wide-open security list changes nothing by itself. Confirm on the host
  with `sudo iptables -L INPUT --line-numbers` and make sure the ACCEPT rules for
  64512/udp and 64513/tcp sit **above** the final REJECT.
- **UDP appearing to work proves nothing.** The stock chain accepts
  `RELATED,ESTABLISHED`, so replies to connections your relay *initiated* flow
  normally while genuinely inbound traffic is rejected. Discovery then looks fine —
  liveness is a UDP check — while data transfer, which needs inbound TCP on 64513,
  cannot work at all. Test from an unrelated host, not from a peer your relay
  already talks to.

## Health & metrics

With `-http :8080` (default in Docker):

- `GET /healthz` → `200 ok` (used by the container `HEALTHCHECK`).
- `GET /stats` → JSON: node ID, uptime, forwarding counters, a **`peers`** list
  (who this relay is actually talking to — NodeID, address, latency, liveness,
  capabilities), and peer-table
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
