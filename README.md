# SyncSwarm

A decentralized, privacy-respecting data-transfer SDK for Go. Inspired by
BitTorrent's distributed approach and I2P/Tor-style onion routing, but designed
to be embedded directly in your application — **no central server, no separate
daemon, just a library**.

Data you send is **encrypted, split into fragments, spread across multiple relay
nodes, and reassembled only at the intended recipient** — so no single relay ever
holds the whole message or sees both endpoints.

> **Status:** the transport SDK is feature-complete and well-tested (135+ tests,
> race-clean), but young and **unaudited**. Read [`THREAT_MODEL.md`](THREAT_MODEL.md)
> before relying on it for anything sensitive, and see [`ROADMAP.md`](ROADMAP.md)
> for what's shipped vs. deferred. For the planned messenger reference app, see
> [`MESSENGER.md`](MESSENGER.md).

---

## How it works

```
 your bytes
     │  seal each fragment with AES-256-GCM (developer key)
     ▼
 [f0][f1][f2] … ──▶ Reed–Solomon shards (data + parity)
     │  wrap each shard in one encryption layer per hop
     ▼
 sender ──▶ relay A ──▶ relay B ──▶ … ──▶ recipient
            (peels 1)   (peels 1)         (peels last, reassembles, opens)

 • Each relay learns only its previous and next hop — never the payload,
   never both endpoints.
 • Any DataShards-of-(DataShards+ParityShards) fragments reconstruct the message.
 • The recipient acknowledges over a single-use anonymous reply block, so it
   never learns who sent it.
```

The same primitives compose into circuit relays (NAT traversal), on-disk
store-and-forward (offline delivery), block-wise streaming (large files), and a
Kademlia DHT (finding peers at scale).

## Features

- **Decentralized** — nodes find each other via UDP broadcast, a bootstrap peer
  list, gossip peer-exchange, and a **Kademlia DHT** for structured lookup at
  scale. No coordinator.
- **Self-authenticating identities** — a node's ID is derived from its persistent
  Ed25519 key (`NodeID()`); it can't be impersonated, and every packet is signed.
- **End-to-end encryption** — each fragment is sealed with AES-256-GCM under a
  developer-supplied key. Relays and interceptors see only ciphertext.
- **Erasure coding** — optional Reed–Solomon (`DataShards`/`ParityShards`): the
  message survives up to `ParityShards` dropped or lost fragments.
- **Onion routing & sender anonymity** — with `HopCount >= 1`, fragments are
  wrapped in per-hop layers; the destination can't learn who sent it, and
  acknowledges via a single-use anonymous reply block.
- **Streaming large payloads** — `SendStream` erasure-codes and sends an
  `io.Reader` block by block, so neither end buffers the whole payload.
- **NAT traversal (circuit relays)** — a node behind NAT (`NeedsRelay`) stays
  reachable by holding a persistent connection to a relay that forwards to it.
- **Offline store-and-forward** — a relay (`StoreForward`) holds messages for an
  offline recipient **on disk** (surviving relay restarts) and delivers them when
  the recipient returns, whether it reserves a circuit or just comes back online.
- **Reliability** — redundant paths, and optional confirmed delivery
  (`ConfirmDelivery`) with authenticated acks and resend.
- **Traffic-analysis defenses** — optional cover traffic, size padding, and relay
  jitter (`CoverTraffic`, `PadCellSize`, `RelayJitter`).
- **Sybil/eclipse resistance** — subnet-diverse relay selection, a bounded,
  bootstrap-protected peer table, and availability scoring that excommunicates
  relays that silently drop traffic (`RelayScoring`).
- **Observability** — activity counters (`Stats()`), peer-table health
  (`PeerHealth()`), and opt-in node-local hop tracing (`HopTrace()`).

## Installation

```bash
go get github.com/APoniatowski/syncswarm
```

Requires **Go 1.24+**. The public API lives in the `swarmsync` package; everything
under `internal/` is implementation detail.

## Quick start

```go
package main

import (
	"fmt"
	"log"

	"github.com/APoniatowski/syncswarm/swarmsync"
)

func main() {
	// A 32-byte AES-256 key shared out-of-band by all nodes that should be able
	// to read each other's messages. Load a real, secret key in production.
	key := make([]byte, 32)

	node, err := swarmsync.New(swarmsync.Options{
		StorageDir: "./data", // holds the node's persistent identity + chunks
		Key:        key,
		OnDataReceived: func(data []byte) {
			fmt.Printf("received: %s\n", data)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := node.Start(); err != nil {
		log.Fatal(err)
	}
	defer node.Stop()

	// Share this with peers out-of-band; they address you by it.
	fmt.Println("my node id:", node.NodeID())

	node.Send([]byte("hello, swarm")) // broadcast to the group
	select {}
}
```

### Runnable examples

The [`examples/`](examples/) directory has three self-contained programs you can
run as multiple instances on one host or across machines:

- **`secure_send`** — addressed, encrypted, confirmed delivery to a specific node.
- **`file_sync`** — directory synchronization over the swarm.
- **`realtime_sync`** — continuously shared state between instances.

See [`examples/README.md`](examples/README.md) for how to wire instances together
with `-disc`/`-boot` ports.

## Identity & addressing

A node's identity is **derived from its Ed25519 public key** and persisted in
`StorageDir`, so it is stable across restarts and cannot be claimed by any other
node. Read it with `node.NodeID()` and share it out-of-band (like a Tor `.onion`
or I2P `.b32` address). Peers address you by that ID:

```go
node.SendTo([]byte("hi"), recipientNodeID)
```

> `Options.NodeID` is **deprecated and ignored** — identity is always key-derived.

## Sending data

```go
// Broadcast to the whole group.
node.Send([]byte("data"))

// Send to a specific node by its key-derived NodeID.
node.SendTo([]byte("data"), recipientNodeID)

// Send a gob-encoded value (register concrete types with gob.Register).
node.SendVariable(myStruct)
node.SendVariableTo(myStruct, recipientNodeID)
```

### Streaming large payloads

`Send`/`SendTo` buffer the whole payload in memory. For large files or media,
`SendStream` cuts an `io.Reader` into independently erasure-coded blocks so the
**sender** never buffers more than about one block. It requires a `Key` and
erasure coding.

```go
sender, _ := swarmsync.New(swarmsync.Options{
	StorageDir: "./sender", Key: key,
	DataShards: 4, ParityShards: 2,
	StreamBlockSize: 4 << 20, // 4 MiB blocks (default)
})

f, _ := os.Open("big.bin")
defer f.Close()
sender.SendStream(f, recipientNodeID) // fire-and-forget (no end-to-end ack yet)
```

On the **receiver**, provide `OnStreamReceived` to flush completed blocks straight
to a writer (a file, a pipe) — bounding receive memory too:

```go
recipient, _ := swarmsync.New(swarmsync.Options{
	StorageDir: "./recipient", Key: key,
	OnStreamReceived: func(id [32]byte) io.WriteCloser {
		f, _ := os.Create("received.bin")
		return f // blocks are written in order, then Close is called
	},
})
```

Without `OnStreamReceived`, a streamed transfer is buffered and delivered via
`OnDataReceived` instead (correct, but not memory-bounded on receive).

Set `ConfirmDelivery` and `SendStream` blocks until the receiver acknowledges the
whole stream (returns `nil` only when it's fully reassembled and flushed).

**Resumable transfers:** `SendStreamResumable(r io.ReadSeeker, nodeID, streamID)`
gives a transfer a stable identity, so if a send is interrupted, calling it again
with the same `streamID` (and a fresh reader over the same content) **skips the
blocks the receiver already has** and finishes — the receiver retains its partial
progress and tells the sender where to resume. Direct path; the recipient must be
directly reachable.

```go
sender.SendStreamResumable(file, recipientID, "file:"+sha) // retry-safe; resumes where it left off
```

## End-to-end sealing to a recipient (no shared key)

`Key` is a **shared** secret — every node holding it can open fragments. For true
**per-recipient** end-to-end encryption, set `SealToRecipient`: a targeted `SendTo`
then seals fragments to the destination's public key, and only that recipient can
open them — with **no shared secret to distribute**, and nothing for your app to
build on top:

```go
sender, _ := swarmsync.New(swarmsync.Options{
	StorageDir:      "./sender",
	SealToRecipient: true, // seal each targeted send to the recipient's key
})
sender.SendTo(secret, recipientNodeID) // only recipientNodeID can decrypt it
```

The recipient opens it automatically with its node key — it doesn't need any
matching option or shared key. It composes with erasure coding, onion routing,
and streaming (each shard is sealed to the recipient), and works whether or not a
shared `Key` is also set. Applies to targeted `SendTo`/`SendStream` (not broadcasts).

**Post-quantum:** add `PostQuantum: true` and sealing uses a hybrid
**X25519 + ML-KEM-768** KEM (`crypto/mlkem`), sealed to the recipient's advertised
ML-KEM key. Content stays confidential as long as *either* primitive is unbroken —
resisting "harvest-now-decrypt-later" while keeping classical security. Nodes
advertise an ephemeral ML-KEM public key when this is set; peers without one fall
back to classical X25519 sealing.

## Anonymous, reliable delivery

Set the individual knobs, or start from a **preset** and adjust:

```go
// A coherent bundle for maximum anonymity; then fill in the rest.
opts := swarmsync.Preset(swarmsync.ProfileAnonymous) // hops, redundancy, cover, padding, jitter, scoring
opts.StorageDir = "./data"
opts.Key = key
opts.DataShards, opts.ParityShards = 4, 2 // Reed–Solomon: survive 2 lost fragments
opts.ConfirmDelivery = true               // wait for an authenticated ack, resend on timeout
node, _ := swarmsync.New(opts)
```

Presets: `ProfileDirect` (fast, non-anonymous), `ProfileBalanced` (one hop,
redundant — a good default), `ProfileAnonymous` (multi-hop + cover traffic +
padding). They set only the privacy/reliability fields; the default *choice* is
yours.

With `HopCount >= 1` (and relays available), `SendTo` is **anonymous**: the
recipient cannot learn the sender's identity or address, and its acknowledgement
routes back over a single-use anonymous reply block. `HopCount = 0` sends directly
and reveals sender↔recipient at the IP layer.

If `HopCount >= 1` but **no relay is available**, delivery is preferred over
anonymity by default: the send falls back to a direct connection (revealing the
sender to the recipient). Set `StrictAnonymity: true` to make that case fail with
an error instead of silently sending in the clear — for both `SendTo` and
`SendStream`.

### Non-blocking sends

With `ConfirmDelivery`, `Send`/`SendTo` block until the recipient's ack (or the
resend budget is exhausted). To trigger a confirmed send from a UI thread without
freezing it, use the async variants and get the outcome via callback:

```go
node.SendToAsync(data, recipientNodeID, func(err error) {
	if err != nil { /* show "failed to send" */ } else { /* mark delivered */ }
})
```

## Reaching NAT'd nodes & offline recipients

```go
// A well-connected node offering to relay and hold messages for others.
relay, _ := swarmsync.New(swarmsync.Options{
	StorageDir: "./relay", Key: key,
	Relay:        true, // forward traffic for other nodes
	StoreForward: true, // hold messages for offline recipients (persisted to disk)
	RelayScoring: true, // challenge relays; route around silent droppers
})

// A node that may or may not be behind NAT: let it figure out reachability.
client, _ := swarmsync.New(swarmsync.Options{
	StorageDir: "./client", Key: key,
	AutoRelay:      true, // AutoNAT: auto-hold reservations only if unreachable
	BootstrapPeers: []string{"relay.example.com:64512"},
	OnDataReceived: func(b []byte) { /* ... */ },
})

// Or force it, if you already know the node is unreachable directly:
//   NeedsRelay: true
```

**AutoNAT (`AutoRelay`)** removes the guesswork: the node periodically asks peers
to connect back to its data port; if it concludes it's unreachable, it
automatically holds circuit reservations with relays (and drops them if it becomes
reachable again). `NeedsRelay: true` still forces reservations unconditionally.
Either way, reachability needs at least one reachable relay in the swarm.

Store-and-forward composes with circuit relays: a message for an offline node
queues at a relay and is delivered when the node returns — either over a circuit
it reserves (if it's NAT'd) or by direct redelivery (if it comes back reachable).

## Finding peers (DHT)

Small swarms discover everyone via broadcast and gossip. At scale, a Kademlia DHT
provides structured `NodeID → address` lookup: you can locate a peer that isn't in
your local table by iteratively querying successively closer nodes.

**You usually don't need to call this yourself** — `SendTo` (and the async
variants) transparently run a DHT lookup when the destination isn't already known,
so having a node's ID is enough to reach it:

```go
node.SendTo(data, someNodeID) // resolves someNodeID via the DHT if needed
```

`FindNode` is still available to pre-resolve or check reachability explicitly:

```go
if node.FindNode(someNodeID) { /* now known locally */ }
```

## Connection-agnostic discovery (bridges)

Discovery is medium-agnostic: nodes **announce** themselves and transport nodes
flood those announces (with de-duplication and a hop cap), while **path requests**
locate a destination you have no route to. On a LAN this needs no configuration.
Across the internet, a broadcast can't reach another network, so open a **bridge**
— a persistent TCP link over which announces and path requests cross subnets, with
no DNS or central server:

```go
// A reachable transport node accepts bridges:
relay, _ := swarmsync.New(swarmsync.Options{Relay: true, BridgeListen: ":64513"})

// A node behind NAT bridges to it; it now discovers (and is discovered by) the
// whole swarm reachable through that relay:
node, _ := swarmsync.New(swarmsync.Options{BridgePeers: []string{"relay.example.net:64513"}})
```

Once a peer is known, `SendToLink` opens an **encrypted Link** to it — an
ephemeral, forward-secret session authenticated to the peer's node identity, with
no shared key, erasure coding, or onion routing:

```go
node.SendToLink(peerID, []byte("confidential"))
```

## Observability

```go
// Aggregate activity counters.
s := node.Stats()
fmt.Println(s.FragmentsSent, s.FragmentsForwarded, s.FragmentsDelivered,
	s.PacketsDropped, s.AcksConfirmed, s.Excommunications)

// Peer-table composition and lifetime churn.
h := node.PeerHealth()
fmt.Printf("%d peers (%d active) across %d subnets\n", h.Total, h.Active, h.Subnets)

// Opt-in, node-local hop trace (set Options.TraceHops = true first).
for _, ev := range node.HopTrace() {
	fmt.Printf("%s %s %s\n", ev.Time.Format(time.RFC3339), ev.Role, ev.Detail)
}
```

> Hop tracing is **node-local by design**: no correlation identifier crosses relays
> on the wire, so it never de-anonymizes forwarded traffic. Operators stitch a
> picture together out of band.

## Options reference

| Field | Meaning |
|---|---|
| `StorageDir` | Directory for the persistent identity key, stored chunks, and offline queue (defaults to a temp dir). |
| `Key` | Optional 32-byte AES-256 key; when set, every fragment is sealed. Required for erasure coding and streaming. |
| `SealToRecipient` | Per-recipient end-to-end sealing for targeted sends — no shared key needed. |
| `PostQuantum` | With `SealToRecipient`, seal via hybrid X25519 + ML-KEM-768 (post-quantum). |
| `Group` | Optional group name for `Send`/`SendVariable` broadcasts. |
| `OnDataReceived` / `OnVariableReceived` | Delivery callbacks for raw bytes / gob values. |
| `OnStreamReceived` | Returns an `io.WriteCloser` to flush an incoming streamed transfer into (bounds receive memory). |
| `BootstrapPeers` | `host:port` UDP addresses of known peers to join beyond the LAN. |
| `BridgePeers` | `host:port` TCP addresses of transport nodes to bridge to, so discovery (announces/path requests) crosses subnets without DNS. |
| `BridgeListen` | `host:port` to accept inbound bridges on (the reachable transport-node role). |
| `HopCount` | Intermediary relay hops per fragment (`0` = direct, non-anonymous). |
| `StrictAnonymity` | Fail an anonymous send when no relay route exists instead of degrading to a direct (sender-revealing) send. |
| `Redundancy` | Independent paths each fragment is sent over. |
| `DataShards` / `ParityShards` | Enable Reed–Solomon erasure coding (requires `Key`). |
| `SubChunkSize` | Wire cap per fragment; larger shards are split into transport sub-chunks (default 4 MiB). |
| `StreamBlockSize` | Per-block plaintext size for `SendStream` (default 4 MiB). |
| `ConfirmDelivery` | Wait for an authenticated ack and resend on timeout (targeted sends). |
| `Relay` | Advertise willingness to forward traffic for others. |
| `NeedsRelay` | Force circuit reservations: this node is unreachable directly. |
| `AutoRelay` | AutoNAT — detect reachability by dial-back and auto-hold reservations only when needed. |
| `StoreForward` / `StoreForwardTTL` | As a relay, hold messages for offline recipients (persisted to disk). |
| `CoverTraffic` / `PadCellSize` / `RelayJitter` | Traffic-analysis defenses (opt-in). |
| `RelayScoring` / `RelayStrikeLimit` / `RelayPenance` | Challenge relays and excommunicate silent droppers, routing around them. |
| `TraceHops` / `TraceSize` | Enable a bounded, node-local hop-event trace readable via `HopTrace()`. |
| `DiscoveryPort` / `DataPort` | UDP/TCP ports (`0` = well-known default, negative = ephemeral). |

## API reference

**Lifecycle:** `New(Options)`, `Start() error`, `Stop() error`.

**Identity & ports:** `NodeID() string`, `DiscoveryPort() int`, `DataPort() int`.

**Sending:** `Send([]byte)`, `SendTo([]byte, nodeID)`, `SendAsync`/`SendToAsync`
(non-blocking, callback outcome), `SendStream(io.Reader, nodeID)`,
`SendStreamResumable(io.ReadSeeker, nodeID, streamID)`,
`SendToLink([]byte, nodeID)` (forward-secret encrypted Link — no shared key/RS/onion),
`SendVariable(any)`, `SendVariableTo(any, nodeID)`.

**Config:** `Preset(Profile) Options` (`ProfileDirect`/`ProfileBalanced`/`ProfileAnonymous`).

**Discovery:** `SetBootstrapPeers([]string)`, `Bootstrap()`, `FindNode(nodeID) bool`.

**Observability:** `Stats() Snapshot`, `PeerHealth() PeerHealth`, `HopTrace() []HopEvent`.

## Architecture

| Package | Responsibility |
|---|---|
| `swarmsync` | Public SDK: node lifecycle and the send/receive API. |
| `internal/discovery` | Peer discovery (broadcast + bootstrap + gossip), latency, anti-eclipse peer table, DHT wiring. |
| `internal/dht` | Kademlia primitives: 128-bit XOR metric, k-bucket routing table, iterative node lookup. |
| `mobile` | Official gomobile-bindable facade over `swarmsync` for Android/iOS apps. |
| `internal/protocol` | Wire packet format, Ed25519 signing, key-bound `NodeID` derivation. |
| `internal/encryption` | AES-256-GCM sealing, X25519 hybrid sealing, onion build/peel, PQ-KEM seam. |
| `internal/fragment` | Chunking, per-fragment sealing, and Reed–Solomon erasure coding. |
| `internal/routing` | Fastest-route and subnet-diverse onion path selection. |
| `internal/transfer` | Forwarding, circuit relays, store-and-forward, streaming, acks, anonymity. |
| `internal/storage` | Filesystem chunk store and offline queue. |
| `internal/monitoring` | Activity metrics. |

## Security model

SyncSwarm defends **message content** and **sender anonymity** against passive
observers, malicious relays, impersonators, and (partially) Sybil operators. It
does **not** defend against a global passive adversary or the compromise of a
node's private key. Read [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full asset
list, adversary model, mechanisms, and known gaps before relying on it.

Key properties:

- Content is sealed with a **developer-supplied key** relays never hold — onion
  layers protect hop-by-hop, the content key protects end-to-end.
- Node identities are **key-bound** (`NodeID = hash(Ed25519 pubkey)`) and enforced
  on discovery, gossip, and DHT contacts, so identities can't be forged.
- Delivery acks are **unforgeable** (bound to the destination key or a secret
  token), so a third party can't falsely stop resends.

## Best practices

1. **Keys** — distribute `Key` securely out-of-band; it is the root of content confidentiality.
2. **Identity** — persist `StorageDir` so your `NodeID()` is stable; share it out-of-band.
3. **Anonymity** — set `HopCount >= 1` (with relays available) for sender-anonymous sends; `HopCount = 0` reveals sender↔recipient at the IP layer.
4. **Reliability** — combine `DataShards`/`ParityShards` with `Redundancy` and `ConfirmDelivery`.
5. **Large data** — prefer `SendStream` with `OnStreamReceived` over `Send([]byte)` to bound memory on both ends.
6. **Resource management** — always `Stop()` on shutdown.

## Testing & contributing

```bash
go test -race ./...
```

Contributions welcome — please open a PR and make sure the race suite passes.

## License

MIT License — see [LICENSE](LICENSE).

## Acknowledgments

- Inspired by BitTorrent's distributed architecture and I2P/Tor onion routing.
- Uses Reed–Solomon erasure coding (`github.com/klauspost/reedsolomon`).
- Uses Warhammer 40k litany-inspired confirmation protocols (see `internal/update`).
