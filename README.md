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
  (`PeerHealth()`), a peer listing (`Peers()`), and opt-in node-local hop tracing
  (`HopTrace()`).

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

### How many hops?

Fixed by default — `HopCount` is a number you choose, and the presets set it
(`ProfileDirect` 0, `ProfileBalanced` 1, `ProfileAnonymous` 2).

Set `AdaptiveOnionHops` and the count is derived per send from how many relays you
can see **in distinct subnets**:

| Distinct-subnet relays | Hops |
|---|---|
| 4 or more | 3 |
| 2–3 | 2 |
| 1 | 1 |
| 0 | send fails |

then clamped to `MaxOnionHops` (never above 3). If the result is below
`MinOnionHops` the send **fails** rather than routing with less anonymity than you
asked for. So `MinOnionHops: 3` on a swarm with two relay subnets fails every send
— that is the intended behaviour, not a bug, but set the floor to what your relay
network can actually supply.

Distinctness is by subnet, not by count: one operator running eight relays in a
single /24 counts as **one**, so adaptive mode will not build a path that merely
looks diverse. It is the same Sybil-resistance rule that governs relay selection.

Adaptive is usually the better choice for an application — it scales up as the
relay network grows, instead of hardcoding a number that is wrong at both ends of
the range.

**With a NAT'd destination**, the peer can only be entered through a relay it holds
a circuit reservation with, so that relay is pinned to the **exit** hop. Earlier
hops stay diverse — enabling `NeedsRelay` does not reduce your path to one hop —
but the achievable count is bounded by the relays you can *use*, not merely the
ones you can see.

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

## Interfaces & bridges: what they are and when to add one

Discovery is medium-agnostic: nodes **announce** themselves, transport nodes
**flood** those announces (de-duplicated, hop-capped), and **path requests** locate
a destination you have no route to. On a LAN this needs **no configuration**.

**A bootstrap peer and a bridge are different kinds of thing — not alternatives:**

- **`BootstrapPeers` is an address *hint*.** A few peers to contact on startup;
  after that, gossip fills your table. It reaches only what you can name, over UDP.
- **A bridge is a network *interface*.** It joins the set of interfaces the node
  floods announces and path requests over. Your LAN's UDP broadcast domain is one
  interface; a TCP bridge is another; a LoRa radio would be a third.

That distinction is why a bridge does four things bootstrap can't:

1. **Transitive** — announces cross a bridge, so a bridged node reaches peers whose
   addresses it never had. A bootstrap peer only reaches *that* peer (then gossip).
2. **Inbound flows back over the held connection** — the far side never has to dial
   you, so it works from behind NAT without a mapping to keep alive.
3. **Works where UDP is dropped** — corporate wifi, some carriers, captive portals.
   Those users can't bootstrap at all; an outbound TCP bridge still gets through.
4. **Not tied to IP** — the same interface seam (`internal/iface`) covers TCP, UDP,
   and (as stubs today) **LoRa/serial**. Bridges are the visible half of the
   connection-agnostic design; radio is the rest of it.

**When do you need one?** An ordinary IP deployment (public relay + `BootstrapPeers`,
or the default seed) needs **no bridge**. Add one when a node is behind NAT/UDP
filtering, or to knit two networks together. **Cost:** a bridge listener is a
**separate inbound TCP port** — it can't share the data port.

```go
// A reachable transport node accepts bridges on its own port (not the data port):
relay, _ := swarmsync.New(swarmsync.Options{Relay: true, BridgeListen: ":64514"})

// A node behind NAT / UDP filtering bridges to it, and now discovers (and is
// discovered by) the whole swarm reachable through that relay:
node, _ := swarmsync.New(swarmsync.Options{BridgePeers: []string{"relay.example.net:64514"}})
```

Peers reached *through* a bridge are first-class: unicast toward a non-adjacent
peer is routed by destination over the per-hop transport rather than addressed on
an interface, so such peers verify normally and can be routed to. (A bridge writes
to its single connection and ignores the address it is given, so an
interface-addressed probe would land on the bridge peer instead — which is what
previously left everything beyond a bridge permanently unverified.)

### Restricting who may bridge (`BridgePSK`)

A bridge listener accepts **every** connection by default. That is correct for a
public transport node — anyone bridging in must be able to attach — but it makes
the bridge host a privileged position: it sees the discovery metadata of everyone
attached to it (node IDs, addresses, timing) and could drop their traffic
selectively. It cannot read message contents; payloads are sealed end to end and
discovery packets are signed. What is exposed is *who is talking to whom*, not
what they said.

For a private deployment, set the same key on both ends:

```go
psk := loadKey() // 16+ bytes, from your own secret store

// Only holders of the key may attach:
relay, _ := swarmsync.New(swarmsync.Options{
    Relay: true, BridgeListen: ":64514", BridgePSK: psk,
})

// And the dialer must present it:
node, _ := swarmsync.New(swarmsync.Options{
    BridgePeers: []string{"relay.internal:64514"}, BridgePSK: psk,
})
```

`BridgePSK` applies to bridges in **both** directions — inbound (`BridgeListen`)
and outbound (`BridgePeers`) — and is re-proven on every reconnect. The check is
mutual, so a dialer also confirms it reached the intended bridge rather than an
impostor on the same address.

Leave it empty (the default) for a public bridge. The two ends must agree: a node
without the key can still open a TCP connection to a protected bridge, but the
bridge reads nothing from it and never registers it, which surfaces on the client
after 45s as `bridge "..." connected but received no traffic`.

This is access control, not confidentiality. Use it to decide *who may attach*;
it adds no secrecy that the Link and content layers do not already provide.

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
| `BridgePeers` | `host:port` TCP addresses of transport nodes to bridge to, so discovery (announces/path requests) crosses subnets without DNS. Pass `swarmsync.DefaultBridges` if you want a bridge but have no particular transport node in mind. Left empty by default: a bridge is a standing connection, so it stays opt-in rather than making the default hosts load-bearing. |
| `BridgeListen` | `host:port` to accept inbound bridges on (the reachable transport-node role). |
| `BridgePSK` | Pre-shared key gating who may attach a bridge, inbound and outbound; mutual, and re-proven on every reconnect. Empty (default) = open bridge, which is what a public transport node wants. Access control only — not confidentiality. Minimum 16 bytes; never pass it on a command line, where `ps` exposes it to every local user. |
| `AutoInterface` | Zero-config LAN discovery via IPv6 link-local multicast — nodes on the same physical network find each other with no bootstrap host or DNS seed. Additive; a host with no multicast interface is skipped, not fatal. |
| `LoRaDevice` / `LoRaBaud` | Join the mesh over the air via a serial LoRa modem (Reticulum RNode / Meshtastic / MeshCore in KISS mode) — no IP required. Serial backends for Linux and macOS; a networked RNode over TCP works on any OS via a custom interface. |
| `LoRaDutyCycle` / `SerialDutyCycle` | Limit radio transmissions to that fraction of airtime per hour (e.g. `0.01` for the 1% licence-free sub-GHz bands like EU 868 MHz permit). Sends over budget are refused with a back-pressure error rather than transmitted. 0 = unlimited (default). |
| `SerialDevice` / `SerialBaud` | Same for a generic KISS/serial radio modem (TNC, packet radio). |
| `ReliableLinkTransfer` | Route node-addressed `SendTo` through the reliable Resource-over-Link path (selective-ARQ) instead of the TCP transfer — delivers over any interface a Link reaches (bridge, LAN multicast, LoRa), not just a direct TCP dial. Off by default; onion routing unaffected. See also `SendToResource`. |
| `OnionOverLinks` | Carry onion-routed (forwarded/anonymous) traffic hop-by-hop over encrypted Links instead of direct TCP dials, so anonymous transfers reach relays only reachable via a bridge/radio and each hop is initiator-anonymous. Source-routed onion + reply-block ack unchanged. Off by default. |
| `PerHopRouting` | Send targeted transfers via per-hop transport routing (transport nodes forward toward the destination using their announce path tables) instead of source-routed onion — more efficient, and reaches destinations across bridges/radio. **Non-anonymous profiles only**: ignored under anonymity (`StrictAnonymity`/adaptive onion), so `ProfileAnonymous` always keeps onion. Falls back to onion/direct when no path is known. Off by default. |
| `HopCount` | Fixed intermediary relay hops per fragment (`0` = direct, non-anonymous). |
| `AdaptiveOnionHops` | Choose hop count per send from relay diversity (distinct subnets) instead of a fixed `HopCount` — "as anonymous as the swarm allows". Always fail-closed. |
| `MinOnionHops` / `MaxOnionHops` | Floor (below it a send fails) and ceiling (cap 3) for `AdaptiveOnionHops`. |
| `StrictAnonymity` | Fail an anonymous send when no relay route exists instead of degrading to a direct (sender-revealing) send. |
| `Redundancy` | Fixed number of independent paths each fragment is sent over. |
| `AdaptiveRedundancy` | Scale independent paths with relay diversity (distinct subnets) instead of a fixed `Redundancy` — resilience grows as the network grows. |
| `MinRedundancy` / `MaxRedundancy` | Floor (thin-network protection) and ceiling (default 4) for `AdaptiveRedundancy`. |
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

**Observability:** `Stats() Snapshot`, `PeerHealth() PeerHealth`, `Peers() []PeerInfo`,
`HopTrace() []HopEvent`.

`PeerHealth()` gives the aggregate shape of the peer table (counts, subnet spread);
`Peers()` answers *who, specifically* — each peer's NodeID, address, data port,
last measured latency, liveness, and advertised capabilities, including peers that
have gone inactive. That last part matters: an inactive entry is usually the one
worth looking at when diagnosing a partition.

**What `Active` means: liveness is first-hand.** A peer is only marked active once
*this* node has exchanged an authenticated round trip with it — a latency check
whose reply is signed by that exact peer. Hearing about a peer from somewhere else
never makes it active: not gossip, not a DHT contact list, not an announce that was
re-flooded by a transport node. Those contribute *candidates* and metadata, and the
peer is promoted only after it answers directly.

That is deliberate. A node that is merely *claimed* to be alive can be selected as
an onion hop, and traffic sealed to a departed node's key is then silently
black-holed — a failure with no error anywhere. The practical consequence for
callers: a freshly discovered peer can take up to one latency round (~30s) to
become usable, so a `SendTo` immediately after discovery may need a retry.
`ConfirmDelivery` is the reliable way to know a send actually arrived.

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

### Forward secrecy: what survives a later key compromise

The question that matters for a passive recorder is not whether the ciphertext can
be broken — it cannot — but what a *later* key seizure retroactively unlocks.
Stated plainly, per layer:

| Layer | Keyed by | Recorder later seizes the **sender's** key | …the **recipient's / relay's** key |
|---|---|---|---|
| Content seal (`SealToRecipient`) | fresh ephemeral X25519 → recipient's **long-term** node key | Safe — the ephemeral is discarded and never stored | **Recovers every recorded transfer to that node** |
| Post-quantum (`PostQuantum`) | fresh ephemeral + fresh ML-KEM-768 encapsulation → recipient's **static** KEM key | Safe | **Recovers them**, same as above |
| Onion layers / reply block | fresh ephemeral → each relay's **long-term** node key | Safe | **That hop's layers peel**, revealing next-hop addresses |
| Link (`SendToLink`, `ReliableLinkTransfer`) | ephemeral ↔ ephemeral X25519, Ed25519 signature for authentication | Safe | **Safe** — no long-term key derives the session key |

So: every seal uses a **fresh ephemeral on the sender side**, which means no key is
ever reused across messages and compromising a sender reveals nothing about its
past traffic. But the fragment and onion paths seal *to long-term keys*, so they
are **not forward secret against compromise of the receiving side**. A recorder who
keeps traffic and later obtains a node's key can read what was sent to it; one who
obtains a relay's key can peel that relay's recorded layers and learn who was
talking to whom — a deanonymisation exposure, which is often the more damaging of
the two.

**Links are the exception, and the mitigation.** A Link's session key comes from an
ephemeral-to-ephemeral exchange authenticated by a signature, so no long-term key
derives it and seizing one later recovers nothing. Setting `OnionOverLinks: true`
carries onion hops inside Links: the blobs are still keyed to relay long-term keys,
but a passive recorder never captures them in the first place, so there is nothing
to peel later. If retrospective deanonymisation is in your threat model, turn it on.

There is **no ratchet and no key evolution** between two nodes. Each transfer is
independent with its own ephemeral, so nothing is reused — but nothing heals a
compromise either. An application needing forward secrecy at its own layer must
provide it there; the transport does not do it for you outside of Links.

### Traffic-shape notes

Ciphertext itself is **not repeatable**: every seal draws a fresh ephemeral key, so
the same message sealed twice shares no bytes at all. What *is* repeatable is
**size and timing**, and that is where correlation lives — not in the ciphertext.
Two defences address them, and both are opt-in:

- **`PadCellSize`** rounds every packet up to a cell boundary, so a short message
  and a long one are not separable by size. It now covers **acknowledgements** as
  well as data fragments and decoys. An ack is far smaller than a fragment, so
  leaving it unpadded made it the one packet an observer could classify by size
  alone — a reliable "this node just received something" marker.
- **`RelayJitter`** delays relayed packets by a random interval, including the
  delivery ack. Padding equalises what a packet looks like; jitter breaks *when* it
  appears. An ack emitted the instant a fragment lands pairs the two by timing no
  matter what size it is.

`ProfileAnonymous` sets both (`PadCellSize: 512`, `RelayJitter: 250ms`) plus
`CoverTraffic`. `ProfileBalanced` and `ProfileDirect` set neither, so if traffic
analysis is in your threat model set them explicitly — the cost is bandwidth on
small messages and a sub-second delay on acknowledgements, neither of which a user
perceives.

**What none of this defends against**: a global passive adversary who observes every
link simultaneously, or correlation by *volume* and long-run frequency. Padding and
jitter raise the cost of linking two endpoints; they do not make it impossible.

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
