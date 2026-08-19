# Reticulum Alignment — connection-agnostic discovery & routing

> **Status:** design / not yet implemented. This is the plan for evolving SyncSwarm
> from an IP-bound stack (UDP discovery + TCP transfer) toward the
> [Reticulum](https://reticulum.network) model: *connection-agnostic, coordination-free,
> advertise → flood → repeat*. It is written to be implementable directly, in phases
> that keep the SDK and the SwarmMessenger building green at every step.

## Why

The recurring pain in SyncSwarm's discovery story is that first contact depends on
something external and operator-owned (DNS seeds, a bootstrap IP, a domain you pay
for). Reticulum dissolves that: nodes **announce** themselves, transport nodes
**flood** those announces (rate-limited, deduplicated, hop-capped), and unknown
destinations are found with **path requests** — all over a medium-agnostic
**Interface** abstraction. "Bootstrap" stops being *DNS-and-a-domain* and becomes
*any interface that reaches one other node* (a TCP peer, a LAN multicast, a radio in
range). That is strictly more robust and less "relies on me."

## What we already share with Reticulum (the 80%)

The identity and session core is already Reticulum-shaped — this is a transport-layer
evolution, not a rewrite:

| Concept | Reticulum | SyncSwarm today | Gap |
|---|---|---|---|
| Identity keys | Ed25519 (sign) + X25519 (encrypt) | Ed25519 + X25519 | none |
| Address | 16-byte truncated SHA-256 of pubkey | `NodeID` = 16-byte SHA-256 of Ed25519 pubkey (`DeriveNodeID`) | none |
| No source addr in forwarded packets | yes (initiator anonymity) | yes (`buildInnerFragment` strips `SourceNode`) | none |
| E2E session | Link (ephemeral ECDH, forward secrecy) | sealed/streaming (ephemeral X25519 + HKDF) | minor |
| Large transfer | Resource | RS-coded chunk/stream transfer | none |
| Anyone can forward | `enable_transport = Yes` | `Relay` capability | none |

**The entire gap is the transport + discovery + routing layer.** That is what this
document addresses.

---

## Scope decision (2026-08-03)

**v1 targets IP-ish media** (UDP/TCP, and by extension I2P/Bluetooth-over-IP). Radio
(LoRa/serial) is **stubbed** — the seam is laid so that if the mesh model proves out we
can bridge into existing LoRa ecosystems without reworking the core:

- **Reticulum RNode** — bridging our physical layer to RNode framing makes SyncSwarm
  interoperable with Reticulum's radio layer.
- **Meshtastic** — ride its LoRa channels via the serial/BLE protobuf API.
- **MeshCore** — same idea, different framing.

Phase 5 (MTU-driven sizing) is the prerequisite for lighting the stubs up, since those
media have ~500-byte MTUs.

### Status

- **Pillar 1 seam — landed.** `internal/iface` with the `Interface` contract, working
  `UDPInterface` (configurable MTU), `TCPServerInterface`, `TCPClientInterface`, and
  `LoRaInterface`/`SerialInterface` **stubs** (`ErrNotImplemented`, `Frames()` yields a
  closed channel). Race-tested.
- **Phase 0a — Discovery wired onto `UDPInterface` — landed.** `Discovery` no longer
  owns a `*net.UDPConn`; it sends/receives through an `iface.Interface`. The read loop
  ranges over `Frames()` and re-resolves `frame.Addr` to a `*net.UDPAddr` so every
  handler is byte-for-byte unchanged. Behavior-preserving: the full integration suite
  (real UDP discovery, AutoNAT dial-back, DHT lookups, streaming) passes under `-race`,
  and the messenger is unaffected. This is what lets announces (P1) ride the same UDP
  port/interface.
- **Phase 1 — Announce + path table — landed.** `PacketTypeAnnounce` (12) +
  `protocol.AnnouncePayload` (self-signed: an inner Ed25519 signature over the
  immutable fields, independent of the packet signature, so it survives re-forwarding;
  `VerifyBound` checks key-binding **and** signature, so an announce cannot be forged
  for another node's ID). `Discovery` now floods a self-announce on the discovery tick
  and on Start; `handleAnnounce` verifies, learns the node into the peer table, records
  a path in a bounded LRU `pathTable`, dedups by `(DestHash,Nonce)`, honors freshness
  (newer `Timestamp` beats a shorter hop count), and re-floods (hop cap 128, randomized
  spread delay) only when this node is a transport (`relay` capability). `PathTo` exposes
  the learned next-hop for later phases. Runs alongside gossip/DHT. Unit-tested
  (learn/path, forged-rejected, self-ignored, dedup, freshness, transport-forward) under
  -race. **Note:** announces currently ride the UDP broadcast interface, so on IP they
  reach the local broadcast domain; cross-subnet flooding arrives with path requests
  (P2) and the TCP-client interface bridging.
- **Phase 2 — Path requests — landed.** `PacketTypePathRequest` (13) +
  `protocol.PathRequestPayload`. `RequestPath(destHash)` floods a query; a node that
  **is** the destination answers with a fresh self-announce, and a transport holding a
  **cached announce** for it re-floods that announce (hop-count bumped) back toward the
  requester — establishing a route with no DNS or bootstrap. Others (transports) flood
  the request one hop further (cap 128, deduped by `REQ:DestHash:Nonce`); endpoints drop
  it. `ResolvePath(destHash, timeout)` short-circuits when a path is known, else floods
  and waits. Wired into `transfer.resolveDest`: a targeted send to an unknown node now
  tries the DHT **and then** a path request (`pathResolveTimeout` = 2s) before failing —
  "have their ID" → "can reach them". Path entries now cache the announce so a transport
  can answer on behalf of the destination. Unit-tested under -race (dest-responds,
  transport-re-announces-cached, transport-forwards-unknown, endpoint-drops, dedup,
  resolve-short-circuit). Same broadcast-domain caveat as P1 until the TCP-client
  interface bridges subnets.
- **Multi-interface + TCP bridge — landed.** `Discovery` now holds a *set* of
  interfaces: the primary UDP (kept for unicast replies — zero regression) plus any
  bridges. Inbound frames from all interfaces are merged (`fanIn` → one `inbound`
  channel) and broadcasts (announces, path requests, discovery) fan out across **all**
  of them (`floodFrame`). `AddBridge(name, addr)` dials a transport node
  (`TCPClientInterface`); `AddListenBridge(name, listenAddr)` accepts inbound bridges
  (`TCPServerInterface`). Exposed via `Options.BridgePeers` (dial out) and
  `Options.BridgeListen` (accept). **This is what makes P1/P2 cross the internet:** two
  nodes that can't reach each other by UDP broadcast discover each other over a TCP
  bridge — proven by `TestBridge_CrossesBroadcastDomains` (distinct ephemeral UDP ports,
  mutual discovery via TCP, under -race).
- **Unicast-over-bridge — landed.** Bridged peers are now fully first-class, not just
  announce-discoverable: `Discovery` records which interface each node was last heard on
  (`nodeIface`, set per inbound packet and per announce) and routes **all unicast**
  (latency, gossip, findnode query + reply) via `ifaceFor(nodeID)`, falling back to the
  primary UDP interface for unknown nodes — so non-bridged behavior is unchanged. Proven
  by `TestBridge_UnicastCrossesBridge` (a latency check + reply round-trips over the TCP
  bridge, no shared UDP domain). *Follow-ups: precise bridged data-path addressing
  (Transfer/Link layer) and bridge auto-reconnect remain.*
- **Link/session primitive — landed (`internal/link`).** The Reticulum Link, built as
  a self-contained, transport-agnostic package (the same "seam first, wire later"
  approach as `internal/iface`). A `Manager` establishes ephemeral encrypted sessions
  over an injected `SendFunc` and is fed inbound link packets via `Deliver` (so a router
  can demux frames by type). Handshake: `PacketTypeLinkRequest` (initiator ephemeral
  X25519 + random link ID, **no initiator identity** — initiator anonymity) →
  `PacketTypeLinkProof` (responder ephemeral X25519 + Ed25519 signature over
  linkID‖ephPub, so the initiator **authenticates the destination**) → shared key via
  ECDH + HKDF bound to the link ID (**forward secrecy** — ephemeral keys). Data
  (`PacketTypeLinkData`) is AES-256-GCM with direction-tagged per-link nonces. Tested
  under -race: establish + bidirectional exchange, wrong-destination-key rejected,
  forged-frame rejected.
- **Links wired onto the real transport — landed.** `Discovery` now hosts the link
  `Manager` (created in `Start` when a signing key is set) and routes it over the
  interfaces: the read loop dispatches `Link*` packet types to `linkMgr.Deliver`
  *before* the packet-signature gate (link frames are self-authenticating and carry no
  packet signature, preserving initiator anonymity), and `linkSend` routes outbound link
  frames via `addrIface` (the interface an address was last heard on) with a primary-UDP
  fallback so a link can be dialed to a directly-addressable peer. Exposed as
  `Discovery.Links() *link.Manager`. Proven by `TestLink_OverRealUDP` (two nodes
  establish an encrypted session over real UDP and exchange data both ways, under -race).
  So encrypted sessions now ride the actual network (UDP today; bridges/multi-hop as the
  address routing fills in).
- **Data over Links — landed (`SendToLink`).** An application data path over the Link
  layer: `link.SendMessage`/`Reassembler` chunk and reassemble arbitrary-size payloads
  across link frames; `Discovery.DialNode(nodeID)` dials a known node (address + Ed25519
  key from discovery); `swarmsync.SendToLink(nodeID, data)` sends over a forward-secret
  Link and the receiver delivers via `OnDataReceived`. No shared content key, erasure
  coding, or onion routing — confidentiality/integrity come from the per-session Link key
  authenticated to the recipient's node identity. Additive (the TCP/onion transfer path
  is untouched), proven by `swarmsync.TestSendToLink` (E2E over real UDP, under -race).
  Best-effort for multi-frame payloads over a datagram transport (app layer
  confirms/retries). **Remaining:** ride Links for the *streaming/erasure-coded/onion*
  transfer paths (needs a reliability/Resource layer on Links and per-hop routing) and
  link reuse/caching; and optionally split interface ownership into a frame router.
- **Phase 0b — Transfer — deliberately deferred.** `Transfer` is connection-oriented
  (`Accept` → `handleConnection` streams many packets + acks over one conn; `net.Dial`
  + connection pool + held circuit reservations). That does not fit the frame-oriented
  `Interface` without a **Link/session layer** (Reticulum's Links). Migrating Transfer
  belongs with that layer, not with this phase — jamming a TCP-session protocol through
  `Send(addr,frame)`/`Frames()` would break streaming, pooling, and reservations. See
  the revised phase list below.

## Pillar 1 — The Interface abstraction (connection-agnostic)

Today the stack is welded to two sockets: `net.ListenUDP` in
[discovery.go:152](internal/discovery/discovery.go#L152) and `net.Listen("tcp", …)`
in [transfer.go:213](internal/transfer/transfer.go#L213). Reticulum puts every medium
behind one interface and lets the core route across whatever is available.

### New package: `internal/iface`

```go
// Interface is a bidirectional, framed transport over one medium. Implementations
// exist for UDP, TCP (client/server), and later LoRa, serial, I2P, Bluetooth.
type Interface interface {
    Name() string
    // Send delivers one frame. addr is medium-specific and opaque to the core
    // ("" = broadcast on media that support it, e.g. UDP/LoRa/AutoInterface).
    Send(addr string, frame []byte) error
    // Frames yields inbound frames with the medium-specific source address.
    Frames() <-chan InboundFrame
    Caps() Caps
    Close() error
}

type InboundFrame struct{ Addr string; Data []byte }

type Caps struct {
    MTU         int  // max frame payload in bytes (e.g. UDP ~1400, LoRa ~500)
    Bitrate     int  // approx bits/sec, for announce bandwidth capping
    Broadcast   bool // medium supports one-to-many (UDP/LoRa) vs point-to-point (TCP)
    FullDuplex  bool
}
```

First three implementations (wrapping code that already exists):

- `UDPInterface` — the current discovery socket, broadcast-capable. `Send("", f)` →
  `255.255.255.255:port`; `Send("host:port", f)` → unicast (today's
  `sendBootstrapDiscovery`).
- `TCPServerInterface` — the current transfer listener; accepts many peers.
- `TCPClientInterface` — dials a known transport node and stays connected (the
  internet-backbone bridge; also the graceful replacement for a "bootstrap peer").
- Later: `AutoInterface` (IPv6 link-local multicast → **zero-config LAN discovery**,
  Reticulum's flagship "just works" interface), `LoRaInterface`, `SerialInterface`.

### Core change

`Discovery` and `Transfer` stop owning sockets and instead take a **set of
interfaces**. A small `Router`/`Mux` fans inbound `InboundFrame`s to the packet
handlers by `PacketType`, and outbound packets are sent on the interface(s) the
router deems suitable (all broadcast-capable interfaces for announces; the
path-table's chosen interface for directed traffic).

This is the load-bearing change: once it exists, every other medium is an additive
`Interface` implementation, and announces/path-requests below are medium-agnostic for
free.

---

## Pillar 2 — Announce / Path-request discovery (advertise, flood, repeat)

Replaces the "DNS seed / bootstrap" model. Slots in **beside** the existing DHT
([internal/dht](internal/dht/)) — for direct-IP swarms the DHT stays the structured
overlay; announces build the path table and path requests replace cold DHT lookups on
media where a DHT is impractical (radio).

### New packet types (extend the enum in `internal/protocol/packet.go`; next free = 12)

```
PacketTypeAnnounce     = 12  // "I exist; here is my hash + pubkeys + signature"
PacketTypePathRequest  = 13  // "who has a path to <destHash>?"
```

A path *response* is just a re-flooded `Announce` for the requested destination, so no
third type is needed.

### Announce payload (reuse existing primitives — Ed25519 signing already in place)

```go
type AnnouncePayload struct {
    DestHash   []byte // 16-byte NodeID (already how we address)
    SignPub    []byte // Ed25519 public key  (verifies DestHash == DeriveNodeID(SignPub))
    KEMPub     []byte // X25519 public key    (for sealing to this node)
    MLKEMPub   []byte // optional ML-KEM-768 pub (already gossiped today)
    Caps       []string // "relay"/"transport", etc.
    AppData    []byte // small app hint (e.g. messenger display handle)
    HopCount   uint8  // incremented per forward; drop at HOP_MAX (128)
    Nonce      []byte // random, for dedup uniqueness
    Signature  []byte // Ed25519 over the above (minus HopCount, which is mutable)
}
```

Key-binding is already our trust root: a receiver **rejects any announce where
`DestHash != DeriveNodeID(SignPub)`** (same check `mergePeer` does today), so a
flooded/relayed announce cannot forge an identity even over a hostile medium.

### Propagation algorithm (Reticulum's rules, ported)

On receiving an announce, a **transport node** (`Relay`-capable):

1. **Dedup** — if `hash(DestHash‖Nonce)` seen recently, drop. (bounded LRU)
2. **Record path** — store `{DestHash → (interface, srcAddr, HopCount)}` in the
   path table; keep the lowest-hop entry, tie-break on freshness.
3. **Hop cap** — if `HopCount+1 > HOP_MAX (128)`, do not forward.
4. **Spread delay** — wait a randomized delay, then rebroadcast on *other* broadcast
   interfaces, `HopCount+1`.
5. **Bandwidth cap** — never let announce traffic exceed `ANNOUNCE_CAP` (2%) of an
   interface's `Caps.Bitrate`; queue/prioritize lower-hop announces.
6. **Retry** — if nobody is heard rebroadcasting within a window, retry `r` (=1) times.

Endpoints (non-transport) announce themselves periodically and on startup, but do not
forward others' announces.

### Path request

When a node wants to reach `destHash` and has no path-table entry and no active DHT
contact: emit `PacketTypePathRequest{destHash}` on all interfaces. Any transport node
holding a path replies by re-flooding that destination's last known announce toward
the requester (decrementing its own hop bias so the path converges back). This is the
medium-agnostic analogue of `discovery.FindNode` — and on IP media we can *first* try
the DHT and fall back to a path request, or run both.

### Path table

New `internal/routing` structure (next to the existing `Planner`):

```go
type PathTable struct { /* destHash -> []PathEntry, LRU-bounded */ }
type PathEntry struct { Iface string; NextHop string; Hops uint8; LastSeen time.Time }
```

Bounded by count and age (your "reasonable amount of routes" instinct — sized off
available memory, same spirit as the DHT's k-buckets).

---

## Pillar 3 — Per-hop routing that coexists with onion source-routing

**This is the one real philosophical tension, and we resolve it per-profile rather
than globally.**

- **Reticulum per-hop routing:** each transport node forwards one hop closer using its
  path table; simple, self-healing, works on 5 bps radio. Anonymity comes from *no
  source address* + *initiator-anonymous links*. Downside: transport nodes learn
  paths (a path table maps destinations to routes).
- **SyncSwarm onion source-routing (today):** the sender picks the whole path and
  layers encryption so no relay learns both ends. Stronger unlinkability; costs more
  bandwidth and requires the sender to know relays up front.

### Resolution: routing mode is a property of the existing `Profile`

| Profile | Discovery | Routing |
|---|---|---|
| `ProfileDirect` | announce/path table + DHT | per-hop (or direct) — cheap, self-healing |
| `ProfileBalanced` | announce/path table + DHT | per-hop, single relay |
| `ProfileAnonymous` | announce/path table for *reachability*, but path **chosen by sender** | **onion source-routing (unchanged)** — relays still learn only their next hop, and now the sender can *discover* candidate relays via announces instead of needing them preconfigured |

So announces improve `ProfileAnonymous` too (better relay discovery) **without**
weakening it — the sender still builds the onion; per-hop path tables are used only
where the profile already accepts that relays see routes.

> **Anonymity note (must stay honest):** enabling per-hop path tables means transport
> nodes in Direct/Balanced learn destination→route mappings. That is an *intended*
> trade for those profiles (they already reveal sender↔recipient at the IP layer or
> use a single relay). `ProfileAnonymous` MUST NOT populate a shareable path table
> from onion traffic. Enforce this with a routing-mode flag threaded from the profile,
> asserted in tests.

---

## Pillar 4 — Small-packet / high-latency media (the honest cost)

Reticulum targets **500-byte MTU, half-duplex, ≥5 bps**. Our transfer layer assumes
fat IP links: 4 MiB stream blocks, RS coding, 4 MiB sub-chunk caps. Two scopes:

- **IP-ish media (UDP/TCP/I2P/Bluetooth) — cheap.** MTUs are ~1400+; the existing
  sub-chunking (`fragmentPieces`, `Options.SubChunkSize`) already splits to a wire
  cap. Just drive the cap from `Interface.Caps.MTU` instead of a constant.
- **True radio (LoRa/serial, <500 B, seconds/packet) — a real phase.** Requires:
  MTU negotiation per interface; much smaller default block/sub-chunk sizes; tolerance
  of long round trips in the ack/resume logic (`streamAckTimeout`, reservation
  keepalives); and possibly deferring RS in favor of ARQ on the slowest links. This is
  a **re-architecture of the framing/erasure sizing**, not a bolt-on — scope it after
  Pillars 1–3 land.

Design rule going forward: **no hard-coded transport sizes** — every size derives from
the active `Interface.Caps.MTU`.

---

## Phased migration (messenger stays green at every step)

Each phase is additive and independently shippable. The messenger depends on the SDK
via `replace => ../../syncswarm`, so every phase must keep `go test ./...` green in
both modules.

- **Phase 0a — Interface seam + Discovery (no behavior change). ✅ DONE.** Introduce
  `internal/iface`; wrap the UDP socket as `UDPInterface`; `Discovery` consumes an
  interface instead of a raw socket. Everything behaves exactly as today.
  *Regression-tested against the full suite under -race.*
- **Phase 0b — Transfer onto interfaces. Deferred to the Link-layer phase.** Transfer
  is connection-oriented and needs a Link/session abstraction over frames before it can
  ride the interface model; do it there, not as a standalone refactor.
- **Phase 1 — Announce + path table. ✅ DONE.** `PacketTypeAnnounce` +
  `AnnouncePayload` (self-signed, forward-safe), `handleAnnounce` (verify → learn →
  path-record → dedup → freshness → transport re-flood), bounded LRU `pathTable`,
  `PathTo`. Alongside gossip/DHT. Unit-tested under -race.
- **Phase 2 — Path requests. ✅ DONE.** `PacketTypePathRequest` + `RequestPath` /
  `ResolvePath`; dest-answers or transport-re-announces-cached-path; wired into
  `transfer.resolveDest` (DHT then path request). Unit-tested under -race.
- **Phase 3 — Routing modes per profile.** Thread routing-mode from `Profile`;
  per-hop for Direct/Balanced, onion unchanged for Anonymous; assert the
  Anonymous-no-path-table invariant in tests.
- **Phase 4 — `AutoInterface` (zero-config LAN).** IPv6 link-local multicast interface
  → two SDK apps on the same network discover each other with no config at all.
- **Phase 5 — MTU-driven sizing + first radio interface.** Drive all transport sizes
  from `Caps.MTU`; add a `SerialInterface`/`LoRaInterface` and the small-packet
  tolerances. The big one; scoped last.

## Open decisions

1. **Do announces replace or complement gossip/DHT on IP media?** Recommendation:
   complement first (both run), measure, then consider retiring UDP gossip once
   announces prove out.
2. **Announce cadence & TTL** — start with periodic (e.g. 5 min) + on-change, path
   entries expire after N missed cadences.
3. **`Relay` vs a distinct `Transport` capability** — reuse `Relay` (a relay already
   forwards); "transport" and "relay" are the same role here.
4. **Radio scope** — is sub-500-byte radio actually a goal, or is "connection-agnostic
   across IP-ish media" enough for v1? This decides whether Phase 5 is in or out.

---

*Companion docs: [ROADMAP.md](ROADMAP.md) (status), [THREAT_MODEL.md](THREAT_MODEL.md)
(anonymity invariants). Reticulum references:
[Understanding Reticulum](https://markqvist.github.io/Reticulum/manual/understanding.html),
[Building Networks](https://reticulum.network/manual/networks.html).*
