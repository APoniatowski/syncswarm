# SyncSwarm Roadmap (Round 6+)

Priorities to take SyncSwarm from a *confidential multipath transport* toward a
*usable, anonymity-respecting network* — the gap surfaced by the I2P comparison.
Each item lists the owning agent (see `.claude/agents/`), why it matters, the
concrete work, and how we know it's done.

Ordering principle: **reachability and authenticated identity first** (the
difference between "LAN toy" and "usable on the internet"), then **anonymity
hardening** (the difference between "confidential" and "anonymous").

---

## ✅ Shipped

- **Confidential multipath transport**: onion-layered source routing, per-fragment
  AEAD sealing (developer key), Reed–Solomon erasure coding, redundant paths.
- **End-to-end delivery acknowledgement** with resend (`ConfirmDelivery`).
- **Configurable/ephemeral ports** + bootstrap/gossip discovery + live multi-node tests.
- **Round 6a — Keyed Ed25519 signing + key-bound identities** *(shipped)*:
  every packet is Ed25519-signed and self-authenticating; `NodeID` is derived from
  the node's Ed25519 public key (persistent, in `StorageDir`) and enforced on
  receipt (discovery, gossip), so impersonation requires the private key. Address
  peers by `SyncSwarm.NodeID()`.
- **Round 6b — Sender-anonymous return path (reply blocks)** *(shipped)*:
  forwarded data packets are now anonymous — no `SourceNode`, no identity
  signature (the onion's final-layer AEAD authenticates the bytes; content
  authenticity comes from the developer-key AEAD). The sender includes a
  **single-use onion reply block**; the destination acks by injecting that opaque
  blob at its entry relay, so it never learns the sender's identity or address.
  `ConfirmDelivery` rides this path transparently.
  *Residuals for later:* the last return-hop relay learns the sender's address
  (inherent to onion return paths, like an I2P inbound gateway); and dropping inner
  identity verification allows keyless relays to inject junk fragments that fail
  developer-key AEAD (a DoS vector, not a confidentiality break) — tracked in the
  threat model (6c).
- **Round 6c — Ack authentication + threat model** *(shipped)*:
  forged delivery acks can no longer stop a sender's resends. Direct acks are
  bound to the destination's Ed25519 key; anonymous (reply-block) acks are bound
  to a secret per-transfer token sealed to the sender (a forger who lacks it is
  rejected). Authored `THREAT_MODEL.md` (assets, adversaries, mechanisms, and the
  prioritized open gaps). *Still open:* wire a `/security-review` gate into CI
  (devops-release) — the doc exists; the automated gate does not yet.

---

## Round 7 — NAT traversal & reachability  ·  network-specialist  *(shipped)*
Delivered two mechanisms:
- **Circuit relay (reservations):** a node that can't accept inbound connections
  (`Options.NeedsRelay`) holds a persistent connection open to reachable relays and
  advertises them (`RelayIDs`). A relay forwards that node's inbound traffic back
  over the held connection instead of dialing it. Senders detect a destination's
  reservation relays and route the final hop through one. Proven by a mechanism
  test (relay forwards over the held conn, not a dial) and an end-to-end test
  (a `NeedsRelay` destination receives through its reservation).
- **Observed-address discovery:** latency replies echo the source address they saw,
  so a node learns its public (reflexive) address (`Discovery.ExternalHost()`) and
  uses it in reply paths instead of guessing its LAN IP.

*Residuals / follow-ups:* UDP/TCP hole punching (for direct P2P without a relay in
the path) and UPnP/NAT-PMP are not implemented — reservations cover reachability
but always route through a relay. Reserved **senders** (a NAT'd node *initiating*
and awaiting an ack) route acks through their own reservation only partially;
reserved **destinations** (inbound) are fully covered. Keepalive/backoff tuning
for real-world NAT timeouts is untested against live NATs.

## Round 8 — Anonymity hardening  ·  routing-specialist + security-auditor  *(shipped)*
Delivered three traffic-analysis defenses (all opt-in via `Options`):
- **Cover traffic** (`CoverTraffic`): a node emits decoy transfers at randomized
  intervals that are ordinary `PacketTypeRelay` packets routed through relays and
  silently dropped at the exit — indistinguishable from real traffic, so an
  observer cannot tell when the node is actually sending. Proven by a test showing
  a decoy is dropped, never delivered.
- **Padding** (`PadCellSize`): forwarded inner packets are padded up to a cell
  boundary so payload length is not inferable from packet size.
- **Relay jitter** (`RelayJitter`): relays delay forwarding by a random bound,
  blunting timing correlation.

*Residuals / follow-ups:* padding is now **exact** (binary framing shipped in P1 —
`padPacket` hits the cell boundary precisely). Cover traffic is still per-node and
un-shaped (not constant-rate); a global mix/batching strategy is stronger. And the
**persistent-circuit vs per-fragment-path** evaluation is still a design decision,
not yet made — per-fragment spreading remains the model.

## Round 9 — Sybil / eclipse resistance  ·  routing-specialist + security-auditor  *(shipped)*
Made Sybil flooding much harder (identities are cheap, so we raise the cost of
*controlling paths and tables* rather than of *making identities*):
- **Subnet-diverse relay selection** (`routing.BuildPath`): a path prefers relays
  in distinct IP /24 (or /48) subnets and distinct from the destination, so one
  operator running many nodes on a few ranges is unlikely to control a whole path.
  Soft preference with fallback so small/loopback swarms still build paths.
- **Anti-eclipse peer table** (`discovery`): caps non-bootstrap peers per subnet
  (`maxPeersPerSubnet`) and total (`maxPeers`), evicting the *stalest* over-cap
  peer — so a same-range Sybil flood can't evict honest peers in other subnets.
- **Bootstrap trust anchors:** peers sharing a bootstrap host are never evicted or
  capped, so a node can't be eclipsed away from its anchors.
- **Gossip flood cap** (`maxGossipAccept`): bounds peers merged from one gossip
  message. Proven by tests (subnet flood is capped; honest distinct-subnet and
  bootstrap peers survive).

**Availability scoring (excommunication)** *(shipped — `Options.RelayScoring`)*:
each relay is periodically challenged to forward a **self-addressed onion probe**
back to the prober. The probe's innermost layer is sealed to the prober's own key
and carries a random ID the relay cannot read, so a relay can only pass by
genuinely forwarding — it **cannot forge success**, and the test is attributable
to exactly one relay (no collateral blame). `RelayStrikeLimit` consecutive
failures (default 3) **excommunicate** the relay — excluded from all routing —
for `RelayPenance` (default 1h); a single success absolves it, and the ban lifts
into redemption after penance. Exposed via `Stats().Excommunications`. Proven by
a bookkeeping test and a real-socket round-trip (healthy relay passes; unreachable
relay fails).

*Residuals / follow-ups:* a **selective** dropper that forwards probes but drops
real traffic evades the challenge (probes are indistinguishable from real traffic
to a relay, but a relay that passes *everything* including probes and drops
*nothing* is honest by definition — the gap is a relay clever enough to detect the
self-loop pattern and pass only probes; longer probe paths would help). A Sybil
spread across *many distinct subnets* still evades subnet caps. Proof-of-work /
stake for identities is out of scope.

## Round 10 — Reliability & scale  ·  storage / segmentation / network / crypto  *(partially shipped)*
Shipped:
- **Offline store-and-forward** *(`Options.StoreForward`)*: a relay holds
  undeliverable fragments for an offline recipient (bounded per-recipient count +
  TTL), **persists them to disk** so they survive a relay restart (10.1), and
  delivers them when the recipient returns — either by **flushing over a circuit
  reservation** (NAT'd recipients) or by **redelivering directly** to a recipient
  that becomes reachable again without reserving (10.2). Composes with the Round 7
  circuit relay. Proven by unit tests (store → flush in order → bound → expiry →
  disabled → restart-recovery → direct redelivery → retain-on-failure) and the
  storage round-trip suite.
- **HKDF key derivation** *(`crypto`)*: the hybrid sealer now derives its AES-256
  key with HKDF-SHA256 (domain-separated extract-and-expand) instead of a bare
  hash — closing the long-standing `TODO`.
- **Observability** *(`internal/monitoring`)*: the empty package now provides a
  nil-safe metrics sink (fragments sent/forwarded/delivered, decoys dropped,
  offline stored, acks confirmed), wired into transfer and exposed via
  `SyncSwarm.Stats()`.

Still open (tracked checklist):
- [x] **10.1 — Persistent (on-disk) store-and-forward** *(shipped · storage)*.
      Held blobs are written under `<StorageDir>/offline/<nodeID>/<seq>.blob`
      (expiry-prefixed) on store and reloaded into the in-memory queue on startup
      (`transfer.loadOffline`), so a relay reboot no longer loses them. The
      sequence counter advances past recovered blobs; expired blobs are dropped on
      load. Backed by `storage.{SaveOffline,LoadOffline,DeleteOffline,DeleteOfflineNode}`.
- [x] **10.2 — Redelivery to non-reserving recipients** *(shipped · transfer)*.
      A background `redeliverOffline` loop retries held blobs against recipients
      that reappear in discovery *without* reserving a circuit, dialing them
      directly (`redeliverTo`) and clearing the queue on success (retaining it on
      failure). Reserved recipients still receive theirs via `flushOffline`, so the
      two paths cover NAT'd and directly-reachable recipients respectively.
      *Note:* delivery is at-least-once (a partial flush may resend earlier blobs);
      dedupe belongs at the application layer.
- [x] **10.3 — Sub-chunk large RS shards** *(shipped · segmentation)*.
      A fragment whose payload exceeds a per-fragment wire cap (`Options.SubChunkSize`,
      default 4 MiB) is split into transport-sized sub-chunks (`transfer.fragmentPieces`)
      carrying `(SubIndex, SubTotal)` on the packet; the receiver reassembles them
      (`absorbFragmentPieceLocked`) into the logical fragment *before* Reed-Solomon
      reconstruction, so no single packet is many megabytes. Applies to both the
      forwarded (onion) and direct streamed paths. *(Fixed a latent correctness bug
      surfaced here: `NewPacket` appended the timestamp onto the caller's payload
      backing array, corrupting a neighbouring sub-chunk that shared the buffer.)*
- [x] **10.4 — DHT discovery** *(shipped · network)*.
      A Kademlia layer adds structured `NodeID → address` lookup on top of the
      existing broadcast/bootstrap/gossip. The pure `internal/dht` package holds
      the 128-bit XOR metric, a k-bucket routing table, and the iterative
      node-lookup algorithm (transport-free, driven by a query callback). Discovery
      populates the table from every sighting, answers `FIND_NODE` queries with its
      k closest contacts, and `Discovery.FindNode(id)` (exposed as
      `SyncSwarm.FindNode`) runs an iterative lookup that locates a peer even when
      it is not in the local table — proven by a transitive test (A finds C via B
      without ever contacting C). A periodic self-lookup refreshes the buckets.
      *Caveats:* contact addresses are as-observed (DHT-behind-NAT is out of scope,
      like the transport's — NAT'd nodes remain reachable via circuit relays); the
      DHT augments rather than replaces the flat table.
- [x] **10.5 — Richer observability** *(shipped · monitoring)*.
      Three additions: (1) more counters — `FragmentsSent/Received/Forwarded/
      Delivered`, `PacketsDropped` — with the previously-unwired `IncSent` and a
      forward-success-only `IncForwarded` fixed, all via `Stats()`. (2) `PeerHealth()`
      — peer-table composition (active/inactive, distinct subnets, per-subnet
      distribution) and lifetime churn (joins/evictions). (3) `HopTrace()` — an
      opt-in (`Options.TraceHops`), bounded, **node-local** ring of hop events
      (send/receive/forward/deliver/decoy/drop).
      *Deliberate anonymity choice:* hop tracing is node-local only — **no
      correlation ID is attached to the forwarded wire format**, because an ID that
      travelled across relays would let any relay/observer link a transfer's hops
      and defeat unlinkability. Operators stitch traces together out of band in a
      trusted network; the naive "correlation IDs across relays" from this item's
      original wording is intentionally not implemented.

## Performance & efficiency (cross-cutting workstream)
Not privacy features, but the biggest levers for throughput/latency/footprint.
These are **implementation** costs (fixable in-place), distinct from the
**inherent** cost of anonymity (onion hops, redundancy, cover traffic).
- [x] **P1 — Binary wire framing** *(shipped)*. `protocol.Packet` now has a
      compact length-prefixed binary codec (`MarshalBinary`/`UnmarshalBinary`) with
      framed stream I/O (`WritePacket`/`ReadPacket`), and onion layers are binary
      too (killing the ~(4/3)^hops base64 blowup on multi-hop paths). Every wire
      boundary in `transfer` + `discovery` switched; sub-payload structs
      (`DiscoveryPayload`, `PeerExchangePayload`, `replyBlock`) stay JSON but now
      ride inside a binary `Packet.Payload`, so no base64. Also **unblocked exact
      fixed-size padding** (Round 8 residual): `padPacket` now hits the cell
      boundary precisely. Validated by the full multi-node suite under `-race`.
- [x] **P2 — Connection reuse** *(shipped)*. A keep-alive `connPool` (per-address,
      capped, TTL-reaped) reuses outbound connections for one-shot forwarded
      packets (relay/ack) instead of dial → send → close per fragment per hop. The
      receiver's `handleConnection` now drains multiple one-shot packets per
      connection. Removes the TCP handshake from the steady-state forward path.
      *Follow-ups:* true stream multiplexing / 0-RTT via **QUIC** (a bigger
      transport swap), and a global (not just per-address) connection cap.
- [x] **P3 — Streaming / bounded-memory transfers** *(shipped · segmentation)*.
      `SendStream(io.Reader, dest)` cuts the payload into fixed-size blocks
      (`Options.StreamBlockSize`, default 4 MiB), each independently Reed-Solomon
      encoded and emitted, so the **sender** never buffers more than ~one block.
      The **receiver** reconstructs per block and flushes completed blocks *in
      order* to `Options.OnStreamReceived`'s `io.WriteCloser` (buffering only the
      reordering window; without a sink it falls back to whole-payload buffering +
      `OnDataReceived`). Works over both the forwarded (onion) and direct paths and
      composes with sub-chunking. Wire: per-packet `Streaming`/`BlockIndex`/
      `BlockLen`/`Final` (length is unknown up front, so the last block is marked
      rather than counted). *Not yet:* end-to-end confirm-delivery for streams, and
      strict single-block receive bound (currently bounded by the reorder window).

## Round 11 — Product: the messenger  ·  messenger-app + media-specialist  *(in progress, separate repo)*
- Its prerequisites (authenticated identity, reachability, reliability) have all
  shipped in Rounds 6a–10, so it is unblocked.
- The **separate messenger repo** (`swarmmessenger`) is under way on top of the SDK.
- Text + file transfer first, then A/V (media-specialist).

---

## Reticulum alignment — connection-agnostic discovery & routing  ·  architect + network + protocol  *(epic, design complete)*
- **North star:** evolve from an IP-bound stack (UDP discovery + TCP transfer) toward
  the [Reticulum](https://reticulum.network) model — *connection-agnostic, advertise →
  flood → repeat* — so first contact no longer depends on DNS/a domain you own.
- Full design in **[RETICULUM_ALIGNMENT.md](RETICULUM_ALIGNMENT.md)**. Our identity
  core already matches Reticulum (Ed25519+X25519, 16-byte key-bound address, no source
  addr in forwarded packets); the gap is purely the transport/discovery/routing layer.
- **Scope: v1 = IP-ish media (UDP/TCP/I2P/Bluetooth).** LoRa/serial are stubbed to
  keep the seam open for a later bridge into **Reticulum RNode / Meshtastic / MeshCore**.
- Phases (each additive, messenger stays green): **P0** Interface abstraction
  (`internal/iface`; wrap current UDP/TCP sockets) → **P1** Announce + path table
  (`PacketTypeAnnounce`, controlled flood) → **P2** Path requests (drop the DNS-seed
  dependency) → **P3** per-hop routing per `Profile` (onion preserved for Anonymous)
  → **P4** `AutoInterface` zero-config LAN (IPv6 multicast) → **P5** MTU-driven sizing
  + light up the radio interfaces.
- **Landed:** `internal/iface` seam (Interface + UDP/TCP interfaces + LoRa/serial
  stubs, race-tested); **Phase 0a** — `Discovery` rewired onto `UDPInterface`,
  behavior-preserving; **Phase 1** — `PacketTypeAnnounce` + self-signed `AnnouncePayload`
  + flooded path table (dedup, hop cap 128, freshness, transport-only re-flood) with
  `PathTo`, alongside gossip/DHT; **Phase 2** — `PacketTypePathRequest` +
  `RequestPath`/`ResolvePath` (dest answers or transport re-announces cached path),
  wired into `transfer.resolveDest` (DHT → path request fallback); **multi-interface +
  TCP bridge** — `Discovery` holds many interfaces, broadcasts fan out across all,
  inbound merged; `AddBridge`/`AddListenBridge` + `Options.BridgePeers`/`BridgeListen`
  make announces cross subnets (proven: two nodes on distinct UDP ports discover via
  TCP); **unicast-over-bridge** — `nodeIface` routing sends latency/gossip/findnode over
  the interface a peer was heard on (bridged peers fully first-class; fallback to UDP
  keeps non-bridge behavior). All unit-tested -race; messenger green.
- **Link/session primitive landed** (`internal/link`): Reticulum Link — ephemeral
  encrypted session (X25519 ECDH + HKDF, forward secrecy, initiator anonymity, dest
  auth via signed proof, AES-GCM data), transport-agnostic, -race tested.
- **Links wired onto the real transport (via Discovery):** read loop dispatches Link
  packets to the link manager before the signature gate (self-authenticating, keeps
  initiator anonymity); `linkSend` routes via `addrIface`. `Discovery.Links()` exposes
  it. Proven by `TestLink_OverRealUDP` (encrypted session over real UDP, both ways).
- **Data over Links landed** (`swarmsync.SendToLink`): `link.SendMessage`/`Reassembler`
  chunk arbitrary payloads; `Discovery.DialNode` dials a known node; receiver delivers
  via `OnDataReceived`. Forward-secret, no shared key/RS/onion. Additive (TCP/onion path
  untouched), E2E tested over real UDP under -race.
- **Phase 0b remaining:** ride Links for the streaming/erasure-coded/onion transfer
  paths (needs a reliability/Resource layer + per-hop routing) and link reuse; optional
  frame-router split. Also unblocks per-hop routing (P3).
- Key invariant to keep honest: `ProfileAnonymous` MUST NOT build a shareable path
  table from onion traffic (asserted in tests). See THREAT_MODEL.

## SDK app-enablement  ·  architect + crypto  *(new workstream)*

Things a consuming app (the messenger, or any secure app) would otherwise
re-implement on top of the SDK. Building them into the SDK saves every downstream
developer the work. Sourced from reviewing what SwarmMessenger had to add; each is
tagged app-side (out of scope) or SDK-side with effort.

- [x] **Async / acked send API** *(shipped · quick win)*. `SendToAsync` /
      `SendAsync` run a (possibly `ConfirmDelivery`-blocking) send on a background
      goroutine and report the outcome via callback, so a UI can trigger a
      confirmed send from its event thread without freezing.
- [x] **Privacy presets** *(shipped · quick win)*. `Preset(Profile)` returns an
      `Options` prefilled with a coherent bundle of privacy/reliability knobs
      (`ProfileDirect` / `ProfileBalanced` / `ProfileAnonymous`), so callers don't
      hand-assemble HopCount/Redundancy/CoverTraffic/Pad into an incoherent mix.
      The **default choice** stays the app's policy.
- [x] **AutoNAT + auto-reserve** *(shipped)*. `Options.AutoRelay` enables a
      **dial-back protocol**: the node periodically asks a few peers to TCP-connect
      to its data port and report back (`PacketTypeReachabilityCheck` /
      `…Result`). A single external success ⇒ reachable; enough all-failures ⇒
      unreachable ⇒ it automatically holds circuit reservations (and drops them if
      it becomes reachable again). No manual `NeedsRelay` needed; a manually-set
      `NeedsRelay` still wins. Which relays to trust remains app/deployment policy.
- [x] **Transparent DHT addressing** *(shipped)*. `SendTo`/`SendData` to a NodeID
      that isn't currently active now runs a `FindNode` (10.4) automatically before
      failing (`transfer.resolveDest`), so "I have their ID" reliably becomes "I can
      reach them" — proven by an ID-only delivery test through a bridge node.
- [x] **Official gomobile binding** *(shipped)*. The `mobile` package wraps
      `swarmsync` with gomobile-safe types (an `EventSink` callback interface,
      JSON for lists, `SendFile`/`SendToAsync`), so apps get `.aar`/`.xcframework`
      bindings without hand-writing a facade and mis-plumbing `Options` fields.
- [x] **Recipient-public-key content sealing** *(shipped)*. `Options.SealToRecipient`:
      a targeted `SendTo` to a keyed node seals fragments to that node's public key
      (`encryption.NewHybridSealer` → ephemeral-X25519 + HKDF + AES-GCM) instead of
      a shared `Key`, and the receiver opens with its node key — **per-recipient E2E
      with no shared secret**, so apps needn't build their own crypto layer. Works
      through the RS/onion pipeline (the hybrid sealer plugs into the existing
      `Sealer` interface); proven by a no-shared-key delivery test and a
      wrong-key-can't-open test.
  - [x] *Streaming-hybrid* **(shipped)** — `SendStream` also seals per-recipient
        (each shard); proven by a receiver-with-no-shared-key test.
  - [x] *Post-quantum upgrade* **(shipped)** — `Options.PostQuantum` uses hybrid
        **X25519 + ML-KEM-768** (`crypto/mlkem`, `encryption.SealHybridPQ`) sealed
        to the recipient's advertised ML-KEM key, so content resists
        "harvest-now-decrypt-later" while keeping classical security if either
        primitive holds. Nodes advertise an ephemeral ML-KEM public key; falls
        back to classical X25519 for peers without one.
- [x] **Streaming delivery confirmation** *(shipped)*. `SendStream` now respects
      `ConfirmDelivery`: the receiver sends an end-to-end ack when the whole stream
      is reassembled/flushed (reply block or signed direct ack), and a confirmed
      `SendStream` blocks until it arrives.
  - [x] *Resumable streams* **(shipped)** — `SendStreamResumable(io.ReadSeeker,
        dest, streamID)`: a stable ID makes a retry the same transfer; the receiver
        **retains its partial assembler** across a dropped connection, and the
        init/ack handshake carries a **resume point** so the sender seeks and
        re-sends only the missing blocks. An idle TTL sweep reclaims abandoned
        partials. Direct path, in-memory retention; proven by an interrupt-then-
        resume test. *(Cross-restart persistence is a further follow-up.)*
- *App-side (not SDK):* read receipts (a "read" is an application concept); the
  concrete default-profile **choice** and the trusted-relay **list** (mechanism is
  SDK, policy is the app).

---

## Cross-cutting (ongoing)
- **DevOps**: `golangci-lint` + `go test -race` in `.forgejo/workflows/build.yml`;
  tagged releases. *(devops-release)*
- **Docs**: keep `README.md` and godoc honest against the API; runnable, CI-tested
  examples. *(docs-dx)*
- **Security review** before every release. *(security-auditor)*

---

## Suggested execution order

Sequenced for leverage — performance fixes that also unblock a privacy residual go
first, then the messenger-critical reliability refinements, then scale.

1. ~~**P1 — binary wire framing**~~ *(shipped)*. Dropped JSON + base64 bloat and
   unblocked exact fixed-size padding.
2. ~~**P2 — connection reuse**~~ *(shipped)*. Keep-alive pool removes the
   TCP-handshake-per-fragment-per-hop waste. (QUIC multiplexing is a later option.)
3. ~~**10.1 + 10.2 — persistent + general offline delivery**~~ *(shipped)*. The
   messenger-critical pair: held messages survive a relay restart (on-disk), and
   directly-reachable nodes that come back online (not just NAT'd reservers) get
   redelivery.
4. ~~**10.3 — shard sub-chunking**~~ *(shipped)*. Bounds per-packet size for large
   RS shards. **P3 (true streaming / bounded whole-transfer memory) remains open.**
5. ~~**10.5 — richer observability**~~ *(shipped)*. Counters, peer-table health,
   and opt-in node-local hop tracing (no cross-relay correlation ID, by design).
6. ~~**P3 — streaming / bounded-memory transfers**~~ *(shipped)*. `SendStream`
   emits block-wise RS; the receiver flushes blocks in order to a sink. Sender
   memory ≈ one block; receiver ≈ the reorder window.
7. ~~**10.4 — DHT discovery**~~ *(shipped)*. Kademlia XOR routing table +
   iterative `FIND_NODE`; structured `NodeID → address` lookup that scales past the
   flat table.
8. **Round 11 — the messenger app** *(next)* (separate repo). All SDK
   prerequisites have now shipped.

### Language / rewrite stance — **decided: stay on Go**
Go for now (widely adopted, strong fit: stdlib crypto, concurrency, single static
self-hostable binary), and the biggest wins (P1, P2) are in-place fixes, not a
language problem. **Benchmark after the roadmap work lands**, and only then weigh a
rewrite. The **inherent** cost of anonymity (onion hops, redundancy,
cover traffic) is algorithmic and no rewrite removes it. Revisit a rewrite — or an
FFI'd performance core — only if a **real-workload profile** demands it; if so,
**Rust** is the recommended target (no-GC latency for A/V, memory safety, mature
crypto + QUIC). Avoid C/C++ (memory-unsafe for a security product); BEAM/Elixir is
attractive for the messenger's coordination layer but not the data plane.
