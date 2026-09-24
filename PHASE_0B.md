# Phase 0b — Transfer over Links + the Resource/reliability layer

> **Status: all sub-phases (0b.1–0b.4) shipped; the default flip is deferred.** This
> was the last large architectural piece of the [Reticulum alignment
> epic](RETICULUM_ALIGNMENT.md): moving the data plane off raw TCP and onto the
> connection-agnostic [`internal/link`](internal/link) session layer, with a
> reliability layer on top. It was sequenced into additive sub-phases so the existing
> TCP path kept working (and the messenger stayed green) at every step. The Link path
> is complete and opt-in (`Options.ReliableLinkTransfer`, `Options.OnionOverLinks`);
> making it the default is a deployment call, not taken here (see 0b.4).

## Why

Discovery is already connection-agnostic (rides `internal/iface`; announces/path
requests flood over UDP, TCP bridges, LAN multicast, and now LoRa/serial). The
**data plane is not**: `internal/transfer` is TCP-oriented end to end —
`net.Listen`/`Accept` → `handleConnection(conn)` reading a packet stream, and
`net.Dial`/`connPool` → `WritePacket` to send (≈31 socket call sites). So a
transfer cannot cross a bridge, a LAN-multicast peer, or a radio link; it only
works where both ends share IP and one can dial the other.

Links close that gap — an encrypted, forward-secret, transport-agnostic session
over any `iface.Interface` — but they are **best-effort and unordered**: `SendMessage`
splits a payload into KISS/MTU-sized chunks (P5), and over a datagram/radio
transport a single lost chunk drops the whole message (`link/message.go` says as
much). Transfer needs guarantees Links don't provide yet. That missing piece is
the **Resource layer**.

## The gap (what to build)

| Transfer needs | Links give today | Resource layer adds |
|---|---|---|
| Reliable delivery over lossy media | best-effort chunks | per-part ACK + selective retransmit (ARQ) |
| Ordering / large payloads | whole-message reassembly in RAM | windowed, numbered parts; bounded memory |
| Integrity per part | AEAD per frame (whole msg) | per-part hash + whole-resource hash |
| A reusable return channel | one-shot `dataPayload` frames | the Link itself is bidirectional and reusable |
| Onion multi-hop (Anonymous) | point-to-point only | per-hop Link sessions, anonymity preserved |

Much of the segmentation math already exists and is reused, not rebuilt:
Reed–Solomon (`internal/fragment`), sub-chunking (`fragmentPieces`, 10.3), block-wise
streaming (`SendStream`/`streaming.go`, P3), and MTU-driven chunk sizing (P5). The
Resource layer is the **reliability envelope** around them, carried over a Link.

## Design

### 1. Resource layer (`internal/link` or a new `internal/resource`)

A **Resource** is one logical transfer over a Link:

```
Resource {
  ID          [16]byte      // random, per transfer
  parts       [][]byte      // MTU-sized, numbered (reuses SSendMessage chunking)
  hashes      [][32]byte    // per-part, for integrity + dedup
  window      int           // parts in flight before waiting for ACKs
}
```

Wire (all inside the Link's AEAD, so relays never see it):

- `RES_ADV`  — advertise: ID, total parts, whole-resource hash, part size.
- `RES_PART` — one numbered part.
- `RES_ACK`  — a **selective** ACK: highest contiguous part + a bitmap/SACK list of
  out-of-order parts received (this is the **selective ARQ** parked from the earlier
  investigation — it belongs here because the Link is the reusable return channel it
  needed).
- `RES_REQ`  — receiver asks for specific missing parts (fast retransmit without
  waiting for a sender timeout).
- `RES_DONE` — whole-resource hash verified; the transfer is complete.

Sender: advertise → send a window of parts → on `RES_ACK` slide the window and
retransmit only the gaps → `RES_DONE` ends it. Receiver: buffer within the window,
`RES_REQ` gaps, flush completed parts in order to the sink (mirrors P3 streaming's
in-order flush), verify the whole-resource hash. This composes with adaptive
redundancy (multiple Links/paths) and, later, adaptive parity
([ADAPTIVE_RELIABILITY.md](ADAPTIVE_RELIABILITY.md)) — ARQ handles the residual loss
FEC doesn't, and the ACK-retry rate is exactly the loss signal that doc's estimator
wants.

### 2. Direct transfers over a Link

Replace the dial-a-TCP-conn direct path (`sendToNode` → `sendFragmentDirect`) with:
`Discovery.DialNode` (already exists) → a Resource over that Link. `SendToLink`
already proves data rides a Link; this makes the *main* `SendTo`/`SendData` path do
it with reliability. The TCP path stays as a fallback/first, switched behind a flag
so nothing regresses while it's proven.

### 3. Onion multi-hop over Links (the hard part)

The onion path (`sendForwarded`/`newForwardCtx`/`sendRelayBlob`) currently dials a
TCP conn per relay and returns acks via a **single-use anonymous reply block**. Over
Links this becomes a **chain of per-hop Link sessions**: the initiator holds a Link
to relay 1; each relay holds a Link to the next; the innermost layer is sealed to the
destination. A Resource then rides hop-by-hop.

**Invariant that must not break** (asserted in tests, see THREAT_MODEL): under
`ProfileAnonymous`, per-hop Links **must not** populate a shareable path table, and a
relay must not learn the initiator. Per-hop Link sessions are individually
initiator-anonymous (the Link handshake carries no initiator identity), which is
exactly why they fit — but the *reliability return channel* must ride the same
anonymous reply path, not a direct Link back to the sender. Selective-ARQ ACKs
therefore travel as reply-block-addressed Resource frames, keeping the sender
unlinkable. This is the reason selective ARQ was parked until 0b: it needs the
reusable anonymous return channel that only the Link/Resource layer provides.

### 4. Frame router + link reuse

A small demux already exists (Discovery routes Link packets before the signature
gate). 0b formalises a **frame router**: one inbound path classifies frames
(discovery / link-control / resource) and dispatches. Links are **reused** across
transfers to the same peer (cache by node ID) instead of a handshake per transfer —
the analogue of the TCP `connPool`, and where cover traffic/jitter re-attach.

## Migration (additive; TCP path stays green throughout)

- **0b.1 — Resource layer, standalone. ✅ shipped.** `internal/link/resource.go`:
  `ResourceSender`/`ResourceReceiver`, `ADV/PART/ACK/DONE` frames, sliding window,
  **selective-ACK** (SACK bitmap), **timeout-based** retransmit (per-part send
  timestamps — no resend storm), in-order reassembly, whole-resource SHA-256.
  Tested over an in-memory lossy pipe (no-loss, 30 %, 50 % tail loss); clean path
  sends exactly `parts+1` frames.
- **0b.2 — Direct transfer over a Link. ✅ shipped.** A per-link `Router`
  (`internal/link/router.go`) multiplexes best-effort **messages** and reliable
  **resources** by a 1-byte sub-protocol prefix (the per-link half of the 0b.4 frame
  router). `swarmsync.SendToResource` dials a Link and transfers reliably;
  `Options.ReliableLinkTransfer` routes node-addressed `SendTo`/`SendToAsync` through
  it (TCP stays the default). Proven end-to-end over UDP **and across a TCP bridge**
  (nodes on separate broadcast domains, discovered only via the bridge); messenger
  green. *(LAN-multicast peer uses the same `addrIface` unicast path as the bridge,
  so it is covered by the same mechanism.)*
- **0b.3 — Onion over Links.** Per-hop Link sessions + Resource, anonymous ARQ
  return path. *Done when:* the anonymity invariant test still passes (no shareable
  path table under Anonymous; relay can't learn the initiator) **and** a 3-hop
  forwarded transfer completes with selective retransmit.
  - **Prerequisite ✅ shipped — Link reuse.** `Manager.DialCached` caches an
    initiator-side Link per peer identity (evicted on close); `NewRouter` is now
    idempotent per Link so a reused Link keeps its single `OnData` handler.
    `Discovery.DialNode` reuses; `SendToResource` closes a stale link on failure so
    the next send re-dials. Without this, onion — which sends many fragment copies
    per hop — would handshake per fragment. Tested (`reuse_test.go`).
  - **Core ✅ shipped.** A `relay` sub-protocol on the Router (`SendRelay`/`OnRelay`)
    carries onion blobs over a Link; `Router` idempotence + link reuse make it one
    cached session per hop. `Transfer.sendRelayHop` prefers a Link (falls back to TCP)
    when `Options.OnionOverLinks` is set — used on both the sender's first hop
    (`sendFragment`) and a relay's forward (`forwardToNextHop`); the inbound Router
    routes relay blobs to `Transfer.HandleRelayBlob`, which peels and forwards exactly
    like the TCP `handleRelay`. The **source-routed onion and anonymous reply-block ack
    are unchanged**, and each Link hop is initiator-anonymous (no `SourceNode`, unlike
    the TCP relay packet). Proven by `TestOnionOverLinks` (sender→relay→dest, each hop
    over a Link) and the deterministic `TestRouter_RelaySubProtocol`; the anonymity
    invariants (`TestInnerFragmentIsAnonymous`, `TestMultiNodeAnonymityHardening`)
    still pass. Off by default (TCP stays default; the flip is the final step).
    *Follow-up: carry the ack/cover/probe/store-forward relay sends over Links too
    (they remain TCP for now).*
- **0b.4 — Link reuse + frame router. ✅ shipped.** Link reuse landed with 0b.3
  (`DialCached` + idempotent `NewRouter`). The **frame router** is the per-link
  `Router`: it demuxes `message` / `resource` / `relay` sub-protocols by a 1-byte
  prefix — the control-plane split the phase called for. The **anonymity defenses now
  ride the link path**: padding is inside the onion blob (transport-agnostic, already
  applied); `applyJitter` runs on the Link forward too (`sendRelayViaLink`); and
  **cover traffic goes through `sendRelayHop`**, so decoys ride the *same* transport
  as real traffic (a decoy over TCP while real traffic rode Links would be a fatal
  distinguisher). Verified by `TestCoverTrafficDropped`, `TestPadPacket`, and the
  onion/anonymity suite. *Residual: the relay-liveness probe keeps its dedicated
  short-timeout TCP dial (a relay-scoring mechanism, not a sender-anonymity one) —
  documented in the threat model.*

**The default flip (TCP → Link) is intentionally NOT taken here.** All the mechanism
is in place behind `Options.OnionOverLinks` / `ReliableLinkTransfer` (both default
off); flipping the default changes behaviour for every deployment and is a policy call
to make after field validation, keeping TCP as the compatibility fallback.

## Interplay with existing features

- **Reservations / circuit relay** (NAT'd recipients): a held Link replaces a held
  TCP conn — cleaner, since a Link is already the reusable bidirectional primitive
  `serveReservation` hand-rolls today.
- **Store-and-forward**: unchanged in spirit — a relay holds Resource parts for an
  offline recipient and flushes them over the recipient's Link when it returns.
- **Adaptive redundancy / parity**: redundancy = N independent Links/paths; parity =
  FEC inside the Resource; ARQ mops up the rest. One delivery target, three levers.
- **MTU sizing (P5)**: already done — Resource parts inherit `link.maxChunkForMTU`, so
  the same transfer works from a TCP bridge down to a 500-byte LoRa link.

## Risks / open questions

- **Complexity vs. the TCP path.** Mitigation: additive sub-phases, TCP stays default
  until each step is proven; flip last.
- **Anonymous ARQ.** The return channel must not deanonymise the sender; ACKs ride the
  reply-block path, not a direct Link. Needs a dedicated invariant test before 0b.3
  ships.
- **Head-of-line blocking** over a single ordered Link for multiplexed transfers —
  Resource IDs demux, but one lossy Resource shouldn't stall another; may want
  per-Resource windows (it does) and, later, multiple Links.
- **Selective-ACK format** — bitmap vs. SACK ranges; pick by expected loss/part-count
  (bitmap is simplest for the ≤65535-part cap the uint16 count already implies).

*Companions: [RETICULUM_ALIGNMENT.md](RETICULUM_ALIGNMENT.md) (the epic; Links landed,
this is the remaining Phase 0b), [ADAPTIVE_RELIABILITY.md](ADAPTIVE_RELIABILITY.md)
(parity + the loss estimator ARQ feeds), [ROADMAP.md](ROADMAP.md), THREAT_MODEL.md
(the anonymity invariant 0b.3 must preserve).*
