# Security audit — NAT'd users and bridges

**Date:** 2026-09-06 · **Scope:** what a hostile swarm member can do to users who are
behind NAT (relying on circuit reservations) or attached via a TCP bridge.

Threat model: the attacker is an ordinary participant. They can join the swarm, run
a well-behaved relay, run a bridge, send any packet, and observe their own traffic.
They do not hold anyone else's private key.

## Summary

Identity and confidentiality hold up well. **Routing metadata does not.** The two
serious findings both concentrate traffic for a NAT'd user onto a single relay —
one by accident, one at an attacker's choosing — which is the exact property the
onion layer exists to prevent.

No finding lets an attacker read message content or impersonate a node.

| # | Severity | Finding | Wire change? | Status |
|---|----------|---------|--------------|--------|
| 1 | High | Onion anonymity collapses to one hop for NAT'd destinations | No | **Fixed** |
| 2 | High | Gossip can forge a victim's reservation relays | Yes | **Fixed** |
| 3 | Medium | Bridges are unauthenticated and are a metadata concentration point | No | **Fixed (opt-in)** |

---

## 1. Onion anonymity collapses for NAT'd destinations — High

`internal/transfer/transfer.go`, path construction:

```go
if len(dest.RelayIDs) > 0 {
    if rr := pickReservationRelay(relays, dest.RelayIDs); rr != nil {
        relays = []routing.Peer{*rr}   // entire relay set discarded
    }
}
```

When the destination is NAT'd, the whole candidate relay set is replaced by a
single relay. Both derived quantities then degrade with it: `hopsFor` sees one
relay, and `paths` is explicitly capped at `len(relays)`. The path becomes one hop.

That single relay therefore observes the sender's address and the destination at
the same time. For a direct (non-NAT'd) destination the sender enjoys multi-hop
onion routing; **turn on `NeedsRelay` and it silently goes away.** The users who
most need unlinkability are the ones who lose it.

This is not the intended design. Twenty lines further down the code computes
`exitNear` — "bias the exit hop toward the destination using the relays it
advertises" — which is exactly the correct mechanism: pin the *last* hop to the
reservation relay and keep earlier hops diverse. The collapse above makes
`exitNear` dead code in precisely the case it was written for.

**Fix:** delete the collapse and let `exitNear` do its job. The reservation relay
must be the exit hop (it is the only way in), but nothing requires it to be the
*only* hop. Applied in this change.

## 2. Gossip can forge a victim's reservation relays — High

`internal/discovery/discovery.go`, `mergePeer`. The only validation on a gossiped
record is the key binding:

```go
if pi.NodeID != protocol.DeriveNodeID(pi.SignKey) { return }
```

That proves the subject's ID matches the subject's signing key — but both are
public, broadcast in every announce. The record is signed by the **gossiper**, not
the subject, and nothing binds the remaining fields (`RelayIDs`, `Capabilities`,
`Address`, `Port`) to the subject at all.

Compare the direct path, which gets this right:

```go
bound := payload.NodeID == signerID && packet.SourceNode == signerID
```

So there is an authenticated channel for these facts and an unauthenticated one
carrying the same fields, and the unauthenticated one wins by arriving later.

**Exploit** (`internal/discovery/gossip_forgery_test.go`, both cases confirmed
failing before the fix and passing after): the attacker runs one genuinely honest, reachable relay —
the price of entry — then gossips a single record naming itself as a victim's
reservation relay. Senders adopt it, and via Finding 1 that relay becomes the
victim's entire inbound path.

Consequences:

- **Traffic analysis.** The attacker learns who contacts the victim, when, and how
  much. Message content stays sealed — the attacker peels only its own onion layer
  — but for a privacy SDK the metadata *is* the asset.
- **Denial of service.** The attacker holds no real reservation, so it can simply
  drop everything, or accept and blackhole. The victim goes dark.
- **Capability forgery.** The same hole lets gossip mark any node `relay`, pulling
  it into other peers' relay sets.

**Fix, two parts:**

- *Now, no wire change:* stop accepting `Capabilities` from gossip. It is already
  carried in the signed `AnnouncePayload`, so the gossip copy is pure downside.
  Applied in this change.
- *Then, with a wire change:* `RelayIDs` had no authenticated channel at all —
  `AnnouncePayload` did not carry it, so gossip was the *only* way a NAT'd peer's
  reservations propagated, and dropping it would have re-broken NAT'd reachability.
  `RelayIDs` is now a signed field of `AnnouncePayload` and is no longer learned
  from gossip.

The announce was already the right vehicle: its inner signature is independent of
the enclosing packet and covers every immutable field, so it stays verifiable
however many hops re-forward it. That is what makes the forwarded case — precisely
the case gossip existed to serve — safe: a relayed copy is still the announcer's own
statement about itself, and a forwarder that rewrites `RelayIDs` to point at itself
invalidates the signature and is dropped. Stripping the field is caught too, so an
attacker cannot silently make a NAT'd node unreachable either.

`SetRelayIDs` now re-announces on change, since reservations no longer ride the
gossip timer.

### Compatibility

`RelayIDs` is appended to the signed bytes **only when non-empty**, so an announce
carrying no reservations hashes exactly as it did before the field existed. Old and
new nodes stay mutually verifiable in both directions for all such announces — the
overwhelming majority. The one break is narrow and self-limiting: an announce that
*does* carry `RelayIDs` will not verify to a peer too old to know the field, so
those peers cannot learn the reservations of a NAT'd node. They could not reliably
route to it before this change either, and a mixed network heals as relays update.
Nodes still emit their *own* `RelayIDs` in gossip, which costs nothing and keeps
older peers working; third-party records no longer carry them, since relaying an
unattested claim only amplifies it.

**Deployment order matters — relays first.** An announce is rejected wholesale when
its signature does not verify, so a node advertising `RelayIDs` is not merely
partially understood by an old relay, it is *invisible* to it: the announce is
dropped and the node is not learned at all. Update the relays before the clients.
A NAT'd client pointed at un-updated relays will be worse off than before this
change, not better.

## 3. Bridges are unauthenticated — Medium

`internal/iface/tcp.go` opens a plain `net.Listen` and accepts every connection.
There is no allowlist, no pre-shared key, no per-peer authorization.

A bridge cannot forge identities — packets are signed and key-bound — and cannot
read content. But it holds a privileged position:

- It sees the discovery metadata of everyone attached to it: node IDs, addresses,
  capabilities, timing.
- It can drop or delay selectively, censoring specific peers.
- It is ideally placed to mount Finding 2, since it is already a trusted-looking
  gossip source for everything bridged through it.
- The known unicast-over-bridge defect (ROADMAP:313) means peers learned through a
  bridge cannot be verified at all, so bridged topologies stay fragile.

Related: bare `-bridge` now defaults to the seed box. That is good for zero-config
onboarding, but it means the discovery metadata of every default user flows through
one host. Worth being explicit about in user-facing docs — it is a reasonable
default, not a private one.

**Fixed, opt-in.** `Options.BridgePSK` (relay: `SYNCSWARM_BRIDGE_PSK`, or
`-bridge-psk-file`) gates who may attach a bridge, inbound and outbound. Until the
handshake completes the server does not register the connection, so an
unauthenticated peer's frames are never read.

The handshake is a mutual HMAC-SHA256 challenge-response over the existing frame
format. Two details it would be easy to get wrong:

- **The directions use different labels.** A symmetric proof is reflectable: an
  attacker holding no key could echo the server's own challenge back and replay the
  server's proof as its own. Client and server proofs are computed over distinct
  labels, and each binds *both* nonces, so a transcript is useless in the other
  direction or on another connection.
- **It is mutual, not just server-side.** A client also verifies the far end, so a
  private deployment cannot be lured onto an impostor bridge at the same address.
- It re-runs on every reconnect, and carries its own deadline so a peer that
  connects and says nothing cannot pin a slot open.

Deliberately **not** a command-line flag: a process's command line is world
readable via `ps`, so a key passed that way leaks to every local user on the host.
Environment variable or file only, with a 16-byte minimum — the handshake exposes
an HMAC over known values, so a short key falls to an offline search from a single
captured handshake.

This is access control, not confidentiality: discovery packets are signed and
payloads sealed end to end regardless. What it decides is *who may attach at all*.

**Default remains open**, which is right for a public seed — `bare -bridge` users
must still be able to attach to the default hosts. So the metadata exposure below
is unchanged for public bridges, and remains a documentation matter.

---

## What held up

Worth stating, since it is the load-bearing part:

- **Identity spoofing is properly blocked on every path** — direct discovery,
  gossip, DHT contacts, and announces all enforce `NodeID == DeriveNodeID(SignKey)`,
  and the direct path additionally requires the signer to be the subject.
- **Content confidentiality survives every finding here.** A malicious relay,
  including an attacker-chosen one, peels exactly one onion layer and forwards an
  opaque blob.
- **Liveness is first-hand**, so an attacker cannot resurrect dead peers or inject
  reachable-looking ghosts by assertion.
- Announce replay is bounded by signed timestamps and `(DestHash, Nonce)` dedup.

## Regression the security fix caused, and how it was found

Closing the gossip hole broke NAT'd delivery in the field, and the unit suite stayed
green throughout. Three separate defects, none visible in tests:

1. **Announces flood by broadcast only** (`floodFrame`). Across the internet that
   reaches nobody, and to a NAT'd peer it never can. The signed announce was
   authenticated but was not a channel: the relay had actually learned the
   receiver's RelayIDs from its unicast *discovery* packets. Fixed by sending a
   node's own announce, path requests, and path-request answers point-to-point to a
   bounded set of verified peers. Forwarded announces stay broadcast-only —
   unicasting those too multiplies every announce by the fanout at each hop.
2. **Self-attested gossip was rejected along with the forgeable kind.** A gossip
   payload is signed by its sender, so the entry describing *the sender itself*
   carries the same authority as a direct discovery packet. Rejecting it left nodes
   with `caps=[]` against known-good relays for minutes, and a NAT'd node that
   cannot see a relay-capable peer can never reserve.
3. **`resolveDest` short-circuited the path request.** `FindNode` succeeding means
   the peer was *located*, not that it is reachable; a NAT'd peer is never active,
   so the early return skipped the path request that fetches its signed announce —
   the only place its reservation relays come from. This is why the live send
   failed in 0.00s with "not reachable" while the relay demonstrably held the
   reservation.

Two latent bugs surfaced on the way, both predating this work: `FindNode`
short-circuited on any known node (so an address-less candidate from a forwarded
announce made a peer permanently unresolvable), and `upsertNode` refused every
unverified address, so a peer first heard of by hearsay could never *gain* one —
the DHT reply that would resolve it is unverified too.

Verified live afterwards: 1 KiB / 32 KiB / 256 KiB all acknowledged, received
exactly once with distinct hashes, over a **2-hop** path (the pre-fix code forced a
single hop for NAT'd destinations).

---

# Part 2 — project-wide audit (2026-09-06)

Scope widened from the NAT/bridge surface to every package. Same threat model: an
ordinary participant who can reach the ports, join the swarm, and send anything.

The theme of part 1 was routing metadata. The theme here is **memory sized from
numbers a stranger supplies**. Confidentiality and identity held up again — no
finding below lets anyone read traffic or impersonate a node — but four places
turned a few bytes of input into an allocation, and the amplification was severe.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 4 | High | Resource advertisement sized slices from an unchecked `uint32` (~100 GB from one frame) | **Fixed** |
| 5 | High | 64 MiB frame pre-allocated from a 4-byte header, before authentication | **Fixed** |
| 6 | Medium | No cap on concurrent inbound data connections | **Fixed** |
| 7 | Medium | Retained resumable streams outlive their connection, bounded only by a 1-hour TTL | **Fixed** |
| 8 | Medium | Path-selection seed was predictable and identical on every node | **Fixed** |
| 9 | Medium | Transfer ID derived from the plaintext (confirmation oracle) | **Fixed** |
| 10 | Informational | `internal/update` was unwired scaffolding that would be dangerous if wired | **Deleted** |
| 11 | Medium | Resource transfer deadlocks permanently if the completing ack and DONE are both lost | **Fixed** |
| 12 | Medium | A peer reached *through* a bridge could never be verified (unicast went to the bridge peer) | **Fixed** |
| 13 | Medium | AutoNAT could never demote a relay with only one peer, so an undialable relay kept advertising | **Fixed** |

## 4. Resource advertisement sized slices from a peer's claim — High

`internal/link/resource.go`, `onAdv`. The advertisement is a peer's statement about
a transfer it has *not yet sent*, and two slices were sized straight from it with
only a `total <= 0` check:

```go
parts: make([][]byte, total),   // total is a full uint32
got:   make([]bool, total),
```

One small frame declaring `total = 4294967295` asks for roughly **100 GB** of slice
headers — an out-of-memory kill for a few dozen bytes. Reachable by any peer that
can establish a Link, which is any peer at all: link identities are free.

The advertisement also carries `partSize`, which was parsed and thrown away. Using
it lets the *implied total size* be validated, which is the bound that actually
matters — either factor alone can look reasonable while the product does not.
Bounded now by part count, part size, and their product.

One subtlety worth recording: an empty resource legitimately advertises
`partSize = 0` (a single zero-length part), so zero means "no size claimed" rather
than a rejection. My first version refused it and broke ordinary empty transfers.

## 5. Pre-allocation from an unauthenticated 4-byte header — High

`internal/protocol/packet.go`, `ReadPacket`. The body is allocated from the declared
length *before* any of it arrives, and the packet that identifies a peer is itself
read through this path — so the cap is exactly how much memory a stranger can
commit per connection. It was 64 MiB against a largest-legitimate frame of one
4 MiB fragment plus overhead: a 16x multiplier over anything real. Now 8 MiB,
derived from what a real frame needs rather than picked round.

## 6 & 7. Unbounded connection and retained-state growth — Medium

The accept loop ran `go handleConnection` per connection with no ceiling, so the
per-connection costs of finding 5 multiplied by however many sockets an attacker
cared to open. Now capped at 256, shedding load by closing rather than queueing —
the cost of being over the limit should be a closed socket, not an OOM.

Separately, a retained resumable stream deliberately **outlives its connection**
(that is what makes resume work) and was reclaimed only after an hour. The
connection cap therefore does not bound it: connect, declare a resumable stream,
disconnect, repeat. Now capped at 512 retained partials, evicting the least
recently active.

Evicting the *oldest* rather than refusing new retention matters: a peer that filled
the table could otherwise block every genuine resume behind it, turning the
safeguard into the denial of service it exists to prevent.

## 8 & 9. Predictable path seed, and an ID derived from the plaintext — Medium

The per-copy shuffle seed was `BlockIndex + Index + SubIndex + copyIdx` — small
integers with no secret in them, so **every node in the network derived the same
relay ordering** for a given fragment. That spread load far less than intended, and
let anyone who knows the relay set predict which relay would carry a given fragment
and position themselves accordingly. Summing also collided heavily: many distinct
pieces share one seed. Now folded with the transfer's random ID, with the
coordinates separated rather than added.

That fix depends on the ID being unpredictable, and it was not: `sha256(data ||
time.Now().String())`. Deriving it from the plaintext makes it a confirmation
oracle — the ID travels with the transfer, so anyone who sees it and can guess the
content verifies the guess by recomputing the hash, and the only other input is a
cheap-to-search wall-clock string. Now `crypto/rand`.

## 10. `internal/update` — Informational, but delete it

Not imported anywhere, so nothing below is currently reachable. It is recorded
because it would be severe if it ever were:

- `NetworkUpdateData` carries **`NewPrivKey`**, and `SendUpdate` broadcasts that
  struct to other nodes over UDP. Distributing a private key is not a bug that can
  be patched around later.
- The handshake is a fixed public catechism (`WIYD`/`TSEW`), i.e. a hardcoded
  "shared secret" in the source — no authentication at all.
- `ReceiveUpdate` binds UDP, reads into a 32-byte buffer and unmarshals attacker
  JSON with no verification, **on the discovery port (64512)**.
- Assorted latent faults: `sending.Close()` deferred before the `DialUDP` error is
  checked (nil dereference), `err` read before `waitGroup.Wait()`, `log.Fatalln` in
  library code.

An update channel is the highest-value target in any peer-to-peer system: it is the
one path designed to make other machines run new code. **Deleted** (along with
`internal/internal.go`, which it orphaned and which carried unused `PrivKey` /
`PreSharedKey` fields). If self-update returns it should be built on signed
artifacts — verify a signature over the payload before anything touches disk — never
on key distribution, and not on the discovery port.

## What held up, again

- **Packet parsing is properly bounds-checked** — the `reader` cursor validates
  every field against the remaining buffer and slices rather than allocating.
- **Onion-layer parsing** checks each length against remaining data before copying.
- **AEAD use is correct**: a fresh `crypto/rand` nonce per `Seal`, prepended,
  standard GCM framing, AAD authenticated.
- **Storage paths are hex-encoded** node and chunk IDs with integer sequence
  numbers — no traversal reachable from peer input.
- **No `os/exec`, no plugin loading, no dynamic code path** anywhere in the tree.
- **Key binding is enforced on every ingest path** — direct discovery, gossip, DHT
  contacts, announces — and the Link handshake verifies an Ed25519 signature over
  the transcript.
- The one `math/rand` use is the path shuffle above; everything security-bearing
  uses `crypto/rand`.

## 11. Resource transfer deadlocks if the completing ack is lost — Medium, **Fixed**

The "flaky" `TestResource_HeavyTailLoss` was not flaky and was not slow. It was
reporting a real deadlock, and had been written off twice — once as a timeout to
raise, once as CPU starvation under parallel test load.

On completion the receiver deletes its state and sends a final ack plus DONE:

```go
delete(r.byID, id)
...
_ = r.send(ackFrame)
_ = r.send(encodeDone(id))
```

Every later frame for that ID then hits `if st == nil { return }` — ignored, with no
reply. So if the ack and the DONE are both lost, the sender's retransmits reach a
receiver that answers nothing, and it retries until its deadline. **Two dropped
frames stall a transfer permanently**, and at 30% loss that is likely enough to see
in a test run, which is exactly what kept happening.

Adversarially it is worse than a flake: anyone positioned to drop two specific
frames can pin a sender's resources for its entire timeout, repeatedly.

Fixed by remembering completed resource IDs briefly (2 minutes, capped at 1024,
since the IDs come from peers) and re-sending DONE when a retransmit arrives for
one. This is the ARQ equivalent of retransmitting a final ACK, and it costs one
frame. `TestResource_CompletionAckLossDoesNotDeadlock` drops the completing ack and
the first DONE deterministically; it stalls for the full timeout without the fix and
passes with it. `TestResource_HeavyTailLoss` now survives 30 consecutive runs.

The lesson is the one from part 1 restated: the test was telling the truth and the
diagnosis was wrong twice, because "flaky under load" is a comfortable explanation
that requires no evidence.

## 12. Unicast to a peer reached through a bridge — Medium, **Fixed**

Long-standing, recorded in the ROADMAP as needing routing rather than a patch.

`ifaceFor(nodeID)` chose the interface a peer was last heard on. For a peer learned
*via* a bridge that is a `TCPClientInterface`, whose `Send` writes to its single
connection and **ignores the address argument** — so a latency check aimed at a
distant node was delivered to the bridge peer, which answered as itself. Nonce-only
matching used to accept that, making bridged peers merely *look* verified; once
liveness became identity-bound the wrong-signer reply was correctly rejected and
such peers could never verify at all. Observed live: with `-bridge`, **no peer ever
became active**, so a bridged NAT'd node had no relay to reserve with.

Fixed by addressing such peers **by destination instead of by interface**:
`PacketTypeRoutedDiscovery` carries a signed discovery packet over the same per-hop
transport routing P3 already provides. The inner packet keeps the original sender's
signature, so the destination applies exactly the key-binding and liveness rules it
would to a direct datagram — an intermediary can drop or delay, but cannot forge.

Two details that decide whether it works and whether it is safe:

- **Reverse-path learning.** The first attempt still failed: the check reached the
  far peer, but that peer had never heard of the sender and had nowhere to send the
  reply. It now records a path back from the hop the packet arrived on.
- **Only after verification.** That reverse path is recorded solely in the delivery
  branch, once the inner signature is verified and bound to the sender's identity.
  Learning it while forwarding would let anyone claim any identity in an unsigned
  outer header and so redirect that node's traffic to themselves — turning a
  reachability fix into a routing-hijack primitive.

`TestBridge_VerifiesPeerReachedThroughBridge` builds the real topology
(A ─bridge─ B ─UDP─ C) and fails without the fix.

## 13. AutoNAT is inert in a small swarm — Medium, **Fixed**

Found by testing the live relays rather than by reading code.

The Oracle relay listens on all three ports but its data (64513) and bridge (64514)
ports are blocked at the cloud firewall — verified unreachable from two independent
networks, while its UDP discovery port (64512) is open. Liveness is a UDP check, so
the relay looked **healthy and active** to its peer while being unable to carry any
traffic at all: onion fragments travel over TCP.

Auto-demote exists for exactly this ("an undialable relay poisons other nodes' path
selection"), and it never fired. `reachMinResponders = 2` required two responders
before concluding *unreachable*, and Oracle has exactly one peer. Every round was
inconclusive, so the relay would have advertised `relay` forever.

The threshold's motivation was sound — one flaky peer should not demote a healthy
relay — but it switched the mechanism off precisely in the small networks where a
bad relay does the most damage. A single responder can now conclude, after
`reachSoloRounds` (3) consecutive rounds of agreement, which keeps the caution
without the inertia. The decision rule is split into `concludeRound` so it is
testable without sockets.

**Operationally**: the Oracle relay is not currently usable as a relay. Its cloud
security list / host firewall needs TCP 64513 (and 64514 for bridges) opened. Until
then the swarm has one usable relay, and with this fix that relay will correctly
stop advertising itself.

## Caveat on the NAT test

The end-to-end NAT'd delivery verified on 2026-09-06 ran the receiver on a LAN box
and the sender on the workstation — **both behind the same NAT**. Neither had a
forwarded port, both used ephemeral discovery ports (so no LAN broadcast rendezvous),
and relay counters confirm the fragments transited the DE relay. So
*relay-mediated delivery without port forwarding* is proven; *delivery between two
distinct NATs* is not yet directly demonstrated, though the mechanism does not
depend on the distinction.
