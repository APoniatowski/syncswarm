# Decentralized bootstrap — a signed, self-propagating seed list

> **Status: future planning — design only, not implemented.** Phase A (peer cache,
> `DefaultSeeds`, key-binding) is shipped; Phases B–D below are a plan to pick up once
> the network has grown and independent operators exist. Recorded now so the direction
> is captured, not because it's on the immediate build path.

How SyncSwarm goes from "one seed (the author's machine)" to "no single machine —
including the author's — is ever required," at the scale of thousands of relays.

## The problem this solves

A brand-new node with an empty peer cache, sharing no medium with anyone, must reach
**at least one** live relay to make first contact. That irreducible entry point cannot
be zero (the bootstrap problem — Bitcoin, BitTorrent, IPFS, and Tor all keep permanent
seed/hub lists). The goal is therefore **not to eliminate the seed, but to make no
single seed load-bearing**: a curated set of entry points, owned by many operators,
that self-maintains and propagates over the mesh, with a hardcoded fallback that never
expires.

## What already exists (the foundation)

- **Persistent peer cache** — a node that has *ever* connected re-bootstraps from its
  own `discovery-peers.json`; it never needs a seed again. So this only concerns
  *brand-new* nodes.
- **Every relay gossips the whole swarm** — reaching any one relay yields the entire
  network.
- **`swarmsync.DefaultSeeds` is a list** — the SDK is already shaped to hold many seeds.
- **Key-binding** — a relay's NodeID is the hash of its Ed25519 key, so even a poisoned
  seed list cannot forge a relay *identity*; it can only steer you toward
  valid-but-attacker relays (a traffic-analysis risk on the entry hop, mitigated below).

This design adds the missing piece: a **signed, updatable, peer-propagated seed list**
so the entry-point set decentralizes without SDK releases and without a single owner.

## Trust model

- **Root of trust:** the SDK ships an initial **operator set** (N Ed25519 public keys)
  and a **threshold M**, plus a small hardcoded fallback seed list. This is the only
  baked-in trust; everything else derives from it.
- A seed list is authoritative iff **≥ M of the currently-trusted operators signed it**.
- **Curated entry points, open participation.** Anyone may run a *relay* (open, key-bound,
  Sybil-resisted by scoring). The *seed list* — which relays newcomers are pointed at
  first — is **curated by the M-of-N operator group**, because an open seed list is an
  eclipse/Sybil vector. This is the deliberate balance.

## Data model

```go
type SeedList struct {
    Version   uint64        // monotonic; a list is only adopted if strictly newer
    IssuedAt  int64         // unix seconds
    ExpiresAt int64         // soft expiry — refetch after, but keep using until replaced
    Seeds     []SeedEntry   // current entry points
    Operators []OperatorKey // the operator set that governs the NEXT list (rotation)
    Threshold int           // M for the next list
    Sigs      []Signature   // ≥ (current) Threshold sigs over canonical(all fields above)
}
type SeedEntry   struct { Host string; Port int; NodeID string } // NodeID optional (pin)
type OperatorKey struct { ID string; Ed25519Pub []byte }
type Signature   struct { OperatorID string; Sig []byte }
```

Signatures cover a canonical encoding of everything except `Sigs` (same pattern as
`AnnouncePayload.signedBytes`).

## Validation (anti-rollback, anti-takeover)

A candidate list replaces the trusted one iff **all** hold:

1. **Newer:** `candidate.Version > trusted.Version` (monotonic — defeats replaying an
   old, since-revoked list).
2. **Authorized:** at least **`trusted.Threshold`** valid signatures from keys in the
   **currently-trusted** `Operators` set (not the candidate's own — that would let a
   forged list appoint its own signers).
3. **Well-formed:** parses, `Threshold ≥ 1`, `Threshold ≤ len(Operators)`.

On adoption: the candidate's `Operators`/`Threshold` become the trusted set (this is how
the operator group itself rotates — a new operator set is only valid if the *old* M-of-N
signed it), the seeds are merged into the bootstrap set, and the list is cached to disk.

## Fetch channels (redundant, transport-untrusted)

The list's integrity comes from signatures, so the *transport* need not be trusted —
any channel works, and more channels = more resilience:

1. **From peers (the "everyone is a seed" mechanism).** A connected node serves its
   cached signed list; nodes gossip newer versions. Once you've touched *any* node, you
   get the current authoritative seed set **peer-to-peer, no infrastructure**. This is
   what makes every participant effectively a seed.
2. **DNS TXT** at well-known names (base64, chunked if needed) — cheap, no server.
3. **HTTPS URLs** — a static file on any host/CDN; several independent ones.
4. **Local disk cache** — last valid list, used first on startup.

## Bootstrap flow on start

1. Bootstrap set = **peer cache ∪ cached signed-list seeds ∪ hardcoded fallback**
   (deduped). Try to connect immediately.
2. In the background, fetch a fresh list from the channels; validate; if newer, adopt +
   persist.
3. Ongoing: accept newer valid lists gossiped by peers.

So a cold node always has *something* to try (fallback), a returning node uses its cache,
and everyone converges on the current operator-curated set as it propagates.

## Rotation — how your machine exits

- **Drop a seed / retire a machine:** issue a new list (Version+1) without that entry,
  signed by ≥ M current operators. It propagates; newcomers stop being pointed at the
  dead box; existing nodes never cared (cache + gossip). **Your machine is gone, the
  network doesn't blink.**
- **Add/remove an operator, rotate a key:** put the new `Operators`/`Threshold` in a new
  list signed by ≥ M of the *old* set. A compromised operator is evicted by the others.
- **Tooling:** a small `seedctl` CLI to assemble a list and collect M signatures (an
  offline M-of-N signing ceremony), plus publish to DNS/HTTPS. Operators never share
  keys; each signs independently.

## Threats & mitigations

| Threat | Mitigation |
|---|---|
| Poisoned list → eclipse newcomers to attacker relays | Needs **M operator keys**; key-binding stops identity forgery; onion routing still protects content; entry-relay diversity limits observation |
| Channel (DNS/HTTPS) compromise | Signatures + monotonic version — attacker can't forge or roll back without signing keys |
| Rollback to an old (revoked) list | Strictly-increasing `Version`; cache never downgrades |
| Operator-set takeover | New operator set valid only if the **old** M-of-N signed it |
| Single operator compromised | M-of-N threshold; evict via a new list signed by the rest |

## Phasing

- **A — done:** persistent peer cache + `DefaultSeeds` list + key-binding.
- **B:** `SeedList` type + signing/verification (reuse the Ed25519 + canonical-bytes
  pattern), baked-in root operators + threshold + fallback, disk cache, DNS-TXT/HTTPS
  fetch, merge into bootstrap. *(Single-operator to start — you — so it's a signed
  version of today's seed, immediately useful.)*
- **C:** peer-to-peer propagation of the list (gossip a newer version to peers) — the
  delivery mechanism that makes every node a seed.
- **D:** operator rotation + `seedctl` M-of-N tooling; recruit independent operators,
  raise N and M.

## The end state

The SDK ships a tiny signed root (operator keys + threshold + fallback IPs). The live
seed set is curated by an M-of-N operator group, updates without SDK releases, and
**propagates over the mesh itself** — so any node a newcomer reaches hands them the
current set. Combined with the peer cache (most nodes never need a seed) and key-binding
(a bad list can't forge identities), **no single machine — including the author's — is
ever required.** Retiring your seed becomes one signed list with one fewer entry.

*Companion: [ADAPTIVE_RELIABILITY.md](ADAPTIVE_RELIABILITY.md),
[RETICULUM_ALIGNMENT.md](RETICULUM_ALIGNMENT.md).*
