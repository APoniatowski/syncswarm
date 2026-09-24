# Adaptive reliability — redundancy & parity

> **Status:** adaptive **redundancy** is shipped; adaptive **parity** below is
> **future planning — design only**, staged until there's loss telemetry to drive it.

How SyncSwarm scales delivery resilience with the network **without saturating it**.
Two knobs, driven by *different* signals:

| Knob | Protects against | Driven by | Status |
|---|---|---|---|
| **Redundancy** (independent paths per fragment) | a whole relay/path dropping traffic | **relay diversity** (distinct subnets) | **shipped** — `AdaptiveRedundancy` |
| **ParityShards** (Reed–Solomon FEC) | individual *fragments* lost on a path | **measured loss rate** | **designed here** (not yet built) |

The load-bearing correction: **parity does not scale with relay count.** A 1000-relay
and a 10-relay network with the same per-fragment loss need the same parity for the
same message. Relay count enters only via redundancy (and second-order: more relays →
better routes → lower loss).

## Redundancy (shipped)

`Options.AdaptiveRedundancy` + `MinRedundancy`/`MaxRedundancy`. Per send, the number of
independent paths = `DistinctSubnetRelays(dest, relays)` clamped to
`[min, max]` (default max = 4), then capped by the actual relay count. So:

- a thin/young network still gets the **floor** (`min`, default 1),
- resilience **grows** as independent relays join,
- a large swarm is **ceilinged** so a fragment isn't fanned out over unbounded paths.

This is the "scales with relays" knob, and it reuses the same `DistinctSubnetRelays`
diversity measure as adaptive onion hops.

## Parity (design)

### The model

Reed–Solomon sends `D` data + `P` parity shards; the receiver reconstructs from **any
`D`**, so it survives up to `P` lost shards. With `R` redundant paths, a shard is lost
only if **all** its copies drop, so effective per-shard loss is:

```
ℓ_eff = ℓ ^ R          (ℓ = per-path per-fragment loss)
```

The number of shards lost out of `N = D + P` is ~ `Binomial(N, ℓ_eff)`. Choose the
**smallest** `P` such that:

```
P(losses ≤ P) ≥ target        e.g. target = 0.999
```

That is the entire algorithm: a binomial-tail solve. Parity tracks **loss**, not
network size.

### What it produces (target 99.9%, D = 10, R = 1)

| Per-fragment loss ℓ | Parity P | Overhead |
|---|---|---|
| 0.1% | 1 | 10% |
| 1%   | 2 | 20% |
| 5%   | 4 | 40% |
| 10%  | ~6 → **cap; resend instead** | 60% |

Overhead is a **small percentage that follows loss**, with a **floor** (so a young,
lossy, low-diversity network isn't left at `P=0`) and a **hard ceiling** (past it, stop
adding parity and let `ConfirmDelivery` resend — cheaper than unbounded FEC). Note the
young-network case wants *relatively more* parity, not less — the opposite of scaling
parity up with relay count.

### Estimating `ℓ` (the missing input)

Parity is only as smart as the loss estimate. Sources, in order of signal quality:

1. **Ack retry rate** (`ConfirmDelivery`) — how often transfers need a resend directly
   implies a delivery-failure rate; fold in via an EWMA per destination/route.
2. **Relay scoring** — strikes/drops already tracked in `internal/transfer/reputation.go`
   give a per-relay drop estimate; combine along a path as `1 - Π(1 - dᵢ)`.
3. **Per-hop × hop count** — a fragment through `h` hops with per-hop drop `d` has
   `ℓ ≈ 1 - (1-d)^h`, so longer (adaptive) paths get slightly more parity.
4. **Cold start** — no data yet → a conservative default (e.g. `ℓ = 5%`), tightening as
   telemetry accumulates.

### Proposed API

```go
// Options
AdaptiveParity  bool    // size parity from measured loss to hit a delivery target
ParityTarget    float64 // e.g. 0.999; 0 -> a sensible default
MinParityShards int     // floor (young/lossy networks); 0 -> 1
MaxParityShards int     // ceiling; beyond it, rely on ConfirmDelivery resend
```

Do **not** overload `Redundancy`/`ParityShards`: those stay the fixed knobs;
`AdaptiveParity` overrides `ParityShards` the way `AdaptiveRedundancy` overrides
`Redundancy`.

### Build order (needs telemetry first)

1. **Reliability estimator** — an EWMA loss estimate per route from ack-retry outcomes
   + relay scores. This is the prerequisite; parity is only as good as it.
2. **Parity solver** — a small binomial-tail function `AdaptiveParity(dataShards, lossEff,
   target, min, max) int` (precomputable as a table), wired to override `ParityShards`
   per send, clamped `D + P ≤ 256` (RS field limit).
3. **Compose with redundancy** — the solver reads `ℓ_eff = ℓ^R`, so redundancy and
   parity are chosen together against one delivery target at minimum total bytes.

### Why staged, not shipped now

Parity sizing is worthless without a real loss estimate, and a two-relay network has no
loss history yet. So redundancy (diversity-driven, needs no telemetry) ships now; parity
(loss-driven) lands once the estimator has data to read — at which point it self-tunes:
low overhead on a healthy network, more on a lossy one, always capped.

*Companion: [RETICULUM_ALIGNMENT.md](RETICULUM_ALIGNMENT.md) (adaptive hops / tiered
routing use the same diversity measure), [ROADMAP.md](ROADMAP.md).*
