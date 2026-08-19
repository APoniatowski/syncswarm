# SyncSwarm Threat Model

Living document owned by the **security-auditor** agent. It describes what
SyncSwarm protects, against whom, by what mechanism, and — importantly — the
gaps that remain. Update it whenever `protocol`, `discovery`, `transfer`, or
`encryption` change. Every release should pass a `/security-review` against this
document (see `ROADMAP.md`).

Status reflects the code as of Round 6c.

---

## 1. Assets

| Asset | Protection goal |
|---|---|
| **Message content** | Confidentiality + integrity to the intended recipient only. |
| **Sender identity/location** | Unlinkable to a message by relays and by the recipient. |
| **Recipient identity** | Known to the sender (it addresses them), hidden from on-path relays. |
| **Node identity** | Unforgeable; a node cannot impersonate another. |
| **Peer table / routing view** | Not poisonable with spoofed `(NodeID, key)` pairs. |
| **Delivery confirmation** | Not forgeable by third parties (can't falsely stop resends). |

## 2. Adversaries

- **A1 — Passive network observer**: sees ciphertext on the wire.
- **A2 — Malicious relay**: a node on a forwarding path (possibly several,
  possibly the entry/exit of a path).
- **A3 — Malicious peer / impersonator**: a swarm participant that forges packets
  or claims another node's identity.
- **A4 — Sybil operator**: runs many nodes to bias routing or eclipse a victim.
- **A5 — Endpoint compromise**: holds a node's private keys.

Not defended against: a **global passive adversary** (no anonymity network fully
is), and **A5** (key compromise is game over for that node's traffic).

## 3. Security properties & mechanisms

| Property | Mechanism | Code |
|---|---|---|
| Content confidentiality/integrity | AES-256-GCM AEAD with a developer-supplied key, per fragment, AAD-bound to `(transferID, index, total)` | `encryption.NewAEADSealer`, `fragment` |
| Per-recipient E2E (no shared key) | Optional: fragments sealed to the recipient's X25519 public key (ephemeral-ECDH + HKDF + AES-256-GCM), openable only with that node's private key | `encryption.NewHybridSealer` (`SealToRecipient`) |
| Hop-by-hop confidentiality | X25519 + AES-256-GCM onion layers; each relay peels exactly one | `encryption.BuildOnion/PeelOnion` |
| No single relay sees the whole payload | Reed–Solomon shards spread across independent paths | `fragment/rs.go`, `transfer.sendForwarded` |
| Packet authenticity | Ed25519 signatures; each packet is self-authenticating (`SignerKey`) | `protocol.Sign/Verify` |
| Impersonation resistance | `NodeID = DeriveNodeID(Ed25519 pub)`, enforced on discovery + gossip | `protocol.DeriveNodeID`, `discovery` |
| Sender anonymity vs. recipient | Forwarded inner packets are unsigned with no `SourceNode`; onion AEAD authenticates them | `transfer.buildInnerFragment`, `handleRelay` |
| Anonymous acknowledgement | Single-use onion **reply block**; recipient injects an opaque blob at an entry relay | `transfer.buildReplyBlock/sendAckReply` |
| Ack unforgeability | Direct acks bound to the destination's Ed25519 key; forwarded acks bound to a secret per-transfer token sealed to the sender | `transfer.signalAckFrom/signalAckToken` |
| Harvest-now-decrypt-later resistance | Opt-in hybrid **X25519 + ML-KEM-768** sealing to the recipient (`PostQuantum` + `SealToRecipient`): confidential if *either* primitive holds. Onion layers remain X25519 for now. | `encryption.SealHybridPQ` / `NewPQHybridSealer` (`crypto/mlkem`) |
| Delivery survives dropped fragments | Reed–Solomon erasure coding + redundant independent paths + confirmed-delivery resends | `fragment/rs.go`, `transfer.sendForwarded` |
| Silent-dropper resistance | Unforgeable per-relay forwarding challenges; excommunication after repeated failure | `transfer/reputation.go` (`RelayScoring`) |
| Reachability behind NAT | Circuit-relay reservations forward inbound traffic over a held connection | `transfer/reservation.go` (`NeedsRelay`/`StoreForward`) |
| Offline delivery | Relays hold sealed fragments for offline recipients (persisted to disk, surviving relay restart) and deliver on return — flushing over a circuit reservation or redelivering directly to a re-reachable recipient | `transfer/storeforward.go`, `storage` |
| Traffic-analysis defenses (opt-in, partial) | Cover traffic, size padding, relay forwarding jitter | `transfer/anonymity.go` (`CoverTraffic`/`PadCellSize`/`RelayJitter`) |
| Sybil/eclipse resistance (partial) | Subnet-diverse path selection; bounded, bootstrap-protected peer table; gossip caps | `routing`, `discovery` |
| Observability without de-anonymization | Hop tracing is node-local and opt-in; **no correlation ID is placed on the forwarded wire format**, so relays/observers cannot link a transfer's hops | `transfer/tracing.go` (`HopTrace`) |
| DHT contact authenticity | FIND_NODE contacts are accepted only if key-bound (`NodeID == DeriveNodeID(SignKey)`); a peer cannot inject forged `(NodeID, address)` pairs into another's routing table | `discovery/dht.go` (`learnContacts`), `dht` |

## 4. Attack surface & current posture

- **A1 (observer)**: sees only ciphertext and traffic *patterns*. Content is
  safe. Metadata (timing, volume, who-connects-to-whom at the IP layer) is
  **exposed by default**; opt-in cover traffic, padding, and relay jitter
  (`CoverTraffic`/`PadCellSize`/`RelayJitter`) blunt volume/timing analysis but
  are partial (padding is exact under binary framing, but cover traffic is
  un-shaped), and a global passive adversary is out of scope.
- **A2 (malicious relay)**:
  - *Read content?* No — onion + developer-key AEAD.
  - *Learn both endpoints?* No — each relay knows only its previous and next hop.
  - *Drop/delay fragments?* Yes → mitigated by RS parity + redundant paths + ack
    resends, and a silently-dropping relay is excommunicated via unforgeable
    forwarding challenges (`RelayScoring`); not eliminated (see gaps).
  - *Inject fragments?* Can inject junk into a forwarded transfer (inner packets
    are unsigned by design); they fail the developer-key AEAD and are discarded —
    a **DoS/resource vector**, not a content-integrity break.
  - *Last return-hop relay* learns the sender's address (inherent to onion
    return paths, like an I2P inbound gateway).
- **A3 (impersonator)**: cannot forge signed packets (Ed25519) nor claim another
  `NodeID` (key-bound). Cannot forge a delivery ack (bound to dest key or secret
  token). Can still send validly-signed garbage under *its own* identity.
- **A4 (Sybil)**: **partially resisted** *(Round 9)*. Identities are still cheap,
  but flooding is costlier to weaponize: relay selection prefers distinct subnets,
  the peer table caps peers per subnet and total (evicting stalest, protecting
  bootstrap anchors), gossip acceptance is bounded, and relays that silently drop
  are excommunicated via unforgeable forwarding challenges (`RelayScoring`). A
  Sybil spread across *many distinct subnets* still evades subnet caps, and a
  relay that passes probes but drops real traffic evades the challenge.
- **A5 (key compromise)**: out of scope; compromises that node only.

## 5. Known gaps / residual risks (prioritized)

1. **Sybil/eclipse resistance is partial** *(Round 9 shipped)* — subnet-diverse
   relay selection, per-subnet/total peer-table caps, bootstrap trust anchors,
   gossip flood caps, and availability scoring (unforgeable forwarding challenges
   that excommunicate silent droppers) raise the cost, but a Sybil spread across
   many distinct subnets still evades caps, and a relay that selectively passes
   probes while dropping real traffic evades the challenge. The **Kademlia DHT**
   *(10.4)* enforces contact key-binding, but inherits Kademlia's eclipse exposure:
   an attacker who can place many key-bound Sybil nodes at IDs near a victim's ID
   can bias the victim's near buckets. ID cost (a keypair + the subnet/table caps)
   is the current mitigation; DHT-specific hardening (e.g. bucket diversity,
   S/Kademlia-style disjoint lookups) is future work.
2. **Traffic-analysis defenses are opt-in and partial** *(Round 8 shipped)* —
   cover traffic, padding, and relay jitter exist (`CoverTraffic`, `PadCellSize`,
   `RelayJitter`) but are off by default; padding is now **exact** (binary framing,
   P1), but cover traffic is un-shaped (not constant-rate) and a global-passive
   adversary correlating timing/volume across the whole network is still out of
   scope.
3. **NAT reachability is via circuit relays only** *(Round 7; AutoNAT added)* —
   NAT'd nodes are reachable through relays they reserve with, but there is no
   direct hole punching, so their traffic always transits a relay (which sees
   timing). A node's chosen reservation relays are public (advertised `RelayIDs`).
   **AutoNAT** (`AutoRelay`) automates the reserve/don't-reserve decision via a
   signed dial-back exchange; it is a convenience, not a security boundary — a
   lying peer can at worst push a node onto a relay it didn't need (harmless) or
   withhold that push (leaving it as reachable as it is without AutoNAT). The
   determination takes the optimistic view (one honest success ⇒ reachable), so a
   single malicious responder cannot force a node off direct reachability.
4. **Last return-hop learns sender address** — inherent to onion return paths;
   full protection needs rendezvous/tunnels. *(Round 8)*
5. **Junk-fragment DoS** — keyless relays can inject fragments that waste
   reassembly effort before failing AEAD. Consider a cheap per-transfer relay
   proof or rate limiting. *(Round 9)*
6. **Ephemeral X25519 onion key is authenticated only by the current signed
   discovery packet** — acceptable, but key rotation/expiry is undocumented.
7. **Non-anonymous direct path** — `SendTo` with `HopCount == 0` (or forwarding
   fallback) reveals sender↔recipient at the IP layer. This is by design;
   callers wanting anonymity must set `HopCount >= 1` with relays available.
8. **No idle read deadline on accepted connections** — a peer that opens a data
   connection and then stalls (sends nothing, or a partial frame) holds a
   receive goroutine blocked on the read indefinitely, a slowloris-style resource
   hold. Falls under the DoS non-goal below; a proper fix is a per-connection idle
   timeout that does not break long-lived reservation circuits or the streaming
   drain. *(Iterative DHT lookups are already bounded — `dht.DefaultMaxRounds` —
   against a related amplification.)*

## 6. Non-goals (current)
- Global-passive-adversary resistance.
- Protecting a node whose private key is compromised.
- Hiding that a node is *running SyncSwarm* (no protocol obfuscation / pluggable
  transports).
- Availability guarantees against a determined DoS.

## 7. Assumptions
- The developer-supplied content key is distributed securely out-of-band and kept
  secret by both endpoints.
- Node identities are exchanged out-of-band (the key-bound `NodeID`).
- At least some honest, reachable relays exist for forwarded/anonymous transfers.
