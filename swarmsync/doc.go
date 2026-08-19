// Package swarmsync is the public SDK for SyncSwarm: a decentralized,
// privacy-respecting peer-to-peer data-transfer library.
//
// A node is created with [New] and started with [SyncSwarm.Start]. It then
// discovers peers, and can send bytes or Go values to a specific node or the
// whole group. Every node has a self-authenticating identity: its NodeID is
// bound to an Ed25519 key ([SyncSwarm.NodeID]), so a node cannot claim an ID it
// does not hold the key for.
//
// # Quick start
//
//	node, err := swarmsync.New(swarmsync.Options{
//	    OnDataReceived: func(b []byte) { fmt.Printf("got %d bytes\n", len(b)) },
//	})
//	if err != nil { log.Fatal(err) }
//	if err := node.Start(); err != nil { log.Fatal(err) }
//	defer node.Stop()
//
//	// ... discover a peer, then:
//	node.SendTo([]byte("hello"), peerID)
//
// # Choosing a posture
//
// [Preset] returns a coherent bundle of settings for a [Profile]:
// [ProfileDirect] (fastest, not anonymous), [ProfileBalanced] (one relay hop),
// or [ProfileAnonymous] (onion routing, cover traffic). Individual [Options]
// fields override a preset.
//
// # Sending
//
//   - [SyncSwarm.Send] / [SyncSwarm.SendTo] — group or targeted byte delivery,
//     erasure-coded and (optionally) onion-routed and sealed.
//   - [SyncSwarm.SendAsync] / [SyncSwarm.SendToAsync] — non-blocking, outcome via
//     callback.
//   - [SyncSwarm.SendStream] / [SyncSwarm.SendStreamResumable] — block-wise
//     streaming of large payloads with bounded memory; the resumable form skips
//     blocks the receiver already holds after an interruption.
//   - [SyncSwarm.SendToLink] — deliver over an ephemeral, forward-secret encrypted
//     Link (no shared key, no erasure coding, no onion), authenticated to the
//     recipient's node identity.
//
// # Confidentiality
//
// Set Options.Key for shared-key sealing of every fragment, or
// Options.SealToRecipient to seal each targeted send to the recipient's public
// key with no shared secret (add Options.PostQuantum for hybrid X25519 +
// ML-KEM-768). SendToLink is confidential by construction via its per-session
// key.
//
// # Reaching peers across networks
//
// On a LAN, nodes discover each other automatically. Across the internet, point
// Options.BootstrapPeers at a known node, or open a persistent bridge with
// Options.BridgePeers / Options.BridgeListen so discovery (announces and path
// requests) crosses subnets without DNS. A node behind NAT can stay reachable by
// holding circuit reservations (Options.NeedsRelay, or Options.AutoRelay to do
// so only when a dial-back test concludes it is unreachable).
//
// See the README and the examples directory for runnable programs.
package swarmsync
