package discovery

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"github.com/APoniatowski/syncswarm/internal/iface"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// Per-hop transport routing (Phase 3): forward a content-sealed packet toward a
// destination using the announce path table, one hop at a time, the way Reticulum
// transport nodes do — no source-routed onion. Each transport node independently
// picks the next hop from its own path table, so no single node needs the whole
// route, and the payload stays sealed end to end (intermediaries route by
// destination but cannot read it). This is used only by the non-anonymous
// profiles; ProfileAnonymous keeps onion source-routing (a shared path table would
// let a relay link a destination to a route).
//
// Routed packets are dispatched before the signature gate: a transport node
// mutates the hop limit as it forwards (which would void an origin signature), and
// forwarding safety rests on the hop limit plus per-packet dedup rather than a
// per-hop signature — content authenticity comes from the end-to-end seal.

// defaultRoutedHopLimit bounds how many transport hops a routed packet may take.
const defaultRoutedHopLimit = 16

// SetRoutedHandler registers the callback invoked when a routed packet reaches
// this node as its destination, with the sealed inner bytes and the claimed origin
// node ID (a hint only — routed packets are not per-hop authenticated).
func (d *Discovery) SetRoutedHandler(fn func(inner []byte, origin string)) {
	d.onRouted.Store(&fn)
}

// SendRouted forwards content-sealed inner bytes toward destHash via per-hop
// transport routing. hopLimit 0 uses the default. Returns false when no path to the
// destination is known (the caller can fall back to a path request or another
// transport).
func (d *Discovery) SendRouted(destHash string, inner []byte, hopLimit uint8) bool {
	if hopLimit == 0 {
		hopLimit = defaultRoutedHopLimit
	}
	pkt := protocol.NewPacket(protocol.PacketTypeRouted, protocol.EncodeRouted(hopLimit, inner), "", destHash)
	pkt.SourceNode = d.selfID
	return d.routeToward(destHash, pkt)
}

// MTUToward reports the advertised MTU of the interface the next hop toward
// destHash is reached on, so a sender can size a routed frame to fit the path (at
// least its first hop). Returns 0 when no path is known.
func (d *Discovery) MTUToward(destHash string) int {
	e, ok := d.paths.lookup(destHash)
	if !ok || e.NextHop == "" {
		return 0
	}
	d.mu.RLock()
	i := d.addrIface[e.NextHop]
	d.mu.RUnlock()
	if i == nil {
		i = d.iface
	}
	if i == nil {
		return 0
	}
	return i.Caps().MTU
}

// routeToward marshals pkt and sends it to the next hop toward destHash from the
// path table, over the interface that path was learned on.
func (d *Discovery) routeToward(destHash string, pkt *protocol.Packet) bool {
	e, ok := d.paths.lookup(destHash)
	if !ok || e.NextHop == "" {
		return false
	}
	b, err := pkt.MarshalBinary()
	if err != nil {
		return false
	}
	d.mu.RLock()
	i := d.addrIface[e.NextHop]
	d.mu.RUnlock()
	if i == nil {
		i = d.iface
	}
	if i == nil {
		return false
	}
	return i.Send(e.NextHop, b) == nil
}

// handleRouted processes an inbound routed packet: deliver it if we are the
// destination, otherwise (as a transport) forward it one hop further toward the
// destination. Dedup by packet ID and the hop limit together bound loops and
// amplification.
func (d *Discovery) handleRouted(pkt *protocol.Packet) {
	if d.routedSeen.observe(hex.EncodeToString(pkt.ID[:])) {
		return // already delivered or forwarded this packet
	}

	if pkt.DestNode == d.selfID {
		if fn := d.onRouted.Load(); fn != nil {
			(*fn)(protocol.RoutedInner(pkt.Payload), pkt.SourceNode)
		}
		return
	}

	// A transport node forwards it onward; endpoints drop what isn't for them.
	if !d.isTransport() {
		return
	}
	if protocol.RoutedHopLimit(pkt.Payload) <= 1 {
		return // hop budget exhausted
	}
	pkt.Payload[0]-- // decrement the hop limit in place; no re-encoding needed
	d.routeToward(pkt.DestNode, pkt)
}

// SendRoutedDiscovery carries an already-signed discovery packet toward destHash
// by per-hop routing instead of by interface. Returns false when no path is known.
//
// This is what makes a peer reached *through* a bridge addressable at all: a
// bridge interface writes to its single connection and ignores the address, so an
// interface-addressed unicast lands on the bridge peer rather than the intended
// node. Routing by destination sidesteps that entirely.
func (d *Discovery) SendRoutedDiscovery(destHash string, signed []byte, hopLimit uint8) bool {
	if hopLimit == 0 {
		hopLimit = defaultRoutedHopLimit
	}
	pkt := protocol.NewPacket(protocol.PacketTypeRoutedDiscovery,
		protocol.EncodeRouted(hopLimit, signed), "", destHash)
	pkt.SourceNode = d.selfID
	return d.routeToward(destHash, pkt)
}

// handleRoutedDiscovery delivers a routed discovery packet to this node's own
// discovery processing when it is the destination, or forwards it one hop further.
//
// The inner packet carries the original sender's signature, so the destination
// applies exactly the same key-binding and liveness rules it would to a packet that
// arrived directly — an intermediary can drop or delay it, but cannot forge one or
// claim its identity.
func (d *Discovery) handleRoutedDiscovery(pkt *protocol.Packet, from *net.UDPAddr, srcIface iface.Interface) {
	if d.routedSeen.observe(hex.EncodeToString(pkt.ID[:])) {
		return
	}

	if pkt.DestNode == d.selfID {
		inner := protocol.RoutedInner(pkt.Payload)
		var ip protocol.Packet
		if err := ip.UnmarshalBinary(inner); err != nil {
			return
		}
		// The reply must travel back the same way it came, so record the interface
		// and next hop this arrived over against the original sender.
		d.deliverRoutedDiscovery(&ip, from, srcIface)
		return
	}

	if !d.isTransport() {
		return
	}
	if protocol.RoutedHopLimit(pkt.Payload) <= 1 {
		return
	}
	pkt.Payload[0]--
	d.routeToward(pkt.DestNode, pkt)
}

// deliverRoutedDiscovery processes a signed discovery packet that arrived by
// routing rather than directly. It applies the same key-binding rule as the direct
// path — the packet must be signed by the node it claims to be from — but
// deliberately learns no address: the peer is, by construction, one we cannot
// address on an interface, and recording the forwarder's address would corrupt its
// entry. Reachability for such a peer comes from the path table, liveness from this
// packet being signed by the peer itself.
func (d *Discovery) deliverRoutedDiscovery(ip *protocol.Packet, from *net.UDPAddr, srcIface iface.Interface) {
	if !ip.Verify() {
		return
	}
	signer := ip.SignerID()
	if signer == "" || signer == d.selfID || ip.SourceNode != signer {
		return
	}

	var payload protocol.DiscoveryPayload
	if err := json.Unmarshal(ip.Payload, &payload); err != nil {
		return
	}
	if payload.NodeID != signer {
		return
	}

	// Reverse-path learning: record how to get back to the sender, using the hop
	// this arrived from. Without it a reply has nowhere to go — the sender may be
	// one we have never heard an announce from, which is exactly the case when it
	// sits on the far side of somebody else's bridge.
	//
	// Recorded only here, after the inner signature has been verified and bound to
	// the sender's identity. Learning it in the forwarding path instead would let
	// anyone claim to be any node by putting that ID in an unsigned outer header,
	// and so redirect that node's traffic to themselves.
	if from != nil {
		d.rememberIface(signer, srcIface)
		d.paths.update(signer, pathEntry{
			Iface:    ifaceName(srcIface),
			NextHop:  from.String(),
			Hops:     1,
			LastSeen: time.Now(),
			OriginTS: ip.Timestamp.UnixNano(),
		})
	}

	switch ip.Type {
	case protocol.PacketTypeLatencyCheck:
		// Answer over the same routed path, so the requester's identity-bound
		// liveness check sees a reply signed by us rather than by a bridge.
		d.sendRoutedLatencyReply(signer, payload.Nonce)

	case protocol.PacketTypeLatencyReply:
		d.resolveLatency(payload.Nonce, signer)

	case protocol.PacketTypeDiscovery:
		// Identity and keys only; no address, for the reason above.
		d.learnRoutedPeer(signer, payload, ip.SignerKey)
	}
}

// sendRoutedLatencyReply answers a routed latency check over the routed path.
func (d *Discovery) sendRoutedLatencyReply(nodeID string, nonce uint64) {
	payload := &protocol.DiscoveryPayload{
		NodeID:  d.selfID,
		Version: "1.0.0",
		Nonce:   nonce,
		// No ObservedAddr: we did not observe the peer at an address, we were
		// routed to. Claiming one would teach it a falsehood about itself.
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	pkt := protocol.NewPacket(protocol.PacketTypeLatencyReply, data, "ANY", nodeID)
	pkt.SourceNode = d.selfID
	pkt.Sign(d.signPriv)
	b, err := pkt.MarshalBinary()
	if err != nil {
		return
	}
	d.SendRoutedDiscovery(nodeID, b, 0)
}

// resolveLatency delivers a latency reply to the waiter for that nonce, subject to
// the same identity binding as the direct path: the reply must come from the node
// the check was addressed to.
func (d *Discovery) resolveLatency(nonce uint64, signer string) {
	d.pendingMu.Lock()
	p, ok := d.pending[nonce]
	d.pendingMu.Unlock()
	if ok && p.nodeID == signer {
		select {
		case p.ch <- time.Now():
		default:
		}
	}
}

// learnRoutedPeer records identity and keys for a peer reachable only by routing.
func (d *Discovery) learnRoutedPeer(id string, payload protocol.DiscoveryPayload, signKey []byte) {
	d.updateNode(id, "", payload.PubKey, signKey, payload.Port,
		payload.Capabilities, payload.RelayIDs, payload.MLKEMPub)
}

// routedOnly reports whether a peer must be reached by routing rather than by
// addressing an interface: a point-to-point bridge can only ever write to its own
// far end, so any address handed to it is ignored.
func (d *Discovery) routedOnly(nodeID string) bool {
	i := d.ifaceFor(nodeID)
	return i != nil && i.Kind() == iface.KindTCPClient
}
