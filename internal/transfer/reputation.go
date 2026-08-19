package transfer

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"strconv"
	"time"

	"github.com/APoniatowski/syncswarm/internal/discovery"
	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/routing"
)

const (
	defaultStrikeLimit = 3                // consecutive failed challenges before excommunication
	defaultPenance     = time.Hour        // how long an excommunication lasts
	probeInterval      = 30 * time.Second // cadence of the liveness rite
	probeTimeout       = 4 * time.Second  // how long we await a probe's return
	probeDialTimeout   = 2 * time.Second  // dial timeout for the first hop of a probe
	maxProbeRelays     = 8                // relays challenged per round
)

// relayPeers returns the eligible relays among nodes: active, relay-capable,
// keyed, not excludeID, and not excommunicated. Their Address is the dial-able
// data address so onion hops are directly reachable.
func (t *Transfer) relayPeers(nodes []*discovery.Node, excludeID string) []routing.Peer {
	var relays []routing.Peer
	for _, n := range nodes {
		if n.ID == excludeID || len(n.PubKey) == 0 || !hasCapability(n.Capabilities, "relay") {
			continue
		}
		if t.isExcommunicated(n.ID) {
			continue // heretics carry no traffic
		}
		relays = append(relays, routing.Peer{
			ID: n.ID, Address: peerDialAddr(n), Latency: n.Latency,
			Active: n.Active, PubKey: n.PubKey, Port: n.Port, RelayCapable: true,
		})
	}
	return relays
}

// isExcommunicated reports whether a relay is currently cast out. An expired
// excommunication is lifted here (redemption), resetting its strikes.
func (t *Transfer) isExcommunicated(relayID string) bool {
	t.repMu.Lock()
	defer t.repMu.Unlock()
	until, ok := t.excommunions[relayID]
	if !ok {
		return false
	}
	if timeAfterNow(until) {
		return true
	}
	delete(t.excommunions, relayID)
	delete(t.relayStrikes, relayID)
	return false
}

// recordProbe folds a challenge outcome into a relay's standing. A success
// absolves it (strikes cleared); strikeLimit consecutive failures excommunicate
// it for the penance duration.
func (t *Transfer) recordProbe(relayID string, ok bool) {
	t.repMu.Lock()
	defer t.repMu.Unlock()
	if ok {
		delete(t.relayStrikes, relayID)
		return
	}
	t.relayStrikes[relayID]++
	if t.relayStrikes[relayID] >= t.strikeLimit {
		t.excommunions[relayID] = nowPlus(t.penance)
		delete(t.relayStrikes, relayID)
		t.metrics.IncExcommunicate()
	}
}

// registerProbe / signalProbe correlate an outstanding challenge with its return.
func (t *Transfer) registerProbe(id [32]byte) chan struct{} {
	ch := make(chan struct{})
	t.probeMu.Lock()
	t.probes[id] = ch
	t.probeMu.Unlock()
	return ch
}

func (t *Transfer) unregisterProbe(id [32]byte) {
	t.probeMu.Lock()
	delete(t.probes, id)
	t.probeMu.Unlock()
}

// signalProbe closes the channel for a returned probe and reports whether id was
// in fact one of our outstanding probes.
func (t *Transfer) signalProbe(id [32]byte) bool {
	t.probeMu.Lock()
	ch, ok := t.probes[id]
	if ok {
		delete(t.probes, id)
	}
	t.probeMu.Unlock()
	if ok {
		close(ch)
	}
	return ok
}

// maintainReputation runs the periodic liveness rite.
func (t *Transfer) maintainReputation() {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.probeRound()
		}
	}
}

// probeRound challenges a bounded set of the relays we might route through.
func (t *Transfer) probeRound() {
	if t.nodePriv == nil || t.discovery == nil {
		return
	}
	var targets []*discovery.Node
	for _, n := range t.discovery.GetActiveNodes() {
		if n.ID == t.selfID || len(n.PubKey) == 0 || !hasCapability(n.Capabilities, "relay") {
			continue
		}
		if t.isExcommunicated(n.ID) {
			continue
		}
		targets = append(targets, n)
		if len(targets) >= maxProbeRelays {
			break
		}
	}
	for _, n := range targets {
		t.recordProbe(n.ID, t.probeRelay(n))
	}
}

// probeRelay challenges one relay to forward a self-addressed onion probe back to
// us. Because the probe's innermost layer is sealed to our own key and carries a
// random ID the relay cannot read, the relay can only pass by genuinely
// forwarding — it cannot forge success. Returns true if the probe comes home.
func (t *Transfer) probeRelay(relay *discovery.Node) bool {
	relayPub, err := ecdh.X25519().NewPublicKey(relay.PubKey)
	if err != nil {
		return false
	}
	// Path: relay -> us. The relay must forward the inner blob to our address.
	hops := []encryption.OnionHop{
		{NodeID: relay.ID, Addr: peerDialAddr(relay), PubKey: relayPub},
		{NodeID: t.selfID, Addr: net.JoinHostPort(t.reachableHost(), strconv.Itoa(t.dataPort)), PubKey: t.nodePriv.PublicKey()},
	}

	var probeID [32]byte
	if _, err := rand.Read(probeID[:]); err != nil {
		return false
	}
	ch := t.registerProbe(probeID)
	defer t.unregisterProbe(probeID)

	ack := protocol.NewPacket(protocol.PacketTypeAcknowledgement, nil, "", "")
	ack.ID = probeID
	inner, err := ack.MarshalBinary()
	if err != nil {
		return false
	}
	blob, err := encryption.BuildOnion(hops, inner)
	if err != nil {
		return false
	}
	if err := t.sendProbeBlob(hops[0].Addr, blob); err != nil {
		return false // the relay's own first hop is unreachable — a strike
	}

	select {
	case <-ch:
		return true
	case <-time.After(probeTimeout):
		return false
	case <-t.ctx.Done():
		return false
	}
}

// sendProbeBlob dials the relay directly with a short timeout (no long retry) and
// sends the probe as an ordinary relay packet.
func (t *Transfer) sendProbeBlob(addr string, blob []byte) error {
	conn, err := net.DialTimeout("tcp", addr, probeDialTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	pkt := protocol.NewPacket(protocol.PacketTypeRelay, blob, "", "")
	pkt.SourceNode = t.selfID
	pkt.Sign(t.signKey)
	return protocol.WritePacket(conn, pkt)
}
