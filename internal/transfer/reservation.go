package transfer

import (
	"bufio"
	"net"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/routing"
)

const (
	reservationKeepalive = 15 * time.Second // keepalive cadence on a held circuit
	reservationRetry     = 3 * time.Second  // backoff between reservation attempts
	maxReservationRelays = 2                // relays a NAT'd node reserves through
)

// reachableHost returns this node's best-known reachable host: the external
// address peers observed (behind NAT), falling back to the locally-determined
// host.
func (t *Transfer) reachableHost() string {
	if t.discovery != nil {
		if h := t.discovery.ExternalHost(); h != "" {
			return h
		}
	}
	return t.selfHost
}

// pickReservationRelay returns the first relay whose ID is one the destination
// holds a circuit reservation with, or nil.
func pickReservationRelay(relays []routing.Peer, relayIDs []string) *routing.Peer {
	want := make(map[string]bool, len(relayIDs))
	for _, id := range relayIDs {
		want[id] = true
	}
	for i := range relays {
		if want[relays[i].ID] {
			return &relays[i]
		}
	}
	return nil
}

// forwardToNextHop forwards a relay blob to the next hop, preferring a held
// circuit reservation when the next node reserved through us (behind NAT), and
// dialing its address otherwise.
func (t *Transfer) forwardToNextHop(nextNode, nextAddr string, blob []byte) {
	if rc := t.reservationFor(nextNode); rc != nil {
		if err := rc.send(t, blob); err == nil {
			t.metrics.IncForwarded()
			t.recordHop(HopForward, "reservation")
			return
		}
	}
	if err := t.sendRelayBlob(nextAddr, blob); err == nil {
		t.metrics.IncForwarded()
		t.recordHop(HopForward, nextAddr)
		return
	}
	// Undeliverable: hold it for the offline recipient if we offer store-and-forward.
	t.recordHop(HopDrop, "undeliverable")
	t.storeOffline(nextNode, blob)
}

// reservationFor returns the held connection for a node that reserved through
// us, or nil.
func (t *Transfer) reservationFor(nodeID string) *reservedConn {
	if nodeID == "" {
		return nil
	}
	t.resMu.Lock()
	defer t.resMu.Unlock()
	return t.reservations[nodeID]
}

// send writes a signed relay packet carrying blob over the held reservation
// connection.
func (rc *reservedConn) send(t *Transfer, blob []byte) error {
	pkt := protocol.NewPacket(protocol.PacketTypeRelay, blob, "", "")
	pkt.SourceNode = t.selfID
	pkt.Sign(t.signKey)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return protocol.WritePacket(rc.conn, pkt)
}

// serveReservation (relay side) registers a reserving node's connection and
// holds it open, forwarding that node's inbound traffic over it, until the
// connection closes.
func (t *Transfer) serveReservation(conn net.Conn, r *bufio.Reader, nodeID string) {
	if nodeID == "" {
		return
	}
	rc := &reservedConn{conn: conn}
	t.resMu.Lock()
	t.reservations[nodeID] = rc
	t.resMu.Unlock()

	// The recipient just came online: flush anything we held for it while offline.
	t.flushOffline(nodeID, rc)

	defer func() {
		t.resMu.Lock()
		if t.reservations[nodeID] == rc {
			delete(t.reservations, nodeID)
		}
		t.resMu.Unlock()
	}()

	// Hold the connection open, draining client->relay keepalives until close.
	for {
		if _, err := protocol.ReadPacket(r); err != nil {
			return
		}
	}
}

// maintainReservations (client side) periodically ensures this NAT'd node holds
// circuit reservations with a few reachable relays.
func (t *Transfer) maintainReservations() {
	ticker := time.NewTicker(reservationRetry)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.ensureReservations()
		}
	}
}

// ensureReservations starts reservation loops with up to maxReservationRelays
// discovered relays we are not already reserving with.
func (t *Transfer) ensureReservations() {
	// With autoRelay the loop always runs; only actively reserve while we believe
	// we need a relay (AutoNAT toggles this via SetNeedsRelay).
	if !t.needsRelay.Load() || t.discovery == nil {
		return
	}
	t.resMu.Lock()
	active := len(t.reservationClients)
	t.resMu.Unlock()
	if active >= maxReservationRelays {
		return
	}

	for _, n := range t.discovery.GetActiveNodes() {
		if active >= maxReservationRelays {
			return
		}
		if n.ID == t.selfID || len(n.PubKey) == 0 || !hasCapability(n.Capabilities, "relay") || t.isExcommunicated(n.ID) {
			continue
		}
		t.resMu.Lock()
		started := t.reservationClients[n.ID]
		if !started {
			t.reservationClients[n.ID] = true
		}
		t.resMu.Unlock()
		if started {
			continue
		}
		active++
		go t.reserveWith(n.ID, peerDialAddr(n))
	}
}

// reserveWith (client side) maintains a circuit reservation with one relay,
// reconnecting until the node stops.
func (t *Transfer) reserveWith(relayID, relayAddr string) {
	defer func() {
		t.resMu.Lock()
		delete(t.reservationClients, relayID)
		t.resMu.Unlock()
	}()
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}
		t.runReservation(relayID, relayAddr)
		t.setReserved(relayID, false)
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(reservationRetry):
		}
	}
}

// runReservation opens one reservation connection and serves it until it drops.
func (t *Transfer) runReservation(relayID, relayAddr string) {
	conn := dialWithRetries(relayAddr)
	if conn == nil {
		return
	}
	defer conn.Close()
	r := bufio.NewReader(conn)

	res := protocol.NewPacket(protocol.PacketTypeReservation, nil, "", relayID)
	res.SourceNode = t.selfID
	res.Sign(t.signKey)
	if err := protocol.WritePacket(conn, res); err != nil {
		return
	}
	t.setReserved(relayID, true)

	// Keepalive writer keeps the NAT mapping and connection alive.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(reservationKeepalive)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.ctx.Done():
				return
			case <-tick.C:
				ka := protocol.NewPacket(protocol.PacketTypeReservation, nil, "", relayID)
				ka.SourceNode = t.selfID
				ka.Sign(t.signKey)
				if err := protocol.WritePacket(conn, ka); err != nil {
					return
				}
			}
		}
	}()

	// Read forwarded relay packets the relay pushes to us and handle them.
	for {
		pkt, err := protocol.ReadPacket(r)
		if err != nil {
			return
		}
		if !pkt.Verify() || pkt.SourceNode != pkt.SignerID() {
			continue
		}
		if pkt.Type == protocol.PacketTypeRelay {
			t.handleRelay(pkt)
		}
	}
}

// setReserved records whether we hold a live reservation with relayID and
// re-advertises the set of reservation relays so peers can route to us.
func (t *Transfer) setReserved(relayID string, ok bool) {
	t.resMu.Lock()
	if ok {
		t.reservedIDs[relayID] = true
	} else {
		delete(t.reservedIDs, relayID)
	}
	ids := make([]string, 0, len(t.reservedIDs))
	for id := range t.reservedIDs {
		ids = append(ids, id)
	}
	t.resMu.Unlock()
	if t.discovery != nil {
		t.discovery.SetRelayIDs(ids)
	}
}
