package transfer

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/routing"
)

const (
	coverBaseInterval = 8 * time.Second // average gap between decoys
	coverPayloadSize  = 512             // random bytes carried by a decoy
)

// padPacket appends filler so the packet's marshaled size is an exact multiple of
// padCell, hiding payload length from on-wire size analysis. Under binary framing
// a Pad of length L adds exactly L bytes, so the boundary is hit precisely (no
// approximation).
func (t *Transfer) padPacket(pkt *protocol.Packet) {
	if t.padCell <= 0 {
		return
	}
	pkt.Pad = nil
	base := marshaledLen(pkt) // includes the empty Pad field's length prefix
	rem := base % t.padCell
	if rem == 0 {
		return // already cell-aligned
	}
	pkt.Pad = make([]byte, t.padCell-rem)
}

func marshaledLen(pkt *protocol.Packet) int {
	b, err := pkt.MarshalBinary()
	if err != nil {
		return 0
	}
	return len(b)
}

// applyJitter sleeps for a random duration up to relayJitter, blunting timing
// correlation across a forwarding hop.
func (t *Transfer) applyJitter() {
	if t.relayJitter <= 0 {
		return
	}
	select {
	case <-t.ctx.Done():
	case <-time.After(randDuration(t.relayJitter)):
	}
}

// maintainCover periodically emits decoy traffic indistinguishable from real
// forwarded transfers, so an observer cannot tell when this node is actually
// sending. Intervals are randomized to avoid a detectable cadence.
func (t *Transfer) maintainCover() {
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(coverBaseInterval + randDuration(coverBaseInterval)):
			t.sendCover()
		}
	}
}

// sendCover builds and dispatches one decoy along a random relay path. It is a
// PacketTypeRelay just like real traffic; the exit node peels it, sees the decoy
// flag, and drops it.
func (t *Transfer) sendCover() {
	if t.nodePriv == nil || t.discovery == nil || t.hopCount < 1 {
		return
	}
	relays := t.relayPeers(t.discovery.GetActiveNodes(), t.selfID)
	if len(relays) == 0 {
		return
	}

	// Terminate the decoy at one of the relays (sealed to its key), so it looks
	// like an ordinary transfer with that node as the destination.
	dest := relays[randIndex(len(relays))]
	others := make([]routing.Peer, 0, len(relays))
	for _, r := range relays {
		if r.ID != dest.ID {
			others = append(others, r)
		}
	}

	hops, err := (&routing.Planner{}).BuildPath(dest, others, t.hopCount-1)
	if err != nil {
		// Not enough distinct relays for extra hops; go straight to the exit.
		hops = []routing.Hop{{NodeID: dest.ID, Address: dest.Address, PubKey: dest.PubKey}}
	}
	onionHops, err := toOnionHops(hops)
	if err != nil {
		return
	}

	inner := t.buildDecoyInner()
	blob, err := encryption.BuildOnion(onionHops, inner)
	if err != nil {
		return
	}
	_ = t.sendRelayBlob(hops[0].Address, blob)
}

// buildDecoyInner builds a padded decoy inner packet carrying random bytes.
func (t *Transfer) buildDecoyInner() []byte {
	payload := make([]byte, coverPayloadSize)
	_, _ = rand.Read(payload)
	pkt := protocol.NewPacket(protocol.PacketTypeData, payload, "", "")
	pkt.Decoy = true
	t.padPacket(pkt)
	b, _ := pkt.MarshalBinary()
	return b
}

// randDuration returns a random duration in [0, max).
func randDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(randUint64() % uint64(max))
}

// randIndex returns a random index in [0, n).
func randIndex(n int) int {
	if n <= 0 {
		return 0
	}
	return int(randUint64() % uint64(n))
}

func randUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint64(b[:])
}
