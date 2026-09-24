package discovery

import (
	"encoding/json"
	"net"
	"strconv"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

const (
	reachCheckInterval = 90 * time.Second // how often to re-test reachability
	reachProbePeers    = 3                // peers asked to dial back per round
	reachMinResponders = 2                // responders for an immediate unreachable verdict
	// reachSoloRounds is how many consecutive rounds a lone responder must report
	// failure before we accept its verdict. Requiring two responders outright makes
	// AutoNAT inert in a small swarm — a relay with one peer can never conclude it
	// is unreachable, so it keeps advertising "relay" while nothing can dial it and
	// poisons every other node's path selection. Observed live on a two-relay
	// network. Demanding sustained agreement from the one peer we have keeps the
	// caution that motivated the threshold (a single transient failure must not
	// demote a healthy relay) without leaving the mechanism switched off.
	reachSoloRounds   = 3
	reachRoundTimeout = 4 * time.Second // wait for dial-back results
	reachDialTimeout  = 3 * time.Second // a peer's TCP dial-back timeout
)

// EnableReachabilityChecks turns on AutoNAT: the node periodically asks peers to
// dial its data port back and calls onChange(reachable) whenever the conclusion
// flips. It is a no-op if the node has no signing key or advertised data port yet
// (set via SetSigningKey / SetIdentity before Start). Safe to call before Start.
func (d *Discovery) EnableReachabilityChecks(onChange func(reachable bool)) {
	d.reachMu.Lock()
	d.reachEnabled = true
	d.onReachability = onChange
	d.reachMu.Unlock()
}

// Reachable reports the latest determination and whether one has been made yet.
func (d *Discovery) Reachable() (reachable, known bool) {
	d.reachMu.Lock()
	defer d.reachMu.Unlock()
	return d.reachable, d.reachKnown
}

// checkReachability runs one dial-back round: it asks a few active peers to
// connect to this node's data port and tallies their results. A single success
// proves reachability; only enough all-failure responses conclude unreachable
// (too few responses is inconclusive and leaves the current state unchanged).
func (d *Discovery) checkReachability() {
	d.mu.RLock()
	dataPort := d.port
	d.mu.RUnlock()
	if dataPort == 0 {
		return // don't know our own data port yet
	}

	peers := d.probeTargets(reachProbePeers)
	if len(peers) == 0 {
		return // no one to ask yet
	}

	nonce := d.nonceCounter.Add(1)
	ch := make(chan bool, len(peers))
	d.reachMu.Lock()
	d.reachPending[nonce] = ch
	d.reachMu.Unlock()
	defer func() {
		d.reachMu.Lock()
		delete(d.reachPending, nonce)
		d.reachMu.Unlock()
	}()

	for _, addr := range peers {
		d.sendReachability(addr, protocol.PacketTypeReachabilityCheck, nonce, dataPort, false)
	}

	responses, reachable := 0, false
	timeout := time.After(reachRoundTimeout)
	for responses < len(peers) {
		select {
		case ok := <-ch:
			responses++
			if ok {
				reachable = true
			}
		case <-timeout:
			responses = len(peers) // stop waiting
		case <-d.ctx.Done():
			return
		}
		if reachable {
			break // one external success is conclusive
		}
	}

	d.concludeRound(responses, reachable)
}

// probeTargets returns up to n dialable UDP addresses of active peers.
func (d *Discovery) probeTargets(n int) []*net.UDPAddr {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*net.UDPAddr, 0, n)
	for _, node := range d.nodes {
		if !node.Active || node.ID == d.selfID {
			continue
		}
		if addr, err := net.ResolveUDPAddr("udp", node.Address); err == nil {
			out = append(out, addr)
			if len(out) >= n {
				break
			}
		}
	}
	return out
}

// handleReachabilityCheck (peer side) dials the requester's data port at the
// address we received the check from and reports whether it connected.
func (d *Discovery) handleReachabilityCheck(from *net.UDPAddr, p protocol.ReachabilityPayload) {
	host, _, err := net.SplitHostPort(from.String())
	if err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(p.DataPort)))

	reachable := false
	if conn, err := net.DialTimeout("tcp", target, reachDialTimeout); err == nil {
		reachable = true
		conn.Close()
	}
	d.sendReachability(from, protocol.PacketTypeReachabilityResult, p.Nonce, 0, reachable)
}

// handleReachabilityResult (requester side) delivers a dial-back outcome to the
// round waiting on its nonce.
func (d *Discovery) handleReachabilityResult(p protocol.ReachabilityPayload) {
	d.reachMu.Lock()
	ch := d.reachPending[p.Nonce]
	d.reachMu.Unlock()
	if ch != nil {
		select {
		case ch <- p.Reachable:
		default:
		}
	}
}

// setReachable records a new determination and fires the change callback when it
// flips (or on the first determination).
func (d *Discovery) setReachable(reachable bool) {
	d.reachMu.Lock()
	changed := !d.reachKnown || d.reachable != reachable
	d.reachKnown = true
	d.reachable = reachable
	cb := d.onReachability
	d.reachMu.Unlock()
	if changed && cb != nil {
		cb(reachable)
	}
}

// sendReachability sends a signed reachability check or result to addr.
func (d *Discovery) sendReachability(addr *net.UDPAddr, typ protocol.PacketType, nonce uint64, dataPort uint16, reachable bool) {
	payload := protocol.ReachabilityPayload{
		NodeID:    d.selfID,
		Nonce:     nonce,
		DataPort:  dataPort,
		Reachable: reachable,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	packet := protocol.NewPacket(typ, data, "ANY", "")
	packet.SourceNode = d.selfID
	packet.Sign(d.signPriv)
	if packetBytes, err := packet.MarshalBinary(); err == nil {
		d.iface.Send(addr.String(), packetBytes)
	}
}

// concludeRound turns one round's tally into a verdict, or leaves the current one
// standing when the evidence is too thin. Split out so the decision rule is
// testable without sockets.
func (d *Discovery) concludeRound(responses int, reachable bool) {
	if reachable {
		d.soloFailures = 0
		d.setReachable(true)
		return
	}
	if responses >= reachMinResponders {
		d.soloFailures = 0
		d.setReachable(false)
		return
	}
	if responses == 0 {
		return // nobody answered: says nothing either way
	}
	// A single responder reporting failure. Accept it only once it has said so
	// consistently, so one flaky peer cannot demote a healthy relay.
	d.soloFailures++
	if d.soloFailures >= reachSoloRounds {
		d.setReachable(false)
	}
}
