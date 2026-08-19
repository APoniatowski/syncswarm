package discovery

import (
	"encoding/json"
	"net"
	"time"

	"github.com/APoniatowski/syncswarm/internal/dht"
	"github.com/APoniatowski/syncswarm/internal/protocol"
)

const findNodeTimeout = 2 * time.Second // wait for a single FIND_NODE reply

// rtUpdate records a sighting of a node in the Kademlia routing table using the
// UDP address it was seen at. No-op when the DHT is disabled or the ID is not a
// valid DHT key.
func (d *Discovery) rtUpdate(nodeID, udpAddr string, port uint16) {
	if d.rt == nil || nodeID == d.selfID {
		return
	}
	id, err := dht.ParseID(nodeID)
	if err != nil {
		return
	}
	d.rt.Update(dht.Contact{ID: id, Address: udpAddr, Port: port})
}

// handleFindNode answers a FIND_NODE query with the contacts we know closest to
// the requested target, enriched with routing keys from the local node table.
func (d *Discovery) handleFindNode(addr *net.UDPAddr, fn protocol.FindNodePayload) {
	if d.rt == nil {
		return
	}
	target, err := dht.ParseID(fn.Target)
	if err != nil {
		return
	}

	closest := d.rt.Closest(target, dht.DefaultK)
	contacts := make([]protocol.DHTContact, 0, len(closest))

	d.mu.RLock()
	for _, c := range closest {
		hexID := c.ID.String()
		if hexID == fn.NodeID {
			continue // don't echo the requester back to itself
		}
		dc := protocol.DHTContact{NodeID: hexID, Address: c.Address, Port: c.Port}
		if n, ok := d.nodes[hexID]; ok {
			dc.PubKey = n.PubKey
			dc.SignKey = n.SignKey
			dc.MLKEMPub = n.MLKEMPub
			if n.Port != 0 {
				dc.Port = n.Port
			}
		}
		contacts = append(contacts, dc)
	}
	d.mu.RUnlock()

	d.sendJSON(fn.NodeID, addr, protocol.PacketTypeFindNodeReply, protocol.FindNodeReplyPayload{
		Nonce:    fn.Nonce,
		Target:   fn.Target,
		Contacts: contacts,
	})
}

// handleFindNodeReply learns the returned contacts and delivers them to the
// lookup waiting on this nonce.
func (d *Discovery) handleFindNodeReply(fr protocol.FindNodeReplyPayload) {
	d.learnContacts(fr.Contacts)

	d.lookupMu.Lock()
	ch, ok := d.lookups[fr.Nonce]
	d.lookupMu.Unlock()
	if ok {
		select {
		case ch <- fr.Contacts:
		default:
		}
	}
}

// learnContacts folds FIND_NODE-returned contacts into both the node table and
// the routing table, honoring the key-binding invariant (NodeID == hash(SignKey)).
func (d *Discovery) learnContacts(contacts []protocol.DHTContact) {
	for _, c := range contacts {
		if c.NodeID == "" || c.NodeID == d.selfID || len(c.SignKey) == 0 {
			continue
		}
		if protocol.DeriveNodeID(c.SignKey) != c.NodeID {
			continue // reject unbound identities
		}
		d.updateNode(c.NodeID, c.Address, c.PubKey, c.SignKey, c.Port, nil, nil, c.MLKEMPub)
	}
}

// sendFindNode issues one FIND_NODE query to contact for target and waits for its
// reply contacts, or returns nil on timeout. Used as the Lookup query callback.
func (d *Discovery) sendFindNode(contact dht.Contact, target string) []dht.Contact {
	nonce := d.nonceCounter.Add(1)
	ch := make(chan []protocol.DHTContact, 1)
	d.lookupMu.Lock()
	d.lookups[nonce] = ch
	d.lookupMu.Unlock()
	defer func() {
		d.lookupMu.Lock()
		delete(d.lookups, nonce)
		d.lookupMu.Unlock()
	}()

	d.mu.RLock()
	pubKey, port := d.pubKey, d.port
	d.mu.RUnlock()

	addr, err := net.ResolveUDPAddr("udp", contact.Address)
	if err != nil {
		return nil
	}
	d.sendJSON(contact.ID.String(), addr, protocol.PacketTypeFindNode, protocol.FindNodePayload{
		NodeID: d.selfID,
		PubKey: pubKey,
		Port:   port,
		Target: target,
		Nonce:  nonce,
	})

	select {
	case reply := <-ch:
		out := make([]dht.Contact, 0, len(reply))
		for _, c := range reply {
			id, err := dht.ParseID(c.NodeID)
			if err != nil {
				continue
			}
			out = append(out, dht.Contact{ID: id, Address: c.Address, Port: c.Port})
		}
		return out
	case <-time.After(findNodeTimeout):
		return nil
	case <-d.ctx.Done():
		return nil
	}
}

// FindNode runs an iterative Kademlia lookup for the hex node ID and returns the
// located node once converged, or false if it could not be found. It works even
// when the target is not in the local table, by asking successively closer peers.
// When the DHT is disabled (symbolic self ID), it falls back to a local lookup.
func (d *Discovery) FindNode(targetHex string) (*Node, bool) {
	if node, ok := d.lookupLocal(targetHex); ok {
		return node, true
	}
	if d.rt == nil {
		return nil, false
	}
	target, err := dht.ParseID(targetHex)
	if err != nil {
		return nil, false
	}

	d.rt.Lookup(target, dht.DefaultK, dht.DefaultAlpha, dht.DefaultMaxRounds, func(c dht.Contact) []dht.Contact {
		return d.sendFindNode(c, targetHex)
	})

	// The lookup populated the node table via learnContacts; read the result out.
	return d.lookupLocal(targetHex)
}

func (d *Discovery) lookupLocal(targetHex string) (*Node, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if n, ok := d.nodes[targetHex]; ok {
		cp := *n
		return &cp, true
	}
	return nil, false
}

// sendJSON marshals payload as a signed discovery packet of the given type and
// sends it to nodeID at addr, routing over the interface that reaches nodeID (a
// bridge if that is where it was heard, else the primary UDP interface).
func (d *Discovery) sendJSON(nodeID string, addr *net.UDPAddr, typ protocol.PacketType, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	packet := protocol.NewPacket(typ, data, "ANY", "")
	packet.SourceNode = d.selfID
	packet.Sign(d.signPriv)
	packetBytes, err := packet.MarshalBinary()
	if err != nil {
		return
	}
	d.ifaceFor(nodeID).Send(addr.String(), packetBytes)
}
