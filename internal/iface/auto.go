package iface

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// AutoInterface is zero-configuration LAN peering: it discovers other SyncSwarm
// nodes on the same physical network with no bootstrap host, DNS seed, or
// broadcast-address configuration — the analogue of Reticulum's AutoInterface
// (Pillar / Phase 4 of RETICULUM_ALIGNMENT.md).
//
// It works over IPv6 **link-local multicast**: every node joins a fixed
// link-local group on each eligible network interface, so a Send(Broadcast, …)
// reaches every SyncSwarm node on the same link, and their frames arrive back
// with a link-scoped source address (including the interface zone). Link-local
// multicast never leaves the LAN and needs no router configuration, so plugging
// two machines into the same switch/Wi-Fi is enough for them to find each other.
//
// A node hears its own multicast frames on some platforms; that is harmless —
// announces are self-signed and the discovery layer ignores a node's own NodeID.
type AutoInterface struct {
	name   string
	group  *net.UDPAddr
	mtu    int
	frames chan InboundFrame
	done   chan struct{}

	closeOnce sync.Once
	wg        sync.WaitGroup // one per member readLoop; frames closed after all exit

	members []*autoMember // one joined interface each
}

// autoMember is one interface on which we've joined the group. conn receives
// multicast (and is reused to send, with the interface zone on the destination).
type autoMember struct {
	ifi  net.Interface
	conn *net.UDPConn
}

// AutoGroup is the fixed IPv6 link-local multicast group SyncSwarm nodes rendezvous
// on (ff02::/16 = link-local scope), and AutoPort the port they bind. Changing
// either partitions a node onto its own private LAN segment.
const (
	AutoGroup = "ff02::7377" // "sw" in the low bytes; link-local scope
	AutoPort  = 64520
)

// ErrNoMulticast is returned when no eligible (up, multicast-capable, non-loopback)
// network interface is available to join the group.
var ErrNoMulticast = errors.New("iface auto: no multicast-capable interface")

// NewAutoInterface joins the SyncSwarm link-local multicast group on every
// eligible interface. It fails with ErrNoMulticast if the host has none (e.g. a
// container with only loopback), so a caller can fall back to explicit bootstrap.
func NewAutoInterface(name string) (*AutoInterface, error) {
	group := &net.UDPAddr{IP: net.ParseIP(AutoGroup), Port: AutoPort}
	if group.IP == nil {
		return nil, fmt.Errorf("iface auto: bad group %q", AutoGroup)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("iface auto: list interfaces: %w", err)
	}

	a := &AutoInterface{
		name:   name,
		group:  group,
		mtu:    udpMTU,
		frames: make(chan InboundFrame, 256),
		done:   make(chan struct{}),
	}

	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 ||
			ifi.Flags&net.FlagMulticast == 0 ||
			ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !hasLinkLocalV6(ifi) {
			continue // no IPv6 link-local route here; sends would be unreachable
		}
		conn, err := net.ListenMulticastUDP("udp6", &ifi, group)
		if err != nil {
			continue // this interface can't join (permissions, no IPv6); skip it
		}
		a.members = append(a.members, &autoMember{ifi: ifi, conn: conn})
	}

	if len(a.members) == 0 {
		return nil, ErrNoMulticast
	}

	for _, m := range a.members {
		a.wg.Add(1)
		go a.readLoop(m)
	}
	go func() { a.wg.Wait(); close(a.frames) }()
	return a, nil
}

func (a *AutoInterface) Name() string { return a.name }
func (a *AutoInterface) Kind() Kind   { return KindUDP } // an IP datagram medium, like UDP
func (a *AutoInterface) Caps() Caps {
	return Caps{MTU: a.mtu, Bitrate: 100_000_000, Broadcast: true, FullDuplex: true}
}

func (a *AutoInterface) Frames() <-chan InboundFrame { return a.frames }

// Send fans a Broadcast frame out to the group on every joined interface;
// a non-Broadcast addr is delivered unicast (its zone, if any, carries the link).
func (a *AutoInterface) Send(addr string, frame []byte) error {
	if len(frame) > a.mtu {
		return fmt.Errorf("iface auto: frame %d exceeds MTU %d", len(frame), a.mtu)
	}
	select {
	case <-a.done:
		return ErrClosed
	default:
	}

	if addr != Broadcast {
		dst, err := net.ResolveUDPAddr("udp6", addr)
		if err != nil {
			return fmt.Errorf("iface auto: resolve dest %q: %w", addr, err)
		}
		// Any joined socket can carry the unicast datagram; the zone in dst
		// (e.g. fe80::1%eth0) selects the link.
		return a.writeFrom(a.members[0], frame, dst)
	}

	// Fan out; a broadcast succeeds if at least one link carried it, so a single
	// down/unreachable interface doesn't fail LAN discovery on the others.
	var lastErr error
	sent := false
	for _, m := range a.members {
		dst := &net.UDPAddr{IP: a.group.IP, Port: a.group.Port, Zone: m.ifi.Name}
		if err := a.writeFrom(m, frame, dst); err != nil {
			lastErr = err
			continue
		}
		sent = true
	}
	if !sent {
		return lastErr
	}
	return nil
}

// hasLinkLocalV6 reports whether ifi has an IPv6 link-local unicast address, i.e.
// a usable route for link-local multicast. Without one, joining the group
// succeeds but every send returns "network is unreachable".
func hasLinkLocalV6(ifi net.Interface) bool {
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func (a *AutoInterface) writeFrom(m *autoMember, frame []byte, dst *net.UDPAddr) error {
	if _, err := m.conn.WriteToUDP(frame, dst); err != nil {
		select {
		case <-a.done:
			return ErrClosed
		default:
			return fmt.Errorf("iface auto: send on %s: %w", m.ifi.Name, err)
		}
	}
	return nil
}

func (a *AutoInterface) Close() error {
	a.closeOnce.Do(func() {
		close(a.done)
		for _, m := range a.members {
			m.conn.Close() // unblocks its readLoop
		}
	})
	return nil
}

func (a *AutoInterface) readLoop(m *autoMember) {
	defer a.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, src, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed (Close) or fatal read error
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case a.frames <- InboundFrame{Addr: src.String(), Data: data}:
		case <-a.done:
			return
		}
	}
}
