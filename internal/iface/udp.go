package iface

import (
	"fmt"
	"net"
	"sync"
)

// udpMTU is a conservative datagram payload cap that avoids IP fragmentation on
// typical paths (well under the 1500-byte Ethernet MTU minus IP/UDP headers).
const udpMTU = 1400

// SafeDatagramMTU is the exported fragmentation-safe datagram frame size higher
// layers can target when sizing payloads for an unknown IP path.
const SafeDatagramMTU = udpMTU

// UDPInterface is a broadcast-capable datagram transport over a single UDP
// socket. Send(Broadcast, …) goes to the configured broadcast address; Send to a
// "host:port" goes unicast. It is the v1 workhorse for discovery and announces.
//
// Two size limits: mtu is the *advertised* fragmentation-safe frame size (via
// Caps, so higher layers size payloads to avoid IP fragmentation), while sendCap
// is the hard reject limit. They differ for discovery, which advertises a small
// sizing MTU but still accepts large gossip datagrams (relying on IP
// fragmentation for those legacy sends).
type UDPInterface struct {
	name      string
	conn      *net.UDPConn
	broadcast *net.UDPAddr // where Broadcast frames go (may be nil to disable)
	mtu       int          // advertised (sizing) MTU reported via Caps
	sendCap   int          // hard limit; datagrams larger than this are rejected
	frames    chan InboundFrame
	done      chan struct{}
	closeOnce sync.Once
}

// NewUDPInterface opens a UDP socket bound to listenAddr (e.g. ":64512" or ":0"
// for an ephemeral port) and routes Broadcast frames to broadcastAddr (e.g.
// "255.255.255.255:64512"); pass "" to disable broadcast on this interface. It
// uses the default datagram MTU (udpMTU); use NewUDPInterfaceMTU to override it.
func NewUDPInterface(name, listenAddr, broadcastAddr string) (*UDPInterface, error) {
	return NewUDPInterfaceMTU(name, listenAddr, broadcastAddr, udpMTU)
}

// NewUDPInterfaceMTU is NewUDPInterface with an explicit MTU used both as the
// advertised sizing MTU and the hard send cap. Use NewUDPInterfaceSized to make
// them differ (advertise a small fragmentation-safe MTU while still accepting
// large datagrams).
func NewUDPInterfaceMTU(name, listenAddr, broadcastAddr string, mtu int) (*UDPInterface, error) {
	return NewUDPInterfaceSized(name, listenAddr, broadcastAddr, mtu, mtu)
}

// NewUDPInterfaceSized separates the advertised (sizing) MTU from the hard send
// cap. sizingMTU is reported via Caps so higher layers size payloads to avoid IP
// fragmentation; sendCap is the largest datagram Send will emit (>= sizingMTU),
// letting legacy large-datagram callers (gossip) through while payload sizing
// still targets the fragmentation-safe MTU.
func NewUDPInterfaceSized(name, listenAddr, broadcastAddr string, sizingMTU, sendCap int) (*UDPInterface, error) {
	la, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("iface udp: resolve listen %q: %w", listenAddr, err)
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, fmt.Errorf("iface udp: listen %q: %w", listenAddr, err)
	}

	var ba *net.UDPAddr
	if broadcastAddr != "" {
		if ba, err = net.ResolveUDPAddr("udp", broadcastAddr); err != nil {
			conn.Close()
			return nil, fmt.Errorf("iface udp: resolve broadcast %q: %w", broadcastAddr, err)
		}
	}

	if sendCap < sizingMTU {
		sendCap = sizingMTU
	}
	u := &UDPInterface{
		name:      name,
		conn:      conn,
		broadcast: ba,
		mtu:       sizingMTU,
		sendCap:   sendCap,
		frames:    make(chan InboundFrame, 256),
		done:      make(chan struct{}),
	}
	go u.readLoop()
	return u, nil
}

func (u *UDPInterface) Name() string { return u.name }
func (u *UDPInterface) Kind() Kind   { return KindUDP }

func (u *UDPInterface) Caps() Caps {
	return Caps{MTU: u.mtu, Bitrate: 100_000_000, Broadcast: u.broadcast != nil, FullDuplex: true}
}

// LocalAddr reports the socket's bound address, useful when listening on an
// ephemeral port (":0").
func (u *UDPInterface) LocalAddr() net.Addr { return u.conn.LocalAddr() }

func (u *UDPInterface) Send(addr string, frame []byte) error {
	if len(frame) > u.sendCap {
		return fmt.Errorf("iface udp: frame %d exceeds send cap %d", len(frame), u.sendCap)
	}
	dst := u.broadcast
	if addr != Broadcast {
		var err error
		if dst, err = net.ResolveUDPAddr("udp", addr); err != nil {
			return fmt.Errorf("iface udp: resolve dest %q: %w", addr, err)
		}
	}
	if dst == nil {
		return fmt.Errorf("iface udp: broadcast disabled and no address given")
	}
	if _, err := u.conn.WriteToUDP(frame, dst); err != nil {
		select {
		case <-u.done:
			return ErrClosed
		default:
			return fmt.Errorf("iface udp: send: %w", err)
		}
	}
	return nil
}

func (u *UDPInterface) Frames() <-chan InboundFrame { return u.frames }

func (u *UDPInterface) Close() error {
	u.closeOnce.Do(func() {
		close(u.done)
		u.conn.Close() // unblocks readLoop's ReadFromUDP
	})
	return nil
}

func (u *UDPInterface) readLoop() {
	defer close(u.frames)
	buf := make([]byte, 65536)
	for {
		n, src, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed (Close) or fatal read error
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case u.frames <- InboundFrame{Addr: src.String(), Data: data}:
		case <-u.done:
			return
		}
	}
}
