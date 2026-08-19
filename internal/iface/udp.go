package iface

import (
	"fmt"
	"net"
	"sync"
)

// udpMTU is a conservative datagram payload cap that avoids IP fragmentation on
// typical paths (well under the 1500-byte Ethernet MTU minus IP/UDP headers).
const udpMTU = 1400

// UDPInterface is a broadcast-capable datagram transport over a single UDP
// socket. Send(Broadcast, …) goes to the configured broadcast address; Send to a
// "host:port" goes unicast. It is the v1 workhorse for discovery and announces.
type UDPInterface struct {
	name      string
	conn      *net.UDPConn
	broadcast *net.UDPAddr // where Broadcast frames go (may be nil to disable)
	mtu       int          // max send frame; datagrams larger are rejected
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

// NewUDPInterfaceMTU is NewUDPInterface with an explicit send MTU. A larger MTU
// is used by legacy datagram callers (e.g. gossip) that may emit packets above
// the fragmentation-avoiding default; the OS still enforces the true UDP limit.
func NewUDPInterfaceMTU(name, listenAddr, broadcastAddr string, mtu int) (*UDPInterface, error) {
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

	u := &UDPInterface{
		name:      name,
		conn:      conn,
		broadcast: ba,
		mtu:       mtu,
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
	if len(frame) > u.mtu {
		return fmt.Errorf("iface udp: frame %d exceeds MTU %d", len(frame), u.mtu)
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
