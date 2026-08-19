package iface

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// tcpMTU is the largest frame the TCP interfaces will send in one call. TCP is a
// stream so there is no hard MTU; this bounds a single logical frame and guards
// the length-prefix reader against absurd allocations.
const tcpMTU = 1 << 20 // 1 MiB

// TCP frames are length-prefixed: a 4-byte big-endian length followed by the
// payload. This turns TCP's byte stream back into discrete frames.

func writeFrame(w io.Writer, frame []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(frame)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(frame)
	return err
}

func readFrame(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > tcpMTU {
		return nil, fmt.Errorf("iface tcp: frame length %d exceeds cap %d", n, tcpMTU)
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

// tcpConn wraps a net.Conn with a write mutex so concurrent Send calls are safe.
type tcpConn struct {
	c  net.Conn
	mu sync.Mutex
}

func (tc *tcpConn) send(frame []byte) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return writeFrame(tc.c, frame)
}

// --- TCP server ------------------------------------------------------------

// TCPServerInterface listens for inbound TCP connections and exposes each as a
// framed peer. Send(addr, …) targets the accepted connection whose remote
// address is addr; Send(Broadcast, …) fans out to every connected peer.
type TCPServerInterface struct {
	name      string
	ln        net.Listener
	frames    chan InboundFrame
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup // acceptLoop + one per readConn; frames closed after all exit

	mu    sync.RWMutex
	conns map[string]*tcpConn // remoteAddr -> conn
}

// NewTCPServerInterface binds a TCP listener on listenAddr (e.g. ":64513").
func NewTCPServerInterface(name, listenAddr string) (*TCPServerInterface, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("iface tcp-server: listen %q: %w", listenAddr, err)
	}
	s := &TCPServerInterface{
		name:   name,
		ln:     ln,
		frames: make(chan InboundFrame, 256),
		done:   make(chan struct{}),
		conns:  make(map[string]*tcpConn),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	// Close frames only once every sender goroutine (acceptLoop + readers) has
	// exited, so a send can never race the close.
	go func() { s.wg.Wait(); close(s.frames) }()
	return s, nil
}

func (s *TCPServerInterface) Name() string { return s.name }
func (s *TCPServerInterface) Kind() Kind   { return KindTCPServer }
func (s *TCPServerInterface) Caps() Caps {
	return Caps{MTU: tcpMTU, Bitrate: 100_000_000, Broadcast: true, FullDuplex: true}
}

// Addr reports the listener's bound address (useful with ":0").
func (s *TCPServerInterface) Addr() net.Addr { return s.ln.Addr() }

func (s *TCPServerInterface) Frames() <-chan InboundFrame { return s.frames }

func (s *TCPServerInterface) Send(addr string, frame []byte) error {
	if addr == Broadcast {
		s.mu.RLock()
		targets := make([]*tcpConn, 0, len(s.conns))
		for _, c := range s.conns {
			targets = append(targets, c)
		}
		s.mu.RUnlock()
		var firstErr error
		for _, c := range targets {
			if err := c.send(frame); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	s.mu.RLock()
	c := s.conns[addr]
	s.mu.RUnlock()
	if c == nil {
		return fmt.Errorf("iface tcp-server: no connected peer %q", addr)
	}
	return c.send(frame)
}

func (s *TCPServerInterface) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.ln.Close() // unblocks acceptLoop
		s.mu.Lock()
		for _, c := range s.conns {
			c.c.Close() // unblocks readConn goroutines
		}
		s.conns = map[string]*tcpConn{}
		s.mu.Unlock()
		// frames is closed by the wg.Wait goroutine once all senders exit.
	})
	return nil
}

func (s *TCPServerInterface) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		tc := &tcpConn{c: conn}
		addr := conn.RemoteAddr().String()
		s.mu.Lock()
		s.conns[addr] = tc
		s.mu.Unlock()
		s.wg.Add(1)
		go s.readConn(addr, tc)
	}
}

func (s *TCPServerInterface) readConn(addr string, tc *tcpConn) {
	defer func() {
		tc.c.Close()
		s.mu.Lock()
		delete(s.conns, addr)
		s.mu.Unlock()
		s.wg.Done()
	}()
	r := bufio.NewReader(tc.c)
	for {
		frame, err := readFrame(r)
		if err != nil {
			return
		}
		select {
		case s.frames <- InboundFrame{Addr: addr, Data: frame}:
		case <-s.done:
			return
		}
	}
}

// --- TCP client ------------------------------------------------------------

// TCPClientInterface dials a single known peer (a transport node) and keeps the
// connection framed. This is the graceful replacement for a "bootstrap peer":
// point it at one reachable node to bridge into a wider mesh over the internet.
// v1 does not auto-reconnect; the core is expected to re-open on failure.
type TCPClientInterface struct {
	name      string
	remote    string
	conn      *tcpConn
	frames    chan InboundFrame
	done      chan struct{}
	closeOnce sync.Once
}

// NewTCPClientInterface dials remoteAddr (e.g. "relay.example.net:64513").
func NewTCPClientInterface(name, remoteAddr string) (*TCPClientInterface, error) {
	conn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("iface tcp-client: dial %q: %w", remoteAddr, err)
	}
	c := &TCPClientInterface{
		name:   name,
		remote: conn.RemoteAddr().String(),
		conn:   &tcpConn{c: conn},
		frames: make(chan InboundFrame, 256),
		done:   make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

func (c *TCPClientInterface) Name() string { return c.name }
func (c *TCPClientInterface) Kind() Kind   { return KindTCPClient }
func (c *TCPClientInterface) Caps() Caps {
	return Caps{MTU: tcpMTU, Bitrate: 100_000_000, Broadcast: false, FullDuplex: true}
}

func (c *TCPClientInterface) Frames() <-chan InboundFrame { return c.frames }

// Send writes to the single upstream connection; addr is ignored (there is one
// peer), so both Send(Broadcast, …) and Send(remote, …) reach it.
func (c *TCPClientInterface) Send(_ string, frame []byte) error {
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	return c.conn.send(frame)
}

func (c *TCPClientInterface) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.conn.c.Close() // unblocks readLoop, which closes frames on exit
	})
	return nil
}

func (c *TCPClientInterface) readLoop() {
	defer close(c.frames) // sole sender closes the channel
	r := bufio.NewReader(c.conn.c)
	for {
		frame, err := readFrame(r)
		if err != nil {
			return
		}
		select {
		case c.frames <- InboundFrame{Addr: c.remote, Data: frame}:
		case <-c.done:
			return
		}
	}
}
