package iface

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
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

	psk []byte // optional bridge PSK; empty means an open bridge

	mu    sync.RWMutex
	conns map[string]*tcpConn // remoteAddr -> conn
}

// NewTCPServerInterface binds a TCP listener on listenAddr (e.g. ":64513"),
// accepting any peer that connects.
func NewTCPServerInterface(name, listenAddr string) (*TCPServerInterface, error) {
	return NewTCPServerInterfaceAuth(name, listenAddr, nil)
}

// NewTCPServerInterfaceAuth is NewTCPServerInterface with an optional pre-shared
// key: when psk is non-empty, a peer must complete the mutual handshake before any
// frame it sends is read, so only holders of the key can attach a bridge. An empty
// psk leaves the bridge open (the default for a public seed).
func NewTCPServerInterfaceAuth(name, listenAddr string, psk []byte) (*TCPServerInterface, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("iface tcp-server: listen %q: %w", listenAddr, err)
	}
	s := &TCPServerInterface{
		name:   name,
		psk:    psk,
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
		// Authenticate off the accept path: a peer that connects and then stalls
		// must not hold up everyone else's connections.
		s.wg.Add(1)
		go s.acceptOne(conn)
	}
}

// acceptOne completes the optional PSK handshake, then serves the connection. The
// reader is created before the handshake and handed to readConn, so bytes the peer
// pipelined behind its proof are not lost.
func (s *TCPServerInterface) acceptOne(conn net.Conn) {
	defer s.wg.Done()
	r := bufio.NewReader(conn)
	if err := bridgeAuthServer(conn, r, s.psk); err != nil {
		conn.Close()
		return
	}
	tc := &tcpConn{c: conn}
	addr := conn.RemoteAddr().String()
	s.mu.Lock()
	s.conns[addr] = tc
	s.mu.Unlock()
	s.wg.Add(1)
	s.readConn(addr, tc, r)
}

func (s *TCPServerInterface) readConn(addr string, tc *tcpConn, r *bufio.Reader) {
	defer func() {
		tc.c.Close()
		s.mu.Lock()
		delete(s.conns, addr)
		s.mu.Unlock()
		s.wg.Done()
	}()
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

// Reconnect backoff bounds for a dropped bridge.
const (
	reconnectMin = 1 * time.Second
	reconnectMax = 30 * time.Second
	dialTimeout  = 10 * time.Second
)

// TCPClientInterface dials a single known peer (a transport node) and keeps the
// connection framed — the graceful replacement for a "bootstrap peer": point it
// at one reachable node to bridge into a wider mesh over the internet. It
// **auto-reconnects**: if the connection drops, it redials with exponential
// backoff (keeping Frames() open across reconnects) until it succeeds or Close is
// called, so a bridge self-heals after a transient outage.
type TCPClientInterface struct {
	name      string
	dialAddr  string
	frames    chan InboundFrame
	done      chan struct{}
	closeOnce sync.Once
	closed    chan struct{} // closed when the run loop has fully exited
	ctx       context.Context
	cancel    context.CancelFunc // cancels an in-flight redial on Close

	psk []byte // optional bridge PSK; re-proven on every reconnect

	mu     sync.Mutex
	conn   *tcpConn      // current connection, or nil while (re)connecting
	reader *bufio.Reader // buffered reader bound to conn
}

// NewTCPClientInterface dials remoteAddr (e.g. "relay.example.net:64513"). The
// first dial is synchronous so a misconfigured address fails fast; subsequent
// drops are recovered automatically by the reconnect loop.
func NewTCPClientInterface(name, remoteAddr string) (*TCPClientInterface, error) {
	return NewTCPClientInterfaceAuth(name, remoteAddr, nil)
}

// NewTCPClientInterfaceAuth is NewTCPClientInterface with an optional pre-shared
// key. The handshake is mutual, so a non-empty psk also proves the far side is the
// intended bridge and not an impostor on the same address. It is re-run on every
// reconnect — a bridge that comes back must re-authenticate.
func NewTCPClientInterfaceAuth(name, remoteAddr string, psk []byte) (*TCPClientInterface, error) {
	conn, err := net.DialTimeout("tcp", remoteAddr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("iface tcp-client: dial %q: %w", remoteAddr, err)
	}
	r := bufio.NewReader(conn)
	if err := bridgeAuthClient(conn, r, psk); err != nil {
		conn.Close()
		return nil, fmt.Errorf("iface tcp-client: %q: %w", remoteAddr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &TCPClientInterface{
		name:     name,
		dialAddr: remoteAddr,
		frames:   make(chan InboundFrame, 256),
		done:     make(chan struct{}),
		closed:   make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
		psk:      psk,
		conn:     &tcpConn{c: conn},
		reader:   r,
	}
	go c.run()
	return c, nil
}

func (c *TCPClientInterface) Name() string { return c.name }
func (c *TCPClientInterface) Kind() Kind   { return KindTCPClient }
func (c *TCPClientInterface) Caps() Caps {
	return Caps{MTU: tcpMTU, Bitrate: 100_000_000, Broadcast: false, FullDuplex: true}
}

func (c *TCPClientInterface) Frames() <-chan InboundFrame { return c.frames }

// Send writes to the current upstream connection; addr is ignored (single peer).
// Returns an error while the bridge is mid-reconnect — callers that broadcast
// treat that as best-effort.
func (c *TCPClientInterface) Send(_ string, frame []byte) error {
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("iface tcp-client: %s not connected (reconnecting)", c.dialAddr)
	}
	return conn.send(frame)
}

func (c *TCPClientInterface) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.cancel() // abort any in-flight redial
		c.mu.Lock()
		if c.conn != nil {
			c.conn.c.Close() // unblocks the current readConn
		}
		c.mu.Unlock()
	})
	<-c.closed // wait for run() to finish and close frames
	return nil
}

// run reads from the current connection and, when it drops, redials with backoff
// until reconnected or closed. It owns the frames channel (sole closer).
func (c *TCPClientInterface) run() {
	defer close(c.frames)
	defer close(c.closed)
	backoff := reconnectMin
	for {
		c.mu.Lock()
		conn, reader := c.conn, c.reader
		c.mu.Unlock()
		if conn != nil {
			c.readConn(reader) // blocks until the connection drops or we Close
			backoff = reconnectMin
		}

		select {
		case <-c.done:
			return
		default:
		}

		// Mark disconnected, then redial with backoff (abortable by Close).
		c.mu.Lock()
		c.conn, c.reader = nil, nil
		c.mu.Unlock()
		select {
		case <-c.done:
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > reconnectMax {
			backoff = reconnectMax
		}
		nc, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(c.ctx, "tcp", c.dialAddr)
		if err != nil {
			continue // stay in the loop, retry after the next backoff (or Close)
		}
		nr := bufio.NewReader(nc)
		// Re-authenticate on every reconnect: a bridge that drops and returns has
		// to prove itself again, and so do we. A failure here is treated like a
		// failed dial — back off and retry, rather than silently running an
		// unauthenticated bridge.
		if err := bridgeAuthClient(nc, nr, c.psk); err != nil {
			nc.Close()
			continue
		}
		c.mu.Lock()
		c.conn, c.reader = &tcpConn{c: nc}, nr
		c.mu.Unlock()
	}
}

// readConn reads framed messages from one connection until it errors.
func (c *TCPClientInterface) readConn(r *bufio.Reader) {
	for {
		frame, err := readFrame(r)
		if err != nil {
			return
		}
		select {
		case c.frames <- InboundFrame{Addr: c.dialAddr, Data: frame}:
		case <-c.done:
			return
		}
	}
}
