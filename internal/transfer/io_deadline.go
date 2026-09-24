package transfer

import (
	"net"
	"time"
)

// ioTimeout bounds a single read or write on a data-plane connection.
//
// Dialing is bounded separately (dataDialTimeout), but an *established*
// connection had no bound at all: a peer that completes a TCP handshake and then
// goes silent — a half-open NAT mapping, a hung process, a machine that vanished
// without a RST — left a send blocked forever. Worse, connPool could hand that
// same dead connection to later sends.
//
// The bound is deliberately generous. It is a liveness backstop, not a
// performance limit: a 60s stall on a connection that is supposed to be actively
// transferring means the peer is gone, while the reservation keepalive (15s) and
// any progressing transfer stay comfortably inside it.
const ioTimeout = 60 * time.Second

// deadlineConn re-arms a deadline before every read and write, so the bound
// applies *per operation* rather than to the connection as a whole. That is the
// important distinction: a single absolute deadline would kill a large but
// perfectly healthy transfer partway through, whereas this only fires when the
// peer actually stops making progress.
type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

// withIOTimeout wraps c so reads and writes cannot block indefinitely. Returns c
// unchanged if it is nil, so callers can wrap a failed dial's result safely.
func withIOTimeout(c net.Conn) net.Conn {
	if c == nil {
		return nil
	}
	return &deadlineConn{Conn: c, timeout: ioTimeout}
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	// Errors here are non-fatal on their own: if the deadline cannot be set the
	// read still proceeds, just unbounded, which is the old behaviour rather than
	// a new failure.
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(b)
}
