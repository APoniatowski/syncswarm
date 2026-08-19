package transfer

import (
	"net"
	"sync"
	"time"
)

const (
	maxIdlePerAddr = 4                // idle connections kept per destination
	connIdleTTL    = 30 * time.Second // idle connection lifetime
	poolReapEvery  = 15 * time.Second // reaper cadence
)

// connPool keeps a small set of idle outbound TCP connections per destination so
// one-shot forwarded packets (relay/ack) reuse a connection instead of paying a
// TCP handshake per fragment per hop. Connections are checked out for the
// duration of a single write, so writes never interleave on one connection.
type connPool struct {
	mu     sync.Mutex
	idle   map[string][]pooledConn
	closed bool
}

type pooledConn struct {
	conn     net.Conn
	lastUsed time.Time
}

func newConnPool() *connPool {
	return &connPool{idle: make(map[string][]pooledConn)}
}

// get removes and returns an idle connection for addr, or nil if none is free.
func (p *connPool) get(addr string) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	q := p.idle[addr]
	if len(q) == 0 {
		return nil
	}
	c := q[len(q)-1]
	if len(q) == 1 {
		delete(p.idle, addr)
	} else {
		p.idle[addr] = q[:len(q)-1]
	}
	return c.conn
}

// put returns a connection to the pool for reuse, or closes it if the pool is
// closed or already full for that address.
func (p *connPool) put(addr string, conn net.Conn) {
	p.mu.Lock()
	if p.closed || len(p.idle[addr]) >= maxIdlePerAddr {
		p.mu.Unlock()
		conn.Close()
		return
	}
	p.idle[addr] = append(p.idle[addr], pooledConn{conn: conn, lastUsed: time.Now()})
	p.mu.Unlock()
}

// reap closes connections that have been idle longer than connIdleTTL.
func (p *connPool) reap() {
	cutoff := time.Now().Add(-connIdleTTL)
	var dead []net.Conn
	p.mu.Lock()
	for addr, q := range p.idle {
		kept := q[:0]
		for _, c := range q {
			if c.lastUsed.Before(cutoff) {
				dead = append(dead, c.conn)
			} else {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(p.idle, addr)
		} else {
			p.idle[addr] = kept
		}
	}
	p.mu.Unlock()
	for _, c := range dead {
		c.Close()
	}
}

// closeAll closes every idle connection and marks the pool closed.
func (p *connPool) closeAll() {
	p.mu.Lock()
	p.closed = true
	all := p.idle
	p.idle = make(map[string][]pooledConn)
	p.mu.Unlock()
	for _, q := range all {
		for _, c := range q {
			c.conn.Close()
		}
	}
}
