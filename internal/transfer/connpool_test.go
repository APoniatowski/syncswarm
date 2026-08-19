package transfer

import (
	"net"
	"testing"
	"time"
)

func TestConnPoolGetPut(t *testing.T) {
	p := newConnPool()
	if p.get("a:1") != nil {
		t.Fatal("get on an empty pool must return nil")
	}

	c, peer := net.Pipe()
	defer c.Close()
	defer peer.Close()

	p.put("a:1", c)
	if got := p.get("a:1"); got != c {
		t.Fatal("get must return the pooled connection")
	}
	if p.get("a:1") != nil {
		t.Fatal("a checked-out connection must not remain in the pool")
	}
}

func TestConnPoolCapsIdlePerAddr(t *testing.T) {
	p := newConnPool()
	var conns []net.Conn
	for i := 0; i < maxIdlePerAddr+3; i++ {
		a, b := net.Pipe()
		conns = append(conns, a, b)
		p.put("x:1", a)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	p.mu.Lock()
	n := len(p.idle["x:1"])
	p.mu.Unlock()
	if n != maxIdlePerAddr {
		t.Fatalf("idle count = %d, want cap %d", n, maxIdlePerAddr)
	}
}

func TestConnPoolReap(t *testing.T) {
	p := newConnPool()
	a, b := net.Pipe()
	defer b.Close()
	// Inject a stale entry.
	p.idle["y:1"] = []pooledConn{{conn: a, lastUsed: time.Now().Add(-time.Hour)}}

	p.reap()

	p.mu.Lock()
	_, present := p.idle["y:1"]
	p.mu.Unlock()
	if present {
		t.Fatal("a stale connection must be reaped")
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("a reaped connection must be closed")
	}
}

func TestConnPoolCloseAll(t *testing.T) {
	p := newConnPool()
	a, b := net.Pipe()
	defer b.Close()
	p.put("z:1", a)
	p.closeAll()

	// After closeAll, further puts close the connection instead of pooling it.
	c, d := net.Pipe()
	defer d.Close()
	p.put("z:1", c)
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("put after closeAll must close the connection")
	}
}
