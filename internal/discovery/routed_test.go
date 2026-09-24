package discovery

import (
	"sync"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/iface"
	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// captureIface records Send calls so a test can assert what a node forwarded.
type captureIface struct {
	mu   sync.Mutex
	sent []capturedFrame
	mtu  int
}

type capturedFrame struct {
	addr string
	data []byte
}

func (c *captureIface) Name() string     { return "cap" }
func (c *captureIface) Kind() iface.Kind { return iface.KindUDP }
func (c *captureIface) Caps() iface.Caps {
	m := c.mtu
	if m == 0 {
		m = 1 << 20
	}
	return iface.Caps{MTU: m, Broadcast: true}
}
func (c *captureIface) Send(addr string, frame []byte) error {
	c.mu.Lock()
	c.sent = append(c.sent, capturedFrame{addr, append([]byte(nil), frame...)})
	c.mu.Unlock()
	return nil
}
func (c *captureIface) Frames() <-chan iface.InboundFrame { return nil }
func (c *captureIface) Close() error                      { return nil }

func (c *captureIface) frames() []capturedFrame {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]capturedFrame(nil), c.sent...)
}

func routedPacket(t *testing.T, origin, dest string, hopLimit uint8, inner []byte) *protocol.Packet {
	t.Helper()
	pkt := protocol.NewPacket(protocol.PacketTypeRouted, protocol.EncodeRouted(hopLimit, inner), "", dest)
	pkt.SourceNode = origin
	return pkt
}

// addPath seeds a path-table entry so routeToward has a next hop.
func addPath(d *Discovery, dest, nextHop string, cap *captureIface) {
	d.paths.update(dest, pathEntry{NextHop: nextHop, Hops: 1, LastSeen: time.Now(), OriginTS: time.Now().UnixNano()})
	d.mu.Lock()
	d.addrIface[nextHop] = cap
	d.mu.Unlock()
}

func TestRouted_DeliversAtDestination(t *testing.T) {
	d := newTestDiscovery("C")
	got := make(chan []byte, 1)
	d.SetRoutedHandler(func(inner []byte, origin string) {
		if origin != "A" {
			t.Errorf("origin = %q, want A", origin)
		}
		got <- inner
	})
	d.handleRouted(routedPacket(t, "A", "C", 5, []byte("sealed")))
	select {
	case inner := <-got:
		if string(inner) != "sealed" {
			t.Fatalf("delivered %q, want sealed", inner)
		}
	default:
		t.Fatal("destination did not deliver the routed packet")
	}
}

func TestRouted_TransportForwards(t *testing.T) {
	d := newTestDiscovery("B")
	d.capabilities = []string{"relay"} // transport
	cap := &captureIface{}
	addPath(d, "C", "addrC", cap)

	d.handleRouted(routedPacket(t, "A", "C", 5, []byte("sealed")))

	frames := cap.frames()
	if len(frames) != 1 {
		t.Fatalf("forwarded %d frames, want 1", len(frames))
	}
	if frames[0].addr != "addrC" {
		t.Fatalf("forwarded to %q, want addrC", frames[0].addr)
	}
	var pkt protocol.Packet
	if err := pkt.UnmarshalBinary(frames[0].data); err != nil {
		t.Fatal(err)
	}
	if hl := protocol.RoutedHopLimit(pkt.Payload); hl != 4 {
		t.Fatalf("forwarded hop limit = %d, want 4 (5-1)", hl)
	}
}

func TestRouted_EndpointDoesNotForward(t *testing.T) {
	d := newTestDiscovery("B") // no relay capability => endpoint
	cap := &captureIface{}
	addPath(d, "C", "addrC", cap)
	d.handleRouted(routedPacket(t, "A", "C", 5, []byte("x")))
	if len(cap.frames()) != 0 {
		t.Fatal("an endpoint must not forward routed traffic")
	}
}

func TestRouted_HopLimitExhausted(t *testing.T) {
	d := newTestDiscovery("B")
	d.capabilities = []string{"relay"}
	cap := &captureIface{}
	addPath(d, "C", "addrC", cap)
	d.handleRouted(routedPacket(t, "A", "C", 1, []byte("x"))) // last hop budget
	if len(cap.frames()) != 0 {
		t.Fatal("a routed packet with an exhausted hop limit must not be forwarded")
	}
}

func TestRouted_Dedup(t *testing.T) {
	d := newTestDiscovery("B")
	d.capabilities = []string{"relay"}
	cap := &captureIface{}
	addPath(d, "C", "addrC", cap)
	pkt := routedPacket(t, "A", "C", 5, []byte("x"))
	d.handleRouted(pkt)
	d.handleRouted(pkt) // same ID: must not forward twice (loop suppression)
	if n := len(cap.frames()); n != 1 {
		t.Fatalf("forwarded %d times, want 1 (dedup)", n)
	}
}

func TestRouted_NoPathDrops(t *testing.T) {
	d := newTestDiscovery("B")
	d.capabilities = []string{"relay"}
	// No path seeded for "C".
	d.handleRouted(routedPacket(t, "A", "C", 5, []byte("x"))) // must not panic
}

func TestMTUToward(t *testing.T) {
	d := newTestDiscovery("A")
	if d.MTUToward("C") != 0 {
		t.Fatal("MTUToward with no path should be 0")
	}
	cap := &captureIface{mtu: 1400}
	addPath(d, "C", "addrC", cap)
	if got := d.MTUToward("C"); got != 1400 {
		t.Fatalf("MTUToward = %d, want 1400 (first-hop iface MTU)", got)
	}
}
