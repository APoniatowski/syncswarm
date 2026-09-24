package discovery

import (
	"testing"
	"time"
)

func TestBridgeLiveness_WarnsOnlyWhenSilent(t *testing.T) {
	d := newTestDiscovery("self")
	old := time.Now().Add(-bridgeLivenessTimeout - time.Second)

	// A bridge that connected but never carried a frame.
	d.bridges["dead"] = &bridgeStat{addr: "1.2.3.4:64514", created: old}
	// A bridge that has carried traffic.
	live := &bridgeStat{addr: "5.6.7.8:64514", created: old}
	live.active.Store(true)
	d.bridges["live"] = live
	// A silent-but-recent bridge (inside the grace window).
	d.bridges["young"] = &bridgeStat{addr: "9.9.9.9:64514", created: time.Now()}

	d.checkBridgeLiveness()

	if !d.bridges["dead"].warned {
		t.Error("a silent, past-timeout bridge should be warned")
	}
	if d.bridges["live"].warned {
		t.Error("an active bridge should never be warned")
	}
	if d.bridges["young"].warned {
		t.Error("a bridge still inside the grace window should not be warned yet")
	}
}

func TestBridgeLiveness_MarkActiveSuppressesWarning(t *testing.T) {
	d := newTestDiscovery("self")
	d.bridges["b"] = &bridgeStat{addr: "1.1.1.1:64514", created: time.Now().Add(-bridgeLivenessTimeout - time.Second)}

	// A frame arriving on the bridge marks it live.
	d.markIfaceActive("b")

	d.checkBridgeLiveness()
	if d.bridges["b"].warned {
		t.Fatal("a bridge that carried a frame must not be warned")
	}
}
