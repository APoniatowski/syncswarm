package transfer

import (
	"net"
	"testing"
	"time"
)

// TestDialWithRetries_Succeeds checks the happy path still works after bounding
// the connect timeout.
func TestDialWithRetries_Succeeds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	conn := dialWithRetries(ln.Addr().String())
	if conn == nil {
		t.Fatal("dialWithRetries failed against a live listener")
	}
	conn.Close()
}

// TestDialWithRetries_FailsFast is the regression test for the unbounded-dial bug:
// a bare net.Dial to a silently-dropped address waits out the OS connect timeout
// (~127s on Linux), so three retries stalled a send for ~7 minutes while reporting
// nothing. Every attempt is now capped by dataDialTimeout, bounding the whole call.
//
// Note: this only exercises the timeout on networks that *drop* traffic to the
// reserved TEST-NET-1 range. Where the local network answers with an immediate
// "unreachable", the dial fails fast for a different reason and the test passes
// trivially — it asserts an upper bound, so it is correct either way, never flaky.
func TestDialWithRetries_FailsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("exercises the full dial retry budget")
	}
	// 192.0.2.0/24 (TEST-NET-1) is reserved and routed nowhere.
	start := time.Now()
	conn := dialWithRetries("192.0.2.1:64513")
	elapsed := time.Since(start)

	if conn != nil {
		conn.Close()
		t.Skip("this environment answers a reserved address; cannot test the timeout here")
	}
	budget := maxRetries*(dataDialTimeout+retryDelay) + 5*time.Second
	if elapsed > budget {
		t.Fatalf("dialWithRetries took %v, over the %v budget — connect is not bounded by dataDialTimeout", elapsed, budget)
	}
	t.Logf("bounded: gave up after %v (budget %v)", elapsed.Round(time.Millisecond), budget)
}
