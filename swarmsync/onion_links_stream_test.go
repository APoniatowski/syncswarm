package swarmsync

import (
	"bytes"
	"testing"
	"time"
)

// waitConverged waits until sender can see at least n active peers, so a
// single-shot send is not racing discovery.
func waitConverged(t *testing.T, nodes []*SyncSwarm, sender *SyncSwarm, n int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, x := range nodes {
			x.Bootstrap()
		}
		active := 0
		for _, p := range sender.Peers() {
			if p.Active {
				active++
			}
		}
		if active >= n {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Skipf("swarm did not converge to %d active peers in this environment", n)
}

// TestOnionOverLinks_Streamed reproduces the messenger's report: with
// OnionOverLinks enabled, SendTo works but SendStream delivers nothing — the
// sender streams the whole payload and reports success while the receiver sees not
// one byte.
//
// It is deliberately single-shot. The other streaming tests retry until a deadline,
// which hides exactly this failure: the send is reported as succeeding, so a retry
// loop simply tries again and eventually gets through, turning "broken" into
// "slow". A file transfer in an application gets one attempt.
//
// The difference between text and a file is volume. A text message is a handful of
// onion blobs; a file is hundreds. Each blob is chunked to the link MTU and
// reassembled per message at the peer, and a partial is held until every chunk of
// that message arrives. The relay sub-protocol is explicitly best-effort, so
// incomplete messages are normal — but nothing reclaimed those partials and the
// table is capped, so once enough accumulate the reassembler drops every subsequent
// message for the life of the link.
func TestOnionOverLinks_Streamed(t *testing.T) {
	key := bytes.Repeat([]byte{0x5b}, 32)
	recv := make(chan []byte, 8)

	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnionOverLinks: true,
		OnDataReceived: func(b []byte) { recv <- b }})
	relay1 := newTestNode(t, Options{NodeID: "relay1", Key: key, Relay: true, OnionOverLinks: true})
	relay2 := newTestNode(t, Options{NodeID: "relay2", Key: key, Relay: true, OnionOverLinks: true})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1,
		DataShards: 4, ParityShards: 2, OnionOverLinks: true})

	nodes := []*SyncSwarm{dest, relay1, relay2, sender}
	wireAndStart(t, nodes...)
	waitConverged(t, nodes, sender, 3, 20*time.Second)

	payload := bytes.Repeat([]byte("syncswarm-streamed-over-links-"), 3200) // ~96 KB, as the messenger reported

	if err := sender.SendStream(bytes.NewReader(payload), dest.NodeID()); err != nil {
		t.Fatalf("SendStream: %v", err)
	}
	select {
	case got := <-recv:
		if !bytes.Equal(got, payload) {
			t.Fatalf("received %d bytes, want %d", len(got), len(payload))
		}
	case <-time.After(20 * time.Second):
		for _, n := range []struct {
			name string
			n    *SyncSwarm
		}{{"sender", sender}, {"relay1", relay1}, {"relay2", relay2}, {"dest", dest}} {
			st := n.n.Stats()
			t.Logf("%-7s sent=%d fwd=%d recv=%d delivered=%d dropped=%d decoys=%d",
				n.name, st.FragmentsSent, st.FragmentsForwarded, st.FragmentsReceived,
				st.FragmentsDelivered, st.PacketsDropped, st.DecoysDropped)
		}
		t.Fatal("sender streamed the whole payload and reported success, but the " +
			"receiver got nothing: onion blobs entered the Links path and were " +
			"never delivered")
	}
}
