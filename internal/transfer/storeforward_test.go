package transfer

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/storage"
)

func newRelayForStore() *Transfer {
	_, sign, _ := ed25519.GenerateKey(nil)
	return &Transfer{
		selfID:       "relay",
		signKey:      sign,
		storeForward: true,
		offlineTTL:   time.Minute,
		offline:      make(map[string][]pendingBlob),
		pool:         newConnPool(),
	}
}

// mkLoopbackRecipient starts a real Transfer listening on an ephemeral loopback
// data port, so a relay can dial it as a reachable recipient.
func mkLoopbackRecipient(t *testing.T) *Transfer {
	t.Helper()
	xpriv, _, err := encryption.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, spriv, _ := ed25519.GenerateKey(nil)
	id := protocol.DeriveNodeID(spriv.Public().(ed25519.PublicKey))
	tr, err := NewTransfer(nil, nil, id, nil, nil, xpriv, spriv, 0, 1, 0, 0, false, 0)
	if err != nil {
		t.Skipf("cannot bind data port in this environment: %v", err)
	}
	tr.Start()
	return tr
}

// TestStoreAndForwardFlush holds messages for an offline recipient and delivers
// them, in order, over the connection it opens on reconnect.
func TestStoreAndForwardFlush(t *testing.T) {
	relay := newRelayForStore()
	relay.storeOffline("D", []byte("m1"))
	relay.storeOffline("D", []byte("m2"))
	if n := len(relay.offline["D"]); n != 2 {
		t.Fatalf("held %d messages, want 2", n)
	}

	clientEnd, relayEnd := net.Pipe()
	defer clientEnd.Close()
	defer relayEnd.Close()
	rc := &reservedConn{conn: relayEnd}

	got := make(chan string, 2)
	go func() {
		r := bufio.NewReader(clientEnd)
		for i := 0; i < 2; i++ {
			pkt, err := protocol.ReadPacket(r)
			if err != nil {
				return
			}
			got <- string(pkt.Payload)
		}
	}()

	relay.flushOffline("D", rc)

	var seen []string
	for i := 0; i < 2; i++ {
		select {
		case s := <-got:
			seen = append(seen, s)
		case <-time.After(2 * time.Second):
			t.Fatal("held message not flushed on reconnect")
		}
	}
	if seen[0] != "m1" || seen[1] != "m2" {
		t.Fatalf("flushed %v, want [m1 m2] in order", seen)
	}
	if _, ok := relay.offline["D"]; ok {
		t.Fatal("offline queue must be cleared after flush")
	}
}

func TestStoreForwardBounded(t *testing.T) {
	relay := newRelayForStore()
	for i := 0; i < maxOfflinePerNode+10; i++ {
		relay.storeOffline("D", []byte{byte(i)})
	}
	q := relay.offline["D"]
	if len(q) != maxOfflinePerNode {
		t.Fatalf("held %d, want cap %d", len(q), maxOfflinePerNode)
	}
	if q[len(q)-1].blob[0] != byte(maxOfflinePerNode+10-1) {
		t.Fatal("bound should keep the most recent messages")
	}
}

func TestStoreForwardExpiry(t *testing.T) {
	relay := newRelayForStore()
	relay.offline["D"] = []pendingBlob{
		{blob: []byte("stale"), expiry: time.Now().Add(-time.Minute)},
		{blob: []byte("fresh"), expiry: time.Now().Add(time.Minute)},
	}
	relay.expireOffline()
	q := relay.offline["D"]
	if len(q) != 1 || string(q[0].blob) != "fresh" {
		t.Fatalf("expiry sweep = %v, want only [fresh]", q)
	}
}

func TestStoreForwardDisabled(t *testing.T) {
	relay := &Transfer{storeForward: false, offline: make(map[string][]pendingBlob)}
	relay.storeOffline("D", []byte("x"))
	if len(relay.offline["D"]) != 0 {
		t.Fatal("store-and-forward disabled must not hold messages")
	}
}

// TestStoreForwardPersistsAcrossRestart verifies that blobs held for an offline
// recipient survive a relay restart: they are written to disk on store and
// recovered into memory by a fresh Transfer over the same storage dir (10.1).
func TestStoreForwardPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	store1, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatal(err)
	}

	relay1 := newRelayForStore()
	relay1.storage = store1
	relay1.storeOffline("D", []byte("m1"))
	relay1.storeOffline("D", []byte("m2"))

	// Simulate a restart: a brand-new Transfer backed by the same directory.
	store2, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	relay2 := newRelayForStore()
	relay2.storage = store2
	relay2.loadOffline()

	q := relay2.offline["D"]
	if len(q) != 2 {
		t.Fatalf("recovered %d blobs after restart, want 2", len(q))
	}
	bySeq := map[uint64][]byte{}
	for _, pb := range q {
		bySeq[pb.seq] = pb.blob
	}
	if !bytes.Equal(bySeq[1], []byte("m1")) || !bytes.Equal(bySeq[2], []byte("m2")) {
		t.Fatalf("recovered payloads = %v, want seq1=m1 seq2=m2", bySeq)
	}

	// The sequence counter must advance past every recovered blob so a new store
	// cannot collide with a reloaded file.
	if next := relay2.offSeq.Add(1); next <= 2 {
		t.Fatalf("offSeq not advanced past recovered blobs: next=%d", next)
	}
}

// TestStoreForwardExpiredNotRecovered drops already-expired blobs on load and
// deletes their files rather than resurrecting them.
func TestStoreForwardExpiredNotRecovered(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Persist one already-expired and one fresh blob directly.
	if err := store.SaveOffline("D", 1, []byte("stale"), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveOffline("D", 2, []byte("fresh"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	relay := newRelayForStore()
	relay.storage = store
	relay.loadOffline()

	q := relay.offline["D"]
	if len(q) != 1 || string(q[0].blob) != "fresh" {
		t.Fatalf("recovered %v, want only [fresh]", q)
	}
	// The stale file must be gone from disk too.
	loaded, _ := store.LoadOffline()
	if len(loaded["D"]) != 1 {
		t.Fatalf("stale blob still on disk: %d held, want 1", len(loaded["D"]))
	}
}

// TestRedeliverToReachableRecipient delivers held blobs directly to a recipient
// that has come back online without reserving, then clears the queue (10.2).
func TestRedeliverToReachableRecipient(t *testing.T) {
	recipient := mkLoopbackRecipient(t)
	defer recipient.Stop()
	addr := fmt.Sprintf("127.0.0.1:%d", recipient.Port())

	dir := t.TempDir()
	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	relay := newRelayForStore()
	relay.storage = store
	relay.storeOffline("D", []byte("held"))

	if !relay.redeliverTo("D", addr) {
		t.Fatal("redeliverTo must succeed to a reachable recipient")
	}
	if _, ok := relay.offline["D"]; ok {
		t.Fatal("in-memory queue must be cleared after redelivery")
	}
	if loaded, _ := store.LoadOffline(); len(loaded["D"]) != 0 {
		t.Fatalf("on-disk queue must be cleared after redelivery: %d held", len(loaded["D"]))
	}
}

// TestRedeliverToUnreachableRetains keeps the held blobs when the recipient
// cannot be reached, so nothing is lost before a later retry.
func TestRedeliverToUnreachableRetains(t *testing.T) {
	relay := newRelayForStore()
	relay.offline["D"] = []pendingBlob{
		{seq: 1, blob: []byte("held"), expiry: time.Now().Add(time.Minute)},
	}
	// 127.0.0.1:1 is a closed port; the dial fails after retries.
	if relay.redeliverTo("D", "127.0.0.1:1") {
		t.Fatal("redeliverTo must fail to an unreachable recipient")
	}
	if len(relay.offline["D"]) != 1 {
		t.Fatal("held blobs must be retained after a failed redelivery")
	}
}
