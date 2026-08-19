package transfer

import "time"

const (
	defaultOfflineTTL = 10 * time.Minute // how long a relay holds a message for an offline recipient
	maxOfflinePerNode = 64               // cap on held fragments per recipient
	offlineSweep      = 30 * time.Second // expiry sweep cadence
	redeliverEvery    = 10 * time.Second // cadence for retrying delivery to reachable recipients
)

// storeOffline holds an undeliverable blob for a recipient that is currently
// unreachable, to be flushed when it reconnects or becomes reachable again.
// No-op unless store-and-forward is enabled; bounded per recipient (oldest
// dropped) and by TTL. When a storage backend is configured the blob is also
// persisted to disk so it survives a relay restart (10.1).
func (t *Transfer) storeOffline(nodeID string, blob []byte) {
	if !t.storeForward || nodeID == "" {
		return
	}
	t.metrics.IncStored()

	seq := t.offSeq.Add(1)
	expiry := nowPlus(t.offlineTTL)

	var dropped []uint64
	t.offMu.Lock()
	q := append(t.offline[nodeID], pendingBlob{seq: seq, blob: append([]byte(nil), blob...), expiry: expiry})
	if len(q) > maxOfflinePerNode {
		for _, pb := range q[:len(q)-maxOfflinePerNode] {
			dropped = append(dropped, pb.seq) // evict oldest, keep the most recent
		}
		q = q[len(q)-maxOfflinePerNode:]
	}
	t.offline[nodeID] = q
	t.offMu.Unlock()

	if t.storage != nil {
		_ = t.storage.SaveOffline(nodeID, seq, blob, expiry)
		for _, ds := range dropped {
			_ = t.storage.DeleteOffline(nodeID, ds)
		}
	}
}

// flushOffline delivers everything held for nodeID over its freshly-established
// reservation connection, in arrival order, dropping any that expired, then
// clears the queue (memory + disk).
func (t *Transfer) flushOffline(nodeID string, rc *reservedConn) {
	t.offMu.Lock()
	q := t.offline[nodeID]
	delete(t.offline, nodeID)
	t.offMu.Unlock()

	for _, pb := range q {
		if timeAfterNow(pb.expiry) {
			_ = rc.send(t, pb.blob)
		}
	}
	t.clearOfflineStore(nodeID)
}

// redeliverOffline periodically attempts to deliver held blobs to recipients
// that have become directly reachable again without reserving a circuit (10.2).
// Recipients reachable only via a reservation are handled by flushOffline when
// they reconnect.
func (t *Transfer) redeliverOffline() {
	ticker := time.NewTicker(redeliverEvery)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.redeliverRound()
		}
	}
}

func (t *Transfer) redeliverRound() {
	if t.discovery == nil {
		return
	}

	t.offMu.Lock()
	recipients := make([]string, 0, len(t.offline))
	for id := range t.offline {
		recipients = append(recipients, id)
	}
	t.offMu.Unlock()
	if len(recipients) == 0 {
		return
	}

	// Snapshot currently-reachable node addresses.
	addrByID := make(map[string]string)
	for _, n := range t.discovery.GetActiveNodes() {
		addrByID[n.ID] = peerDialAddr(n)
	}

	for _, id := range recipients {
		// Reserved recipients receive their held blobs over the reservation
		// (flushOffline); don't also dial them directly.
		if t.reservationFor(id) != nil {
			continue
		}
		addr, ok := addrByID[id]
		if !ok {
			continue // not currently reachable
		}
		t.redeliverTo(id, addr)
	}
}

// redeliverTo attempts to deliver every currently-held, unexpired blob for
// nodeID directly to addr, clearing the queue only if all of them are sent.
// Returns true if the queue was cleared. Expired blobs are skipped (the sweep
// reaps them); a send failure aborts and leaves the queue intact for a later
// round.
func (t *Transfer) redeliverTo(nodeID, addr string) bool {
	t.offMu.Lock()
	blobs := append([]pendingBlob(nil), t.offline[nodeID]...)
	t.offMu.Unlock()

	for _, pb := range blobs {
		if !timeAfterNow(pb.expiry) {
			continue
		}
		if err := t.sendRelayBlob(addr, pb.blob); err != nil {
			return false // recipient went away mid-flush; retry next round
		}
	}
	t.clearOffline(nodeID)
	return true
}

// clearOffline removes every held blob for nodeID from memory and disk (used
// once they have all been redelivered).
func (t *Transfer) clearOffline(nodeID string) {
	t.offMu.Lock()
	delete(t.offline, nodeID)
	t.offMu.Unlock()
	t.clearOfflineStore(nodeID)
}

func (t *Transfer) clearOfflineStore(nodeID string) {
	if t.storage != nil {
		_ = t.storage.DeleteOfflineNode(nodeID)
	}
}

// loadOffline restores blobs persisted across a restart into the in-memory
// queue and advances the sequence counter past every recovered blob so new
// stores never collide with reloaded files (10.1).
func (t *Transfer) loadOffline() {
	if t.storage == nil {
		return
	}
	loaded, err := t.storage.LoadOffline()
	if err != nil {
		return
	}

	var maxSeq uint64
	t.offMu.Lock()
	for nodeID, entries := range loaded {
		for _, e := range entries {
			if !timeAfterNow(e.Expiry) {
				_ = t.storage.DeleteOffline(nodeID, e.Seq) // drop already-expired on load
				continue
			}
			t.offline[nodeID] = append(t.offline[nodeID], pendingBlob{seq: e.Seq, blob: e.Blob, expiry: e.Expiry})
			if e.Seq > maxSeq {
				maxSeq = e.Seq
			}
		}
	}
	t.offMu.Unlock()

	if maxSeq > t.offSeq.Load() {
		t.offSeq.Store(maxSeq)
	}
}

// sweepOffline periodically drops expired held fragments.
func (t *Transfer) sweepOffline() {
	ticker := time.NewTicker(offlineSweep)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.expireOffline()
		}
	}
}

func (t *Transfer) expireOffline() {
	type expired struct {
		node string
		seq  uint64
	}
	var gone []expired

	t.offMu.Lock()
	for id, q := range t.offline {
		kept := q[:0]
		for _, pb := range q {
			if timeAfterNow(pb.expiry) {
				kept = append(kept, pb)
			} else {
				gone = append(gone, expired{node: id, seq: pb.seq})
			}
		}
		if len(kept) == 0 {
			delete(t.offline, id)
		} else {
			t.offline[id] = kept
		}
	}
	t.offMu.Unlock()

	if t.storage != nil {
		for _, e := range gone {
			_ = t.storage.DeleteOffline(e.node, e.seq)
		}
	}
}

// nowPlus / timeAfterNow isolate the clock so tests can reason about TTLs.
func nowPlus(d time.Duration) time.Time { return time.Now().Add(d) }
func timeAfterNow(ts time.Time) bool    { return ts.After(time.Now()) }
