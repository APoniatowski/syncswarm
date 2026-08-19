package monitoring

import (
	"sync"
	"testing"
)

func TestMetricsCountsAndNilSafe(t *testing.T) {
	// A nil *Metrics must not panic and reports zeros.
	var nilM *Metrics
	nilM.IncSent()
	nilM.IncDelivered()
	if got := nilM.Snapshot(); got != (Snapshot{}) {
		t.Fatalf("nil metrics snapshot = %+v, want zero", got)
	}

	m := New()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.IncDelivered()
			m.IncForwarded()
		}()
	}
	m.IncDecoy()
	m.IncStored()
	m.IncAck()
	m.IncSent()
	m.IncReceived()
	m.IncReceived()
	m.IncDropped()
	wg.Wait()

	s := m.Snapshot()
	if s.FragmentsDelivered != 100 || s.FragmentsForwarded != 100 {
		t.Fatalf("delivered=%d forwarded=%d, want 100/100", s.FragmentsDelivered, s.FragmentsForwarded)
	}
	if s.DecoysDropped != 1 || s.OfflineStored != 1 || s.AcksConfirmed != 1 {
		t.Fatalf("decoy/stored/ack = %d/%d/%d, want 1/1/1", s.DecoysDropped, s.OfflineStored, s.AcksConfirmed)
	}
	if s.FragmentsSent != 1 || s.FragmentsReceived != 2 || s.PacketsDropped != 1 {
		t.Fatalf("sent/received/dropped = %d/%d/%d, want 1/2/1", s.FragmentsSent, s.FragmentsReceived, s.PacketsDropped)
	}
}
