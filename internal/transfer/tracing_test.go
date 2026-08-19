package transfer

import "testing"

func TestHopTraceDisabledByDefault(t *testing.T) {
	tr := &Transfer{}
	tr.recordHop(HopSend, "x")
	if got := tr.HopTrace(); got != nil {
		t.Fatalf("tracing off must record nothing, got %d events", len(got))
	}
}

func TestHopTraceRecordsInOrder(t *testing.T) {
	tr := &Transfer{}
	tr.SetTracing(true, 8)
	tr.recordHop(HopSend, "a")
	tr.recordHop(HopReceive, "b")
	tr.recordHop(HopForward, "c")

	got := tr.HopTrace()
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	if got[0].Role != HopSend || got[1].Role != HopReceive || got[2].Role != HopForward {
		t.Fatalf("events out of order: %v", []string{got[0].Role, got[1].Role, got[2].Role})
	}
	if got[0].Detail != "a" || got[2].Detail != "c" {
		t.Fatal("event details not preserved")
	}
}

func TestHopTraceRingWraps(t *testing.T) {
	tr := &Transfer{}
	tr.SetTracing(true, 3)
	for i, r := range []string{"1", "2", "3", "4", "5"} {
		_ = i
		tr.recordHop(HopForward, r)
	}
	got := tr.HopTrace()
	if len(got) != 3 {
		t.Fatalf("ring of 3 held %d events", len(got))
	}
	// Oldest two ("1","2") were overwritten; newest three remain in order.
	if got[0].Detail != "3" || got[1].Detail != "4" || got[2].Detail != "5" {
		t.Fatalf("ring kept wrong window: %s,%s,%s", got[0].Detail, got[1].Detail, got[2].Detail)
	}
}

func TestSetTracingClearsPriorTrace(t *testing.T) {
	tr := &Transfer{}
	tr.SetTracing(true, 4)
	tr.recordHop(HopSend, "old")
	tr.SetTracing(true, 4) // re-enable resets
	if got := tr.HopTrace(); got != nil {
		t.Fatalf("re-enabling must clear prior trace, got %d events", len(got))
	}
}
