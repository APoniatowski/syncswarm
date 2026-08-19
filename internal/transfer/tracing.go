package transfer

import (
	"sync"
	"time"
)

// Hop-event roles recorded by the local tracer.
const (
	HopSend    = "send"    // this node originated a fragment piece
	HopReceive = "receive" // this node accepted a relay packet as a hop
	HopForward = "forward" // this node passed a relay packet onward
	HopDeliver = "deliver" // this node reassembled and delivered a transfer
	HopDecoy   = "decoy"   // this node dropped a cover-traffic decoy
	HopDrop    = "drop"    // this node rejected a packet (bad sig / unpeelable / malformed)
)

const defaultTraceSize = 256

// HopEvent is one entry in a node's local hop trace: what the node did with a
// packet, when. It is deliberately node-local — see hopTracer.
type HopEvent struct {
	Time   time.Time
	Role   string
	Detail string // small, non-sensitive label (e.g. a next-hop address or short id)
}

// hopTracer is an opt-in, bounded ring buffer of a node's recent hop events.
//
// It is intentionally NOT a distributed trace: no correlation identifier is
// attached to the anonymous forwarded wire format, because an ID that travelled
// with a packet across relays would let any relay or on-path observer link the
// hops of one transfer — defeating the unlinkability that is SyncSwarm's core
// property. Each node only records what it itself did; operators stitch a
// picture together out of band (in a trusted test network), never on the wire.
type hopTracer struct {
	mu      sync.Mutex
	enabled bool
	size    int
	buf     []HopEvent
	next    int
	count   int
}

// SetTracing enables or disables local hop tracing with a ring of `size` events
// (non-positive uses the default). Enabling or resizing clears any prior trace.
// Call before Start.
func (t *Transfer) SetTracing(enabled bool, size int) {
	if size <= 0 {
		size = defaultTraceSize
	}
	tr := &t.tracer
	tr.mu.Lock()
	tr.enabled = enabled
	tr.size = size
	tr.buf = nil
	tr.next = 0
	tr.count = 0
	tr.mu.Unlock()
}

// recordHop appends a hop event when tracing is enabled; a cheap no-op otherwise.
func (t *Transfer) recordHop(role, detail string) {
	tr := &t.tracer
	tr.mu.Lock()
	if !tr.enabled || tr.size == 0 {
		tr.mu.Unlock()
		return
	}
	if tr.buf == nil {
		tr.buf = make([]HopEvent, tr.size)
	}
	tr.buf[tr.next] = HopEvent{Time: time.Now(), Role: role, Detail: detail}
	tr.next = (tr.next + 1) % tr.size
	if tr.count < tr.size {
		tr.count++
	}
	tr.mu.Unlock()
}

// HopTrace returns the recorded hop events, oldest first. Empty when tracing is
// off or nothing has been recorded.
func (t *Transfer) HopTrace() []HopEvent {
	tr := &t.tracer
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.count == 0 || tr.size == 0 {
		return nil
	}
	out := make([]HopEvent, 0, tr.count)
	start := (tr.next - tr.count + tr.size) % tr.size
	for i := 0; i < tr.count; i++ {
		out = append(out, tr.buf[(start+i)%tr.size])
	}
	return out
}
