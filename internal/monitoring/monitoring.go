// Package monitoring provides lightweight, thread-safe counters for observing a
// SyncSwarm node's transfer activity. All methods are nil-safe, so callers can
// hold a possibly-nil *Metrics and record unconditionally when monitoring is off.
package monitoring

import "sync/atomic"

// Metrics accumulates counters for a node's transfer activity.
type Metrics struct {
	fragmentsSent      atomic.Uint64
	fragmentsForwarded atomic.Uint64
	fragmentsReceived  atomic.Uint64
	fragmentsDelivered atomic.Uint64
	packetsDropped     atomic.Uint64
	decoysDropped      atomic.Uint64
	offlineStored      atomic.Uint64
	acksConfirmed      atomic.Uint64
	excommunications   atomic.Uint64
}

// New returns a fresh Metrics.
func New() *Metrics { return &Metrics{} }

// Snapshot is an immutable read of the counters at a point in time.
type Snapshot struct {
	FragmentsSent      uint64 // fragment pieces this node originated
	FragmentsForwarded uint64 // relay packets this node passed onward
	FragmentsReceived  uint64 // relay packets this node accepted as a hop
	FragmentsDelivered uint64 // transfers reassembled and handed to the app
	PacketsDropped     uint64 // packets rejected (bad signature, unpeelable, malformed)
	DecoysDropped      uint64
	OfflineStored      uint64
	AcksConfirmed      uint64
	Excommunications   uint64
}

func (m *Metrics) IncSent() {
	if m != nil {
		m.fragmentsSent.Add(1)
	}
}
func (m *Metrics) IncForwarded() {
	if m != nil {
		m.fragmentsForwarded.Add(1)
	}
}
func (m *Metrics) IncReceived() {
	if m != nil {
		m.fragmentsReceived.Add(1)
	}
}
func (m *Metrics) IncDropped() {
	if m != nil {
		m.packetsDropped.Add(1)
	}
}
func (m *Metrics) IncDelivered() {
	if m != nil {
		m.fragmentsDelivered.Add(1)
	}
}
func (m *Metrics) IncDecoy() {
	if m != nil {
		m.decoysDropped.Add(1)
	}
}
func (m *Metrics) IncStored() {
	if m != nil {
		m.offlineStored.Add(1)
	}
}
func (m *Metrics) IncAck() {
	if m != nil {
		m.acksConfirmed.Add(1)
	}
}
func (m *Metrics) IncExcommunicate() {
	if m != nil {
		m.excommunications.Add(1)
	}
}

// Snapshot returns the current counter values, or a zero Snapshot if m is nil.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		FragmentsSent:      m.fragmentsSent.Load(),
		FragmentsForwarded: m.fragmentsForwarded.Load(),
		FragmentsReceived:  m.fragmentsReceived.Load(),
		FragmentsDelivered: m.fragmentsDelivered.Load(),
		PacketsDropped:     m.packetsDropped.Load(),
		DecoysDropped:      m.decoysDropped.Load(),
		OfflineStored:      m.offlineStored.Load(),
		AcksConfirmed:      m.acksConfirmed.Load(),
		Excommunications:   m.excommunications.Load(),
	}
}
