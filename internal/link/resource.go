package link

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// A Resource is one reliable, ordered transfer of an arbitrary payload over a
// Link (Reticulum's term). Links themselves are best-effort framed sessions; the
// Resource layer adds the guarantees a real data transfer needs — segmentation
// into numbered parts, a sliding send window, selective-ACK retransmission (ARQ),
// in-order reassembly, and a whole-resource integrity hash — all carried inside
// the Link's AEAD so relays never see the control traffic.
//
// This file is the standalone state machine (Phase 0b.1 of PHASE_0B.md): it is
// transport-agnostic, driven by an injected send function and fed inbound frames
// via Feed, so it is unit-testable over an in-memory lossy pipe before it is wired
// onto real Links. The wire is compact binary (a 1-byte tag + fields), not JSON.
//
// Frames:
//
//	ADV  tag id[16] total(4) partSize(4) wholeHash[32]
//	PART tag id[16] index(4) <data>
//	ACK  tag id[16] base(4) bmlen(1) bitmap[bmlen]   (bitmap covers parts >= base)
//	DONE tag id[16]
//
// base is the receiver's lowest not-yet-received part (everything below it is in);
// the bitmap marks out-of-order parts received at/above base, so the sender
// retransmits only the gaps. Completion is reaching base == total (DONE is a
// fast-path nicety; loss of it is recovered by the terminal ACK).
const (
	resTagAdv  = 0x01
	resTagPart = 0x02
	resTagAck  = 0x03
	resTagDone = 0x04

	resIDLen = 16

	// Bounds on what a resource advertisement may claim. They exist to cap what an
	// allocation driven by a peer's numbers can cost, so they are deliberately
	// generous compared with real use rather than tuned tight.
	maxResourceParts    = 1 << 16   // 65536 parts
	maxResourcePartSize = 1 << 20   // 1 MiB, the largest link frame
	maxResourceBytes    = 256 << 20 // 256 MiB assembled in memory
	resHdrAdv           = 1 + resIDLen + 4 + 4 + 32

	// Defaults; callers override via NewResourceSender.
	defaultResWindow = 32
	defaultResRTO    = 250 * time.Millisecond

	// maxAckBitmapBytes bounds an ACK's selective bitmap (covers one window).
	maxAckBitmapBytes = 32
)

// --- encoding helpers ------------------------------------------------------

func putResID(b []byte, id [16]byte) { copy(b, id[:]) }

func encodeAdv(id [16]byte, total, partSize uint32, whole [32]byte) []byte {
	b := make([]byte, resHdrAdv)
	b[0] = resTagAdv
	putResID(b[1:], id)
	binary.BigEndian.PutUint32(b[1+resIDLen:], total)
	binary.BigEndian.PutUint32(b[1+resIDLen+4:], partSize)
	copy(b[1+resIDLen+8:], whole[:])
	return b
}

func encodePart(id [16]byte, index uint32, data []byte) []byte {
	b := make([]byte, 1+resIDLen+4+len(data))
	b[0] = resTagPart
	putResID(b[1:], id)
	binary.BigEndian.PutUint32(b[1+resIDLen:], index)
	copy(b[1+resIDLen+4:], data)
	return b
}

func encodeAck(id [16]byte, base uint32, bitmap []byte) []byte {
	b := make([]byte, 1+resIDLen+4+1+len(bitmap))
	b[0] = resTagAck
	putResID(b[1:], id)
	binary.BigEndian.PutUint32(b[1+resIDLen:], base)
	b[1+resIDLen+4] = byte(len(bitmap))
	copy(b[1+resIDLen+5:], bitmap)
	return b
}

func encodeDone(id [16]byte) []byte {
	b := make([]byte, 1+resIDLen)
	b[0] = resTagDone
	putResID(b[1:], id)
	return b
}

func frameID(b []byte) (id [16]byte) {
	copy(id[:], b[1:1+resIDLen])
	return
}

// --- sender ----------------------------------------------------------------

// ResourceSender drives one outbound resource: it advertises, streams a window of
// parts, and retransmits gaps as selective ACKs arrive, completing when the
// receiver has every part.
type ResourceSender struct {
	id     [16]byte
	parts  [][]byte
	whole  [32]byte
	send   func([]byte) error
	window int
	rto    time.Duration

	mu       sync.Mutex
	base     int         // lowest unacked part (all below are acked)
	acked    []bool      // per-part ack state
	sentAt   []time.Time // last send time per part (for timeout retransmit)
	sentHigh int         // exclusive high-water of parts ever sent
	finished bool

	done chan error
	stop chan struct{}
}

// NewResourceSender splits data into parts of at most partSize bytes and prepares
// a sender over send. window and rto default when non-positive. The resource ID is
// random.
func NewResourceSender(data []byte, partSize, window int, rto time.Duration, send func([]byte) error) (*ResourceSender, error) {
	if partSize <= 0 {
		return nil, fmt.Errorf("resource: partSize must be > 0")
	}
	if window <= 0 {
		window = defaultResWindow
	}
	if rto <= 0 {
		rto = defaultResRTO
	}
	var parts [][]byte
	for off := 0; off < len(data); off += partSize {
		end := off + partSize
		if end > len(data) {
			end = len(data)
		}
		parts = append(parts, data[off:end])
	}
	if len(parts) == 0 {
		parts = [][]byte{{}} // always at least one (possibly empty) part
	}
	s := &ResourceSender{
		id:     randID16(),
		parts:  parts,
		whole:  sha256.Sum256(data),
		send:   send,
		window: window,
		rto:    rto,
		acked:  make([]bool, len(parts)),
		sentAt: make([]time.Time, len(parts)),
		done:   make(chan error, 1),
		stop:   make(chan struct{}),
	}
	return s, nil
}

// ID reports the resource identifier (so a receiver/demux can be matched to it).
func (s *ResourceSender) ID() [16]byte { return s.id }

// Start advertises the resource, sends the first window, and launches the
// retransmission timer. It returns immediately; call Wait for completion.
func (s *ResourceSender) Start() {
	adv := encodeAdv(s.id, uint32(len(s.parts)), uint32(maxPartLen(s.parts)), s.whole)
	_ = s.send(adv)

	s.mu.Lock()
	frames := s.fillWindowLocked()
	s.mu.Unlock()
	s.flush(frames)

	go s.retransmitLoop()
}

// Wait blocks until the transfer completes, errors, or the timeout elapses.
func (s *ResourceSender) Wait(timeout time.Duration) error {
	select {
	case err := <-s.done:
		return err
	case <-time.After(timeout):
		s.finish(fmt.Errorf("resource: send timed out"))
		return <-s.done
	}
}

// Feed consumes an inbound control frame (ACK/DONE) for this resource.
func (s *ResourceSender) Feed(frame []byte) {
	if len(frame) < 1+resIDLen || frameID(frame) != s.id {
		return
	}
	switch frame[0] {
	case resTagAck:
		s.onAck(frame)
	case resTagDone:
		s.finish(nil)
	}
}

func (s *ResourceSender) onAck(frame []byte) {
	if len(frame) < 1+resIDLen+4+1 {
		return
	}
	base := int(binary.BigEndian.Uint32(frame[1+resIDLen:]))
	bmLen := int(frame[1+resIDLen+4])
	if len(frame) < 1+resIDLen+5+bmLen {
		return
	}
	bitmap := frame[1+resIDLen+5 : 1+resIDLen+5+bmLen]

	s.mu.Lock()
	// Everything below base is acknowledged.
	for i := 0; i < base && i < len(s.acked); i++ {
		s.acked[i] = true
	}
	if base > s.base {
		s.base = base
	}
	// Selective bits mark out-of-order parts already received.
	for i := 0; i < bmLen*8; i++ {
		if bitmap[i/8]&(1<<uint(i%8)) != 0 {
			if idx := base + i; idx < len(s.acked) {
				s.acked[idx] = true
			}
		}
	}
	complete := s.base >= len(s.parts)
	var frames [][]byte
	if !complete {
		// An ACK only slides the window and pushes new parts; lost parts are
		// recovered by the timeout loop, so a burst of ACKs can't trigger a
		// resend storm.
		frames = s.fillWindowLocked()
	}
	s.mu.Unlock()

	if complete {
		s.finish(nil)
		return
	}
	s.flush(frames)
}

// fillWindowLocked sends any not-yet-sent parts that fall inside the current
// window [base, base+window). Caller holds s.mu.
func (s *ResourceSender) fillWindowLocked() [][]byte {
	var out [][]byte
	limit := s.base + s.window
	if limit > len(s.parts) {
		limit = len(s.parts)
	}
	now := time.Now()
	for i := s.sentHigh; i < limit; i++ {
		out = append(out, encodePart(s.id, uint32(i), s.parts[i]))
		s.sentAt[i] = now
	}
	if limit > s.sentHigh {
		s.sentHigh = limit
	}
	return out
}

// dueRetransmitsLocked re-sends in-window parts that were sent but not acked and
// whose last send is older than one RTO — timeout-based selective retransmit, so
// only genuinely overdue parts go back on the wire. Caller holds s.mu.
func (s *ResourceSender) dueRetransmitsLocked(now time.Time) [][]byte {
	var out [][]byte
	limit := s.base + s.window
	if limit > s.sentHigh {
		limit = s.sentHigh
	}
	for i := s.base; i < limit; i++ {
		if !s.acked[i] && now.Sub(s.sentAt[i]) >= s.rto {
			out = append(out, encodePart(s.id, uint32(i), s.parts[i]))
			s.sentAt[i] = now
		}
	}
	return out
}

func (s *ResourceSender) retransmitLoop() {
	t := time.NewTicker(s.rto)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			now := time.Now()
			s.mu.Lock()
			frames := s.dueRetransmitsLocked(now)
			// Also push the window forward in case an ACK that would have
			// advanced sentHigh was lost.
			frames = append(frames, s.fillWindowLocked()...)
			s.mu.Unlock()
			s.flush(frames)
		}
	}
}

func (s *ResourceSender) finish(err error) {
	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		return
	}
	s.finished = true
	close(s.stop)
	s.mu.Unlock()
	s.done <- err
}

func (s *ResourceSender) flush(frames [][]byte) {
	for _, f := range frames {
		_ = s.send(f)
	}
}

// --- receiver --------------------------------------------------------------

// ResourceReceiver accepts inbound resource frames (possibly for several
// resources at once), reassembles each in order, verifies its whole-resource
// hash, and invokes onComplete once per resource.
type ResourceReceiver struct {
	send       func([]byte) error
	onComplete func(id [16]byte, data []byte)

	mu    sync.Mutex
	byID  map[[16]byte]*recvState
	limit int // max concurrent resources buffered

	// finished remembers recently completed resource IDs so a retransmit that
	// arrives after completion is answered instead of ignored. Without it the
	// transfer deadlocks: on completion the state is deleted and a final ack plus
	// DONE are sent, and if both are lost the sender's retransmits reach a receiver
	// with nothing to match them against, which stays silent — so the sender
	// retries fruitlessly until its deadline. Re-sending DONE is the ARQ equivalent
	// of retransmitting a final ACK, and it costs one frame.
	finished map[[16]byte]time.Time
}

const (
	// finishedTTL is how long a completed resource ID is remembered so late
	// retransmits can still be answered.
	finishedTTL = 2 * time.Minute
	// maxFinished bounds that memory, since the IDs come from peers.
	maxFinished = 1024
)

type recvState struct {
	total    int
	whole    [32]byte
	parts    [][]byte
	got      []bool
	count    int
	base     int // lowest not-yet-received part
	complete bool
}

// NewResourceReceiver returns a receiver that acks over send and delivers each
// finished resource to onComplete.
func NewResourceReceiver(send func([]byte) error, onComplete func(id [16]byte, data []byte)) *ResourceReceiver {
	return &ResourceReceiver{
		send:       send,
		onComplete: onComplete,
		byID:       make(map[[16]byte]*recvState),
		finished:   make(map[[16]byte]time.Time),
		limit:      maxInflightMessages, // reuse the link-layer bound
	}
}

// Feed consumes one inbound resource frame.
func (r *ResourceReceiver) Feed(frame []byte) {
	if len(frame) < 1+resIDLen {
		return
	}
	switch frame[0] {
	case resTagAdv:
		r.onAdv(frame)
	case resTagPart:
		r.onPart(frame)
	}
}

// pending reports how many resources are currently buffered. Used by tests to
// check that a rejected advertisement allocated nothing.
func (r *ResourceReceiver) pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byID)
}

func (r *ResourceReceiver) onAdv(frame []byte) {
	if len(frame) < resHdrAdv {
		return
	}
	id := frameID(frame)
	total := int(binary.BigEndian.Uint32(frame[1+resIDLen:]))
	partSize := int(binary.BigEndian.Uint32(frame[1+resIDLen+4:]))
	// The advertisement is a peer's *claim* about a transfer it has not sent yet,
	// and both slices below are sized directly from it. Unchecked, one small frame
	// declaring total=2^32-1 asks for ~100 GB of slice headers — an out-of-memory
	// kill for the price of a few dozen bytes. Validate the claim against what a
	// real resource can be before allocating anything from it.
	//
	// partSize was previously parsed and discarded; using it lets the implied total
	// size be checked too, which is the bound that actually matters.
	if total <= 0 || total > maxResourceParts {
		return
	}
	if partSize > maxResourcePartSize {
		return
	}
	// A zero partSize is legitimate — an empty resource is advertised as one
	// zero-length part — so it means "no size claimed" rather than a rejection.
	// total is bounded above regardless, so the slices stay small either way.
	if partSize > 0 && total > maxResourceBytes/partSize {
		return // implied resource larger than we will ever assemble
	}
	var whole [32]byte
	copy(whole[:], frame[1+resIDLen+8:1+resIDLen+8+32])

	r.mu.Lock()
	if _, ok := r.byID[id]; !ok {
		if len(r.byID) >= r.limit {
			r.mu.Unlock()
			return // shed load rather than grow unbounded
		}
		r.byID[id] = &recvState{
			total: total,
			whole: whole,
			parts: make([][]byte, total),
			got:   make([]bool, total),
		}
	}
	r.mu.Unlock()
}

func (r *ResourceReceiver) onPart(frame []byte) {
	if len(frame) < 1+resIDLen+4 {
		return
	}
	id := frameID(frame)
	idx := int(binary.BigEndian.Uint32(frame[1+resIDLen:]))
	data := frame[1+resIDLen+4:]

	r.mu.Lock()
	st := r.byID[id]
	if st == nil {
		// Already completed? Then this is a retransmit whose ack we evidently lost.
		// Answer it again rather than leaving the sender to time out.
		_, done := r.finished[id]
		r.mu.Unlock()
		if done {
			_ = r.send(encodeDone(id))
		}
		return
	}
	if idx < 0 || idx >= st.total {
		r.mu.Unlock()
		return
	}
	if !st.got[idx] {
		st.got[idx] = true
		st.parts[idx] = append([]byte(nil), data...)
		st.count++
		for st.base < st.total && st.got[st.base] {
			st.base++
		}
	}
	ackFrame := encodeAck(id, uint32(st.base), st.ackBitmapLocked())
	var (
		complete  bool
		assembled []byte
	)
	if st.count == st.total && !st.complete {
		assembled = st.assembleLocked()
		if sha256.Sum256(assembled) == st.whole {
			st.complete = true
			complete = true
			delete(r.byID, id)
			r.rememberFinishedLocked(id)
		} else {
			assembled = nil // integrity failure: keep waiting/retrying
		}
	}
	r.mu.Unlock()

	_ = r.send(ackFrame)
	if complete {
		_ = r.send(encodeDone(id))
		if r.onComplete != nil {
			r.onComplete(id, assembled)
		}
	}
}

// ackBitmapLocked builds the selective bitmap of out-of-order parts received at or
// above base, covering at most one window. Caller holds r.mu.
func (st *recvState) ackBitmapLocked() []byte {
	span := st.total - st.base
	if span <= 0 {
		return nil
	}
	nbytes := (span + 7) / 8
	if nbytes > maxAckBitmapBytes {
		nbytes = maxAckBitmapBytes
	}
	bm := make([]byte, nbytes)
	for i := 0; i < nbytes*8; i++ {
		idx := st.base + i
		if idx >= st.total {
			break
		}
		if st.got[idx] {
			bm[i/8] |= 1 << uint(i%8)
		}
	}
	// Trim trailing zero bytes to keep the ACK small.
	for len(bm) > 0 && bm[len(bm)-1] == 0 {
		bm = bm[:len(bm)-1]
	}
	return bm
}

func (st *recvState) assembleLocked() []byte {
	var out []byte
	for _, p := range st.parts {
		out = append(out, p...)
	}
	return out
}

// --- small helpers ---------------------------------------------------------

func randID16() (id [16]byte) {
	_, _ = rand.Read(id[:])
	return
}

func maxPartLen(parts [][]byte) int {
	m := 0
	for _, p := range parts {
		if len(p) > m {
			m = len(p)
		}
	}
	return m
}

// rememberFinishedLocked records a completed resource ID so later retransmits are
// answered, pruning expired entries and capping the map since the IDs are supplied
// by peers. Caller holds r.mu.
func (r *ResourceReceiver) rememberFinishedLocked(id [16]byte) {
	now := time.Now()
	if len(r.finished) >= maxFinished {
		for k, t := range r.finished {
			if now.Sub(t) >= finishedTTL {
				delete(r.finished, k)
			}
		}
		// Still full of fresh entries: drop an arbitrary one rather than grow. The
		// cost of forgetting is one sender timeout, not a correctness failure.
		for k := range r.finished {
			if len(r.finished) < maxFinished {
				break
			}
			delete(r.finished, k)
		}
	}
	r.finished[id] = now
}
