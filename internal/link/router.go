package link

import (
	"sync"
	"sync/atomic"
	"time"
)

// Router multiplexes one Link between two sub-protocols, distinguished by a 1-byte
// prefix on every frame: best-effort **messages** (link.SendMessage semantics) and
// reliable **resources** (the ARQ Resource layer). It owns the Link's OnData,
// strips the prefix, and dispatches — ACK/DONE to the matching local
// ResourceSender, ADV/PART to a lazily-created ResourceReceiver, message chunks to
// a Reassembler. This is the per-link half of the Phase 0b frame router; a node
// uses one Router per Link for both directions.
type Router struct {
	l *Link

	reasm      atomic.Pointer[Reassembler]
	relayReasm atomic.Pointer[Reassembler]
	onResource atomic.Pointer[func(id [16]byte, data []byte)]

	mu       sync.Mutex
	senders  map[[16]byte]*ResourceSender
	receiver *ResourceReceiver
}

const (
	subMessage  byte = 0x01
	subResource byte = 0x02
	subRelay    byte = 0x03 // onion relay blobs (best-effort, reassembled per message)

	// Bytes a resource PART frame adds around its payload, plus the 1-byte router
	// prefix — subtracted from the link MTU chunk so a part still fits one frame.
	resourceFrameOverhead = 1 + 1 + resIDLen + 4
)

// NewRouter binds a Router to l and starts consuming its inbound frames. It is
// idempotent: a Link has at most one Router, so a reused (cached) Link keeps its
// single OnData handler instead of a second Router clobbering the first.
func NewRouter(l *Link) *Router {
	if r := l.router.Load(); r != nil {
		return r
	}
	r := &Router{l: l, senders: make(map[[16]byte]*ResourceSender)}
	if !l.router.CompareAndSwap(nil, r) {
		return l.router.Load() // lost the race; use the winner
	}
	l.OnData(r.feed)
	return r
}

// OnMessage delivers reassembled best-effort messages to fn.
func (r *Router) OnMessage(fn func([]byte)) {
	r.reasm.Store(NewReassembler(fn))
}

// OnResource delivers each fully received reliable resource to fn.
func (r *Router) OnResource(fn func(id [16]byte, data []byte)) {
	r.onResource.Store(&fn)
}

// OnRelay delivers each fully reassembled onion relay blob to fn (for the transfer
// layer to peel and forward). Best-effort, like the underlying onion hop.
func (r *Router) OnRelay(fn func([]byte)) {
	r.relayReasm.Store(NewReassembler(fn))
}

func (r *Router) feed(frame []byte) {
	if len(frame) < 1 {
		return
	}
	body := frame[1:]
	switch frame[0] {
	case subMessage:
		if ra := r.reasm.Load(); ra != nil {
			ra.Feed(body)
		}
	case subResource:
		r.routeResource(body)
	case subRelay:
		if ra := r.relayReasm.Load(); ra != nil {
			ra.Feed(body)
		}
	}
}

func (r *Router) routeResource(f []byte) {
	if len(f) < 1 {
		return
	}
	switch f[0] {
	case resTagAdv, resTagPart:
		r.getReceiver().Feed(f)
	case resTagAck, resTagDone:
		if len(f) < 1+resIDLen {
			return
		}
		id := frameID(f)
		r.mu.Lock()
		s := r.senders[id]
		r.mu.Unlock()
		if s != nil {
			s.Feed(f)
		}
	}
}

func (r *Router) getReceiver() *ResourceReceiver {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.receiver == nil {
		r.receiver = NewResourceReceiver(r.resourceSend, func(id [16]byte, data []byte) {
			if fn := r.onResource.Load(); fn != nil {
				(*fn)(id, data)
			}
		})
	}
	return r.receiver
}

// resourceSend prefixes a resource frame and writes it to the Link.
func (r *Router) resourceSend(f []byte) error {
	return r.l.Send(append([]byte{subResource}, f...))
}

// SendMessage sends a best-effort message over the multiplexed link.
func (r *Router) SendMessage(data []byte) error {
	chunk := r.l.mgr.chunkFor(r.l.peerAddr) - 1 // room for the prefix byte
	return sendMessageChunks(func(f []byte) error {
		return r.l.Send(append([]byte{subMessage}, f...))
	}, chunk, data)
}

// SendRelay sends an onion relay blob (best-effort, chunked to the link MTU and
// reassembled at the peer) over the relay sub-protocol.
func (r *Router) SendRelay(blob []byte) error {
	chunk := r.l.mgr.chunkFor(r.l.peerAddr) - 1 // room for the prefix byte
	return sendMessageChunks(func(f []byte) error {
		return r.l.Send(append([]byte{subRelay}, f...))
	}, chunk, blob)
}

// SendResource reliably transfers data as a resource and blocks until the receiver
// has all of it (or timeout). Part size is derived from the link MTU so each part
// rides one frame.
func (r *Router) SendResource(data []byte, timeout time.Duration) error {
	partSize := r.l.mgr.chunkFor(r.l.peerAddr) - resourceFrameOverhead
	if partSize < 1 {
		partSize = 1
	}
	s, err := NewResourceSender(data, partSize, 0, 0, r.resourceSend)
	if err != nil {
		return err
	}
	id := s.ID()
	r.mu.Lock()
	r.senders[id] = s
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.senders, id)
		r.mu.Unlock()
	}()

	s.Start()
	return s.Wait(timeout)
}
